"""
Secure Vault - Main Window
Primary application window with file explorer interface.
"""

import os
import shutil
import json
import sys
import subprocess
from pathlib import Path
from typing import Optional, List
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QMessageBox,
    QApplication, QInputDialog,
    QFrame, QComboBox
)
from PyQt6.QtCore import pyqtSlot, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QIcon

from src.core.config import get_config
from src.core.i18n import _
from src.core.crypto import encrypt_metadata, decrypt_metadata
from src.core.hash_utils import format_size
from src.database.models import Repository, VirtualFile, Operation
from src.database.database import get_repository_database, RepositoryDatabase, close_database
from src.repository.repository import get_repository_stats, can_store_file, get_repository, set_active_repository
from src.operations.file_ops import (
    check_blocks_exist, OperationCancelled, FileImporter, FileExporter, BatchFileDeleter
)
from src.utils.logger import get_logger
from src.utils.file_utils import get_unique_filename

from src.ui.styles import get_stylesheet
from src.ui.window_utils import update_all_windows_theme
from src.ui.main.file_tree import FileTreeView, FileTreeModel
from src.ui.main.context_menu import FileContextMenu
from src.ui.main.progress_widget import ProgressWidget
from src.ui.main.log_widget import LogWidget


class WorkerThread(QThread):
    """Thread for background file operations."""
    
    progress = pyqtSignal(object, object, str, str, str) # Use object to pass Python's big ints without any C++ 32-bit truncation
    finished = pyqtSignal(bool, str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
        self._cancelled = False
    
    def run(self):
        try:
            result = self.operation(*self.args, **self.kwargs)
            self.finished.emit(True, str(result) if result else _("msg_finished"))
        except OperationCancelled:
            self.finished.emit(False, "__CANCELLED__")
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def cancel(self):
        self._cancelled = True

    def is_cancelled(self) -> bool:
        return self._cancelled


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, master_key: bytes, repository: Repository, parent=None):
        super().__init__(parent)
        self.master_key = master_key
        self.repository = repository
        self.config = get_config()
        self.logger = get_logger()
        self._worker: Optional[WorkerThread] = None
        
        self._active_task: Optional[str] = None  # 'encrypt', 'decrypt_export', 'encrypted_export', 'delete', 'rename', 'comment'
        self._current_operation: Optional["Operation"] = None  # Persistent operation record
        self._current_task_phase: int = 0  # For multi-phase tasks
        self._is_restarting = False  # Flag for graceful restart
        
        self._setup_window()
        self._setup_ui()
        self._connect_signals()
        self._load_files()
        
        # Apply initial theme
        self._apply_theme()
        
        # Log startup
        self.logger.operation(_("log_startup"), _("log_repo_info", name=repository.name))
        
        # Check for pending operations to resume
        self._check_pending_operations()
        
        # Periodic persistence timer (flush progress every 3s)
        self._persistence_timer = QTimer(self)
        self._persistence_timer.timeout.connect(self._save_progress_heartbeat)
        self._persistence_timer.start(3000)

    def _save_progress_heartbeat(self):
        """Periodically flush current operation progress to DB to ensure persistence."""
        if hasattr(self, '_current_operation') and self._current_operation:
            # We don't update if nothing changed? 
            # Actually Operation.update_progress already throttles or is fast.
            # But here we double-check if we have an active worker.
            if self._worker and self._worker.isRunning():
                # We can't easily get the precise bytes here without a tracker reference,
                # but the Operations inside the workers (FileImporter/Exporter) 
                # already update the DB via unified_callback.
                # This heartbeat serves as an extra safety layer and "alive" signal.
                try:
                    self._current_operation.update_progress(self.repository.path, self._current_operation.processed_size)
                except Exception:
                    pass

    def _check_pending_operations(self):
        """Check for and resume any pending operations."""
        pending = Operation.get_pending(self.repository.path)
        if not pending:
            return
            
        for op in pending:
            self.logger.warning(_("log_found_pending", id=op.id, type=op.type, status=op.status))
            
            # Logic to resume or cleanup
            if op.status == 'processing':
                self.logger.info(_("log_resuming_task", type=op.type))
                if op.type == 'import':
                    QTimer.singleShot(1000, lambda o=op: self._resume_import(o))
                elif op.type == 'export':
                    QTimer.singleShot(1000, lambda o=op: self._resume_export(o))
                elif op.type == 'delete':
                    QTimer.singleShot(1000, lambda o=op: self._resume_delete(o))
            elif op.status == 'cancelling':
                self.logger.info(_("log_resume_cleanup", type=op.type))
                QTimer.singleShot(1000, lambda o=op: self._resume_cleanup(o))

    def _resume_import(self, op):
        """Resume import with path validation."""
        import json
        try:
            source_paths = json.loads(op.source_paths)
            
            # Validation 1: Check source files exist
            missing_sources = [p for p in source_paths if not Path(p).exists()]
            if missing_sources:
                self.logger.error(_("log_resume_failed_missing", path=missing_sources[0]))
                self._current_operation = op
                self._active_task = "encrypt"
                self._cleanup_current_task(force_record_delete=True)
                return
            
            # Validation 2: Check encryption path (vault) exists
            vault_path = Path(self.repository.path) / RepositoryDatabase.VAULT_DIR
            if not vault_path.exists():
                self.logger.error(_("log_resume_failed_vault"))
                self._current_operation = op
                self._active_task = "encrypt"
                self._cleanup_current_task(force_record_delete=True)
                return

            self.logger.info(_("log_resume_success", type=_("type_import"), id=op.id))
            self._on_files_dropped(source_paths, op.parent_id, existing_op=op)
        except Exception as e:
            self.logger.error(_("log_task_failed", type=_("type_import"), error=e))
            op.update_status(self.repository.path, 'failed', str(e))

    def _resume_export(self, op):
        """Resume export with path validation."""
        try:
            source_file_ids = json.loads(op.source_paths)
            target_path = Path(op.target_path)
            
            # Validation 1: Check decryption target path exists (if resumed)
            if op.processed_size > 0 and not target_path.exists():
                self.logger.error(_("log_resume_failed_export_missing", path=target_path))
                self._current_operation = op
                self._active_task = "decrypt_export"
                self._cleanup_current_task(force_record_delete=True)
                return
            
            if not target_path.parent.exists():
                self.logger.error(_("log_resume_failed_export_parent", path=target_path.parent))
                self._current_operation = op
                self._active_task = "decrypt_export"
                self._cleanup_current_task(force_record_delete=True)
                return

            # Validation 2: Check repository file paths (blocks) exist
            files = []
            for fid in source_file_ids:
                vf = VirtualFile.get_by_id(fid, self.repository.path)
                if not vf:
                    continue
                
                # Check if blocks actually exist in the vault
                missing_blocks = check_blocks_exist(vf, self.repository)
                if missing_blocks:
                    self.logger.error(_("log_resume_failed_blocks", name=vf.name if vf.name else vf.id))
                    self._current_operation = op
                    self._active_task = "decrypt_export"
                    self._cleanup_current_task(force_record_delete=True)
                    return
                files.append(vf)
            
            if files:
                self.logger.info(_("log_resume_success", type=_("type_export"), id=op.id))
                self._on_export_decrypted(files, target_path, existing_op=op)
            else:
                self.logger.error(_("log_resume_failed_no_files"))
                op.delete(self.repository.path)
        except Exception as e:
            self.logger.error(_("log_task_failed", type=_("type_export"), error=e))
            op.update_status(self.repository.path, 'failed', str(e))

    def _resume_cleanup(self, op):
        # Implementation for resuming cleanup
        self.logger.info(_("log_force_cleanup", id=op.id))
        self._active_task = op.type
        self._current_operation = op
        # Perform rollback/deletion since we are resuming a cancelled/broken task
        self._cleanup_current_task(cleanup_success=False)

    def _setup_window(self):
        """Setup window properties."""
        self.setWindowTitle(f"Secure Vault - {self.repository.name}")
        self.setMinimumSize(1000, 700)
        
        # Set window icon
        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "assets", "icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        
        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        self.resize(1200, 800)
        self.move(
            (screen.width() - self.width()) // 2,
            (screen.height() - self.height()) // 2
        )
    
    def _setup_ui(self):
        """Setup UI components."""
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Title bar
        self._create_title_bar(main_layout)
        
        # Info bar
        self._create_info_bar(main_layout)
        
        # Main content (tree view)
        self._create_tree_view(main_layout)
        
        # Progress bar
        self.progress_widget = ProgressWidget()
        main_layout.addWidget(self.progress_widget)
        
        # Log widget
        self.log_widget = LogWidget(self.config.dark_mode)
        main_layout.addWidget(self.log_widget)
        
        # Connect logger to log widget
        self.logger.add_callback(self.log_widget.add_log)
    
    def _create_title_bar(self, parent_layout):
        """Create custom title bar with controls."""
        title_bar = QFrame()
        title_bar.setFixedHeight(42)
        
        layout = QHBoxLayout(title_bar)
        layout.setContentsMargins(12, 0, 8, 0)
        layout.setSpacing(8)
        
        # Repository switch button (folder icon)
        self.repo_btn = QPushButton("📁")
        self.repo_btn.setProperty("class", "icon")
        self.repo_btn.setToolTip(_("tooltip_switch_repo"))
        self.repo_btn.clicked.connect(self._switch_repository)
        layout.addWidget(self.repo_btn)
        
        # Path label
        self.path_label = QLabel(self.repository.path)
        self.path_label.setProperty("class", "subtitle")
        layout.addWidget(self.path_label, 1)
        
        # Capacity info
        stats = get_repository_stats(self.repository)
        self.capacity_label = QLabel(
            _("info_used", used=format_size(stats['used']), total=format_size(stats['max_capacity']))
        )
        layout.addWidget(self.capacity_label)
        
        # PIN change button
        pin_btn = QPushButton("🔑")
        pin_btn.setProperty("class", "icon")
        pin_btn.setToolTip(_("tooltip_change_pin"))
        pin_btn.clicked.connect(self._show_pin_change)
        layout.addWidget(pin_btn)
        
        # Theme toggle
        self.theme_btn = QPushButton("🌙" if self.config.dark_mode else "☀️")
        self.theme_btn.setProperty("class", "icon")
        self.theme_btn.setToolTip(_("tooltip_theme"))
        self.theme_btn.clicked.connect(self._toggle_theme)
        layout.addWidget(self.theme_btn)
        
        # Language selection
        self.lang_combo = QComboBox()
        self.lang_combo.setProperty("class", "titlebar")
        self.lang_combo.addItems(["简体中文", "English"])
        self.lang_combo.setFixedWidth(75)
        self.lang_combo.setCurrentIndex(0 if self.config.language == "zh" else 1)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        layout.addWidget(self.lang_combo)
        
        parent_layout.addWidget(title_bar)
    
    def _create_info_bar(self, parent_layout):
        """Info bar is now merged into title bar - this is a no-op."""
        pass
    
    def _create_tree_view(self, parent_layout):
        """Create file tree view."""
        # Model
        self.tree_model = FileTreeModel()
        self.tree_model.set_master_key(self.master_key)
        self.tree_model.set_repository_path(self.repository.path)
        
        # View
        self.tree_view = FileTreeView()
        self.tree_view.setModel(self.tree_model)
        
        # Context menu
        self.context_menu = FileContextMenu(self)
        
        parent_layout.addWidget(self.tree_view, 1)
    
    def _connect_signals(self):
        """Connect UI signals."""
        # Tree view signals
        self.tree_view.files_dropped.connect(self._on_files_dropped)
        self.tree_view.items_moved.connect(self._on_items_moved)
        self.tree_view.context_menu_requested.connect(self._on_context_menu)
        
        # Context menu signals
        self.context_menu.delete_requested.connect(self._on_delete_files)
        self.context_menu.rename_requested.connect(self._on_rename_file)
        self.context_menu.comment_requested.connect(self._on_comment_file)
        self.context_menu.export_decrypted_requested.connect(self._on_export_decrypted)
        self.context_menu.new_folder_requested.connect(self._on_new_folder)
        
        # Progress
        self.progress_widget.cancel_requested.connect(self._on_cancel)
    
    def _load_files(self):
        """Load files into tree view."""
        # Save expanded state
        expanded_ids = set()
        model = self.tree_model
        root = model.invisibleRootItem()
        
        # Save column widths before reload
        header = self.tree_view.header()
        column_widths = []
        for i in range(header.count()):
            column_widths.append(header.sectionSize(i))
        
        def save_expanded(item):
            for row in range(item.rowCount()):
                child = item.child(row)
                if self.tree_view.isExpanded(child.index()):
                    vf = model.get_virtual_file(child)
                    if vf:
                        expanded_ids.add(vf.id)
                    save_expanded(child)
        
        save_expanded(root)
        
        # Load files
        self.tree_model.load_files()
        
        # Restore expanded state
        root = model.invisibleRootItem()
        
        def restore_expanded(item):
            for row in range(item.rowCount()):
                child = item.child(row)
                vf = model.get_virtual_file(child)
                if vf and vf.id in expanded_ids:
                    self.tree_view.setExpanded(child.index(), True)
                restore_expanded(child)
        
        restore_expanded(root)
        
        # Restore column widths
        for i, width in enumerate(column_widths):
            if i < header.count() and width > 0:
                header.resizeSection(i, width)
        
        # Cleanup orphaned blocks (ghost data)
        cleaned_bytes = self.repository.cleanup_orphaned_blocks()
        if cleaned_bytes > 0:
            self.logger.info(_("msg_cleaning_orphans", size=cleaned_bytes / 1024 / 1024))
            self._update_capacity()
        
        self.log_widget.add_info(_("msg_files_loaded"))
    
    def _on_language_changed(self, index):
        """Handle language selection change."""
        new_lang = "zh" if index == 0 else "en"
        
        # Don't do anything if language hasn't changed (e.g., initial setup)
        if new_lang == self.config.language:
            return
            
        # Check if a task is running
        if self._active_task and self._worker and self._worker.isRunning():
            reply = QMessageBox.warning(
                self,
                _("dialog_restart_warning_title"),
                _("dialog_restart_warning_msg"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                # Reset combo box to current language
                self.lang_combo.currentIndexChanged.disconnect(self._on_language_changed)
                self.lang_combo.setCurrentIndex(0 if self.config.language == "zh" else 1)
                self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
                return
            
            # Cancel and cleanup before restart
            self._worker.cancel()
            self._cleanup_current_task()
        else:
            # Normal confirmation
            reply = QMessageBox.question(
                self,
                _("dialog_confirm_restart_title"),
                _("dialog_confirm_restart_msg"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                # Reset combo box to current language
                self.lang_combo.currentIndexChanged.disconnect(self._on_language_changed)
                self.lang_combo.setCurrentIndex(0 if self.config.language == "zh" else 1)
                self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
                return
        
        # Apply change and restart
        self.config.language = new_lang
        self.logger.info(f"Language changed to {new_lang}, restarting...")
        self._restart_app()

    def _apply_theme(self):
        """Apply current theme stylesheet."""
        stylesheet = get_stylesheet(self.config.dark_mode)
        self.setStyleSheet(stylesheet)
        update_all_windows_theme(self.config.dark_mode)
        self.log_widget.set_dark_mode(self.config.dark_mode)
    
    def _toggle_theme(self):
        """Toggle between dark and light mode."""
        # Check if a task is running, mimicking closeEvent logic
        if self._active_task and self._worker and self._worker.isRunning():
            reply = QMessageBox.warning(
                self,
                _("dialog_restart_warning_title"),
                _("dialog_restart_warning_msg"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            # Cancel and cleanup before restart
            self._worker.cancel()
            self._cleanup_current_task()
        else:
            # Normal confirmation
            reply = QMessageBox.question(
                self,
                _("dialog_confirm_restart_title"),
                _("dialog_confirm_restart_msg"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Apply change and restart
        self.config.dark_mode = not self.config.dark_mode
        mode = _("mode_dark") if self.config.dark_mode else _("mode_light")
        self.logger.operation(_("log_theme_switch"), _("log_prepare_restart", mode=mode))
        self._restart_app()

    def _restart_app(self):
        """Restart the application gracefully."""
        # Log restart
        self.logger.operation(_("log_system"), _("log_restart_app"))
        
        # Set restart flag to bypass confirmation in closeEvent
        self._is_restarting = True
        
        # Launch new process
        try:
            subprocess.Popen([sys.executable] + sys.argv)
        except Exception as e:
            self.logger.error(_("error_restart_failed", error=e))
            self._is_restarting = False
            return
            
        # Close database and quit
        close_database()
        
        # Quit the application
        QApplication.quit()
    
    def _show_pin_change(self):
        """Show PIN change dialog."""
        from src.ui.setup.pin_change import PinChangeDialog
        
        dialog = PinChangeDialog(self)
        dialog.setStyleSheet(get_stylesheet(self.config.dark_mode))
        
        if dialog.exec() == PinChangeDialog.DialogCode.Accepted:
            self.logger.operation(_("log_security"), _("log_pin_changed"))
    
    def _switch_repository(self):
        """Show repository selection dialog to switch repositories."""
        # Block if a task is running
        if self._active_task and self._worker and self._worker.isRunning():
            type_names = {
                "encrypt": _("label_encrypt_import"),
                "decrypt_export": _("label_decrypt_export"),
                "delete": _("label_delete"),
            }
            current_task_name = type_names.get(self._active_task, self._active_task)
            QMessageBox.warning(
                self,
                _("dialog_task_busy_title"),
                _("dialog_switch_blocked_msg", name=current_task_name)
            )
            return
        
        from src.ui.setup.repo_manager import RepositoryManagerDialog
        
        # Remember current repo
        current_repo_id = self.repository.id
        
        # Pass master_key correctly
        dialog = RepositoryManagerDialog(self.master_key, self)
        dialog.setStyleSheet(get_stylesheet(self.config.dark_mode))
        
        selected_repo_id = None
        
        def on_selected(repo_id):
            nonlocal selected_repo_id
            selected_repo_id = repo_id
        
        dialog.repository_selected.connect(on_selected)
        
        if dialog.exec() == RepositoryManagerDialog.DialogCode.Accepted:
            # Always refresh repo data (may have been renamed or capacity changed)
            repo_to_load = selected_repo_id if selected_repo_id else current_repo_id
            new_repo = get_repository(repo_to_load)
            
            if new_repo:
                self.repository = new_repo
                self.setWindowTitle(f"Secure Vault - {new_repo.name}")
                self.path_label.setText(new_repo.path)
                self.tree_model.set_repository_path(new_repo.path)
                self._load_files()
                self._update_capacity()
                
                if selected_repo_id and selected_repo_id != current_repo_id:
                    self.logger.operation(_("log_switch_repo"), _("log_switch_to", name=new_repo.name))
            else:
                # This could happen if current repo was deleted and user just clicked "Enter"
                QMessageBox.critical(
                    self,
                    _("dialog_repo_not_found_title"),
                    _("dialog_repo_not_found_msg")
                )
                self.logger.operation(_("log_system"), _("log_repo_not_found_exit"))
                self._restart_app()  # Restart to PIN window instead of quit
        else:
            # Check if current repository still exists (in case it was deleted and dialog cancelled)
            if not get_repository(current_repo_id):
                QMessageBox.critical(
                    self,
                    _("dialog_repo_deleted_title"),
                    _("dialog_repo_deleted_msg")
                )
                self.logger.operation(_("log_system"), _("log_repo_deleted_exit"))
                self._restart_app()  # Restart to PIN window instead of quit

    @pyqtSlot(object, object, str, str, str)
    def _on_progress_update(self, current, total, message, speed="", eta=""):
        """Handle progress updates in a thread-safe way."""
        display_msg = ""
        if message:
            # If message is "Status: Detail", only show "Status" in progress widget
            if ":" in message:
                display_msg = message.split(":", 1)[0].strip()
            else:
                display_msg = message
            
            # For heavy logging, we might want to throttle this or only log significant changes
            # But the logger already handles most of this.
            self.logger.info(message)
            
        self.progress_widget.set_progress(current, total, display_msg, speed, eta)

    
    def _update_capacity(self):
        """Update capacity display."""
        stats = get_repository_stats(self.repository)
        self.capacity_label.setText(
            _("info_used", used=format_size(stats['used']), total=format_size(stats['max_capacity']))
        )

    def _make_progress_callback(self, op: Optional[Operation]):
        """
        Creates a robust progress callback for file operations.
        Handles resumption logic, catch-up protection, and 64-bit safe signals.
        """
        def progress_callback(current, total, message, speed="", eta=""):
            if not self._worker:
                return
            
            # 1. Coordinate parsing (use Python's big ints)
            cur = int(current)
            tot = int(total)
            base_cur = int(op.processed_size) if op else 0
            base_tot = int(op.total_size) if op else 0
            
            # 2. Resumption/Scanning Adjustment
            display_cur, display_tot = cur, tot
            if base_tot > 0:
                # Catch-up phase: either total is unknown or worker hasn't reached past progress
                if tot <= 0 or cur < base_cur:
                    display_cur = max(cur, base_cur)
                    display_tot = max(tot, base_tot)
                    
                    # Improve message during catch-up
                    resuming_tag = f"[{_('status_resuming')}] "
                    if message and resuming_tag not in message:
                        message = resuming_tag + message
            
            # 3. Denominator Stability (fallback to known total or arbitrary 1)
            if display_tot <= 0:
                display_tot = base_tot if base_tot > 0 else 1
            
            # 4. Final Clamping & Overflow Protection
            if display_cur < 0: display_cur = 0
            if display_cur > display_tot: display_cur = display_tot
            
            # Pass original big ints as 'object' through signal
            self._worker.progress.emit(display_cur, display_tot, message, speed, eta)
            
        return progress_callback
    
    # File operation handlers
    
    def _on_files_dropped(self, file_paths: list, parent_id, existing_op=None):
        """Handle files dropped from Windows Explorer."""
        # Check mutual exclusion
        if not self._can_start_task("encrypt") and not existing_op:
            return
        
        self._active_task = "encrypt"
        
        self.logger.operation_start(_("type_import"), _("msg_imported_count", count=len(file_paths)))
        self.progress_widget.set_status("Encrypting")
        
        # Create or use existing operation record
        if existing_op:
            op = existing_op
            self._current_operation = op
        else:
            paths_str_list = [str(p) for p in file_paths]
            op = Operation.create(
                self.repository.path, 
                'import', 
                paths_str_list, 
                parent_id=parent_id
            )
            self._current_operation = op
        progress_callback = self._make_progress_callback(op)
        
        importer = FileImporter(
            self.repository,
            self.master_key,
            progress_callback,
            is_cancelled=self._worker_ref_callback, # We'll need a way to get worker ref
            operation=op
        )
        self._current_importer = importer
        
        def import_files():
            # Convert strings to Path objects
            paths = [Path(p) for p in file_paths]
            
            # Step 1: Pre-calculate total size for unified progress
            total_size = FileImporter.calculate_total_import_size(paths, progress_callback)
            
            # Update op with total size
            if not existing_op:
                db = get_repository_database(self.repository.path)
                db.execute("UPDATE operations SET total_size = ? WHERE id = ?", (total_size, op.id))
                op.total_size = total_size # Update locally for callback
            
            importer.set_total_bytes(total_size)
            
            for path_obj in paths:
                if self._worker.is_cancelled():
                   return
                
                if path_obj.is_dir():
                    importer.import_folder(path_obj, parent_id)
                else:
                    importer.import_file(path_obj, parent_id)
            
            # Remove operation record on success
            op.delete(self.repository.path)
            
            return None  # Success
        
        self._run_in_background(
            import_files, 
            _("msg_imported_count", count=len(file_paths)),
            log_items=[Path(p).name for p in file_paths],
            log_action=_("type_import")
        )
    
    def _on_items_moved(self, file_ids: list[int], new_parent_id: Optional[int]):
        """Handle internal items movement in batch."""
        if not file_ids:
            return
            
        self.logger.info(_("log_moving_items", count=len(file_ids)))
        
        # 1. Pre-fetch existing names in the target directory to optimize collision checks
        from src.database.models import VirtualFile
        existing_files = VirtualFile.get_children(self.repository.path, new_parent_id)
        existing_names = set()
        for existing in existing_files:
            # We will ignore files being moved if they are already in target dir
            try:
                name = decrypt_metadata(
                    existing.name_encrypted,
                    self.master_key,
                    existing.name_nonce
                )
                existing_names.add(name)
            except Exception:
                continue
                
        # 2. Fetch files to be moved
        vfs = VirtualFile.get_batch(file_ids, self.repository.path)
        move_ids = []
        
        for vf in vfs:
            try:
                current_name = decrypt_metadata(
                    vf.name_encrypted,
                    self.master_key,
                    vf.name_nonce
                )
                
                # Check for collision and get unique name if needed
                new_name = get_unique_filename(current_name, existing_names)
                
                if new_name != current_name:
                    name_encrypted, name_nonce = encrypt_metadata(
                        new_name, self.master_key
                    )
                    vf.update_name(name_encrypted, name_nonce, self.repository.path)
                    self.logger.info(_("log_rename_to", name=new_name))
                else:
                    # If no rename, add to batch move list
                    # (Renamed files are technically "moved" too, but update_name doesn't move)
                    pass
                
                # Always add to move list for parent_id update
                move_ids.append(vf.id)
                # Add to existing names so subsequent files in this batch don't collide with it
                existing_names.add(new_name)
                
            except Exception as e:
                self.logger.error(f"Move failed for item {vf.id}: {e}")
        
        # 3. Perform batch move in DB
        if move_ids:
            VirtualFile.move_batch(move_ids, new_parent_id, self.repository.path)
            
        # 4. Single UI refresh
        self._load_files()
        self.logger.operation(_("log_move"), _("log_items_count", count=len(move_ids)))
    
    def _on_context_menu(self, index, global_pos):
        """Show context menu."""
        # Check mutual exclusion before showing menu
        if not self._can_start_task(""):
            return
            
        files = self.tree_view.get_selected_files()
        # Note: files might be empty if clicking background, which is fine for "New Folder"
        
        # Decrypt names for display
        for f in files:
            try:
                f.name = decrypt_metadata(
                    f.name_encrypted, self.master_key, f.name_nonce
                )
                if f.comment_encrypted and f.comment_nonce:
                    f.comment = decrypt_metadata(
                        f.comment_encrypted, self.master_key, f.comment_nonce
                    )
            except Exception:
                f.name = _("label_encrypt_error")
        
        self.context_menu.show_menu(files, global_pos)
    
    def _on_delete_files(self, files: list):
        """Handle delete request with progress and logging."""
        if not files:
            return
        
        # Check mutual exclusion
        if not self._can_start_task("delete"):
            return
        
        self._active_task = "delete"
        
        # Create operation record for persistent deletion
        source_ids = [f.id for f in files]
        op = Operation.create(
            self.repository.path,
            'delete',
            source_ids, # Store IDs as source paths
            total_size=len(files) # For deletion, total_size is item count
        )
        self._current_operation = op
        
        self.logger.operation_start(_("log_delete"), _("msg_deleted_count", count=len(files)))
        
        def do_delete():
            deleter = BatchFileDeleter(
                self.repository, 
                self.master_key, 
                lambda c, t, m, s="", e="": self._worker.progress.emit(c, t, m, s, e),
                is_cancelled=self._worker.is_cancelled,
                operation=op
            )
            deleter.delete(files)
            
            # Remove operation record on success
            op.delete(self.repository.path)
            
            return None  # Success signal for _run_in_background

        self._run_in_background(
            do_delete,
            success_msg=_("msg_deleted_count", count=len(files)),
            log_action=_("log_delete")
        )

    def _resume_delete(self, op: Operation):
        """Resume persistent deletion task."""
        try:
            import json
            file_ids = json.loads(op.source_paths)
            
            # Fetch VirtualFiles by IDs
            from src.database.models import VirtualFile
            files = VirtualFile.get_batch(file_ids, self.repository.path)
            
            if not files:
                self.logger.info(_("log_resume_nothing_to_delete"))
                op.delete(self.repository.path)
                return
                
            self.logger.info(_("log_resume_success", type=_("log_delete"), id=op.id))
            
            # Set state
            self._active_task = "delete"
            self._current_operation = op
            
            # Logic similar to _on_delete_files but with existing_op
            def do_delete():
                deleter = BatchFileDeleter(
                    self.repository, 
                    self.master_key, 
                    lambda c, t, m, s="", e="": self._worker.progress.emit(c, t, m, s, e),
                    is_cancelled=self._worker.is_cancelled,
                    operation=op
                )
                deleter.delete(files)
                
                # Remove operation record on success
                op.delete(self.repository.path)
                
                return None  # Success
                
            self._run_in_background(
                do_delete,
                success_msg=_("msg_deleted_count", count=len(files)),
                log_action=_("log_delete")
            )
            
        except Exception as e:
            self.logger.error(_("log_task_failed", type=_("log_delete"), error=e))
            op.update_status(self.repository.path, 'failed', str(e))
        
    def _on_new_folder(self, parent_file: Optional[VirtualFile]):
        """Handle new folder creation."""
        # Check mutual exclusion
        if not self._can_start_task("create_dir"):
            return
            
        parent_id = parent_file.id if parent_file else None
        parent_desc = parent_file.name if parent_file else _("label_root")
        
        # Get folder name
        name, ok = QInputDialog.getText(
            self,
            _("dialog_new_folder_title"),
            _("dialog_new_folder_msg"),
            text=_("placeholder_new_folder")
        )
        
        if not ok or not name.strip():
            return
            
        name = name.strip()
        
        try:
            # Check for name collision
            existing_files = VirtualFile.get_children(self.repository.path, parent_id)
            for existing in existing_files:
                try:
                    existing_name = decrypt_metadata(
                        existing.name_encrypted,
                        self.master_key,
                        existing.name_nonce
                    )
                    if existing_name == name:
                        QMessageBox.warning(
                            self,
                            _("dialog_name_clash_title"),
                            _("dialog_name_clash_msg", name=name)
                        )
                        return
                except Exception:
                    continue
            
            # Encrypt name
            name_encrypted, name_nonce = encrypt_metadata(name, self.master_key)
            
            # Create directory
            VirtualFile.create(
                repo_path=self.repository.path,
                parent_id=parent_id,
                name_encrypted=name_encrypted,
                name_nonce=name_nonce,
                is_directory=True
            )
            
            self._load_files()
            self.logger.operation(_("log_new_folder"), _("log_new_folder_at", name=name, parent=parent_desc))
            
        except Exception as e:
            self.logger.error(f"Failed to create folder: {e}")
            QMessageBox.critical(self, _("label_error"), _("error_create_folder_failed", error=str(e)))
            
    def _on_rename_file(self, vf: VirtualFile, new_name: str):
        """Handle rename request."""
        # Check mutual exclusion
        if not self._can_start_task("rename"):
            return
        
        self._active_task = "rename"
        
        name_encrypted, name_nonce = encrypt_metadata(new_name, self.master_key)
        vf.update_name(name_encrypted, name_nonce)
        self._load_files()
        self.logger.operation(_("log_rename"), _("log_rename_arrow", name=new_name))
        
        # Clear task immediately (sync operation)
        self._active_task = None
    
    def _on_comment_file(self, vf: VirtualFile, new_comment: str):
        """Handle comment update."""
        # Check mutual exclusion
        if not self._can_start_task("comment"):
            return
        
        self._active_task = "comment"
        
        if new_comment:
            comment_encrypted, comment_nonce = encrypt_metadata(
                new_comment, self.master_key
            )
        else:
            comment_encrypted, comment_nonce = None, None
        
        vf.update_comment(comment_encrypted, comment_nonce)
        self._load_files()
        self.logger.operation(_("log_comment_update"), _("log_comment_for", name=vf.name if vf.name else f"ID {vf.id}", id=vf.id))
        
        # Clear task immediately (sync operation)
        self._active_task = None
    
    def _on_export_decrypted(self, files: list, output_dir: str, existing_op=None):
        """Handle decrypt export request."""
        # Check mutual exclusion
        if not self._can_start_task("decrypt_export") and not existing_op:
            return
        
        self._active_task = "decrypt_export"
        
        # Log start
        names = [vf.name if vf.name else f"ID {vf.id}" for vf in files]
        self.logger.operation_start(_("type_export"), _("msg_exported_count", count=len(files)), details=_("log_export_target", path=output_dir))
        self.progress_widget.set_status("Decrypting")
        
        # Create or use existing operation record
        if existing_op:
            op = existing_op
            self._current_operation = op
        else:
            source_ids = [f.id for f in files]
            op = Operation.create(
                self.repository.path, 
                'export', 
                source_ids, 
                target_path=output_dir
            )
            self._current_operation = op
            
        # Check blocks exist
        for vf in files:
            missing = check_blocks_exist(vf, self.repository)
            if missing:
                name = vf.name if vf.name else f"ID {vf.id}"
                QMessageBox.warning(
                    self,
                    _("dialog_export_failed_title"),
                    _("dialog_export_failed_msg", name=name) + 
                    "\n".join(missing[:5])
                )
                if not existing_op:
                    op.delete(self.repository.path)
                self._active_task = None
                return
        
        progress_callback = self._make_progress_callback(op)

        exporter = FileExporter(
            self.repository,
            self.master_key,
            progress_callback,
            is_cancelled=self._worker_ref_callback,
            operation=op
        )
        # Store in MainWindow if we want, but local closure reference is fine as long as we don't need it elsewhere
        # We don't have a self._current_exporter attribute used in cleanup yet, 
        # but let's add it for consistency if we want to cleanup exported files.
        # Actually our cleanup logic uses op.source_paths, so it doesn't need exporter ref.
        
        def export():
            # Pre-calculate total size
            total_size = FileExporter.calculate_total_export_size(
                files, self.repository.path, progress_callback
            )
            
            # Update op with total size
            if not existing_op:
                db = get_repository_database(self.repository.path)
                db.execute("UPDATE operations SET total_size = ? WHERE id = ?", (total_size, op.id))
                op.total_size = total_size # Update locally for callback

            # Always start from 0 because Exporter will reconstruct progress via scanning (avoid double counting)
            exporter.set_progress_params(0, total_size)
            
            for vf in files:
                if self._worker.is_cancelled():
                    return
                success, errors = exporter.export_decrypted(vf, Path(output_dir), reset_progress=False)
                if errors:
                    return _("error_export_generic", error=errors[0])
            
            # Remove operation record on success
            op.delete(self.repository.path)
            
            return None  # Success
        
        self._run_in_background(
            export, 
            _("msg_exported_count", count=len(files)), 
            open_dir=output_dir,
            log_items=names,
            log_action=_("log_export")
        )
    
    
    def _run_in_background(
        self, 
        operation, 
        success_msg: str, 
        open_dir: str = None,
        log_items: list = None,
        log_action: str = None,
        rollback_file_ids: list = None
    ):
        """Run operation in background thread."""
        # Store rollback info for cancel
        self._rollback_file_ids = rollback_file_ids or []
        
        self._worker = WorkerThread(operation)
        self._worker.progress.connect(self._on_progress_update)
        self._worker.finished.connect(
            lambda success, msg: self._on_worker_finished(
                success, msg, success_msg, open_dir, log_items, log_action
            )
        )
        self._worker.start()
    
    def _on_worker_finished(
        self, 
        success: bool, 
        message: str, 
        success_msg: str, 
        open_dir: str,
        log_items: list = None,
        log_action: str = None
    ):
        """Handle worker thread completion."""
        # Clear rollback info
        self._rollback_file_ids = []
        
        if success:
            # Progress bar complete (no text)
            self.progress_widget.set_complete("")
            
            # Log success message
            self.logger.operation_end(log_action, _("msg_items_count", count=len(log_items)) if log_items else success_msg)
            
            # Log each item if provided
            if log_items and log_action:
                for item in log_items:
                    self.logger.debug(_("log_item_finished", action=log_action, item=item))
            
            # Synchronized cleanup for successful task (removes DB record)
            self._cleanup_current_task(cleanup_success=True)
            
            self._load_files()
            self._update_capacity()
            
            # Open directory if requested
            if open_dir:
                try:
                    os.startfile(open_dir)
                except Exception:
                    pass
        elif message == "__CANCELLED__":
            self.progress_widget.set_complete(_("msg_cancelled"))
            self.log_widget.add_info(_("log_cancelled_by_user"))
            # Synchronized cleanup for cancelled task (performs rollback/deletion)
            self._cleanup_current_task(cleanup_success=False)
            self._load_files()
            self._update_capacity()
        else:
            self.progress_widget.set_error(message)
            self.logger.error(message)
            # Synchronized cleanup for failed task (performs rollback/deletion)
            self._cleanup_current_task(cleanup_success=False)
            self._load_files()
            self._update_capacity()
        
        # Finally clear active task state
        self._active_task = None
        self._current_operation = None
        self._current_importer = None
        self._current_task_phase = 0
    
    def _worker_ref_callback(self):
        """Helper to get cancellation status from current worker."""
        if self._worker:
            return self._worker.is_cancelled()
        return False

    def _on_cancel(self):
        """Handle cancel request with task-specific rollback."""
        if self._worker and self._worker.isRunning():
            # Update status in DB so resume logic knows we were cancelling
            op = getattr(self, '_current_operation', None)
            if op:
                op.update_status(self.repository.path, 'cancelling')
                self.logger.info(_("log_cleanup_recorded"))
            
            self._worker.cancel()
            self.progress_widget.set_status(_("status_cancelling")) # Update UI feedback
    
    def _cleanup_current_task(self, cleanup_success=False, is_exit=False):
        """
        Clean up resources based on current active task type.
        
        Args:
            cleanup_success: If True, only delete the operation record.
                            If False, perform full rollback (delete partial files).
            is_exit: If True, keep the record for resumption.
        """
        if not self._active_task:
            return
        
        op = getattr(self, '_current_operation', None)
        
        # 1. Exit handling (No deletion, just pause)
        if is_exit:
            if op:
                self.logger.info(_("log_pause_on_exit"))
                # Status remains 'processing' in DB
            return

        # 2. Failure/Cancellation Rollback
        if not cleanup_success:
            if self._active_task in ("encrypt", "import"):
                # Rollback importer (deletes created virtual files and blocks)
                if hasattr(self, '_current_importer') and self._current_importer:
                    try:
                        fids = self._current_importer._created_file_ids
                        if fids:
                            self.logger.info(_("log_rollback_files", count=len(fids)))
                            from src.database.models import FileBlockMapping, Block, VirtualFile
                            # Use new batch methods for extreme performance
                            bids = FileBlockMapping.remove_mappings_for_files_batch(fids, self.repository.path)
                            if bids:
                                Block.decrement_batch(bids, self.repository.path)
                            VirtualFile.delete_batch(fids, self.repository.path)
                    except Exception as e:
                        self.logger.error(f"Import rollback failed: {e}")
            
            elif self._active_task in ("decrypt_export", "export"):
                # Delete partially exported files
                if op and op.target_path:
                    try:
                        target_dir = Path(op.target_path)
                        source_ids = json.loads(op.source_paths)
                        self.logger.info(_("log_cleanup_files", count=len(source_ids)))
                        
                        # Optimization: Get all metadata in batch to avoid O(N) queries
                        from src.database.models import VirtualFile
                        vfs = VirtualFile.get_batch(source_ids, self.repository.path)
                        
                        for vf in vfs:
                            name = decrypt_metadata(vf.name_encrypted, self.master_key, vf.name_nonce)
                            target_file = target_dir / name
                            if target_file.exists():
                                if target_file.is_dir():
                                    shutil.rmtree(target_file, ignore_errors=True)
                                else:
                                    target_file.unlink(missing_ok=True)
                    except Exception as e:
                        self.logger.error(f"Export cleanup failed: {e}")

        if op:
            try:
                op.delete(self.repository.path)
                self.logger.info(_("log_cleanup_finished"))
                self._current_operation = None
            except Exception as e:
                self.logger.debug(f"Op record deletion failed (might be already deleted): {e}")
                
        # Clear active state after cleanup unless exiting
        self._active_task = None
        self._current_task_phase = 0
        self.logger.info(_("log_cleanup_finished"))
    
    def _can_start_task(self, task_name: str) -> bool:
        """Check if a new task can be started (mutual exclusion).
        
        Args:
            task_name: Name of the task to start
        
        Returns:
            True if task can start, False if blocked
        """
        if self._active_task is not None:
            type_names = {
                "encrypt": _("label_encrypt_import"),
                "decrypt_export": _("label_decrypt_export"),
                "delete": _("label_delete"),
                "rename": _("label_rename"),
                "comment": _("label_comment")
            }
            current_task_name = type_names.get(self._active_task, self._active_task)
            QMessageBox.warning(
                self,
                _("dialog_task_busy_title"),
                _("dialog_task_busy_msg", name=current_task_name)
            )
            return False
        return True
    
    def closeEvent(self, event):
        """Handle window close event with graceful shutdown."""
        # Check if we are restarting (bypass confirmation)
        if getattr(self, "_is_restarting", False):
            self.logger.remove_callback(self.log_widget.add_log)
            event.accept()
            return
            
        # Check if a task is running
        if self._active_task and self._worker and self._worker.isRunning():
            reply = QMessageBox.warning(
                self,
                _("dialog_exit_warning_title"),
                _("dialog_exit_warning_msg"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            
            # This corresponds to "Exit/Pause" (Yes)
            self._worker.cancel()
            self._cleanup_current_task(is_exit=True)
        else:
            reply = QMessageBox.question(
                self,
                _("exit_confirm_title"),
                _("exit_confirm_msg"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        
        self.logger.operation(_("log_exit"), _("log_app_closed"))
        self.logger.remove_callback(self.log_widget.add_log)
        event.accept()
