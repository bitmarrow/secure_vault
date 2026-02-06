"""
Secure Vault - File Tree Component
Tree view for virtual file structure with drag-and-drop support.
"""

from typing import Optional, List

from PyQt6.QtWidgets import (
    QTreeView, QAbstractItemView, QHeaderView
)
from PyQt6.QtCore import (
    Qt, QModelIndex, pyqtSignal, QSortFilterProxyModel
)
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QDragEnterEvent, QDropEvent, QKeyEvent
from PyQt6.QtWidgets import QFileIconProvider


class FileSortProxyModel(QSortFilterProxyModel):
    """Proxy model for proper numeric sorting of size and count columns."""
    
    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        """Compare two items for sorting."""
        column = left.column()
        
        # For Size (column 2) and Count (column 3), use UserRole data (numeric values)
        if column in (2, 3):
            left_data = self.sourceModel().data(left, Qt.ItemDataRole.UserRole)
            right_data = self.sourceModel().data(right, Qt.ItemDataRole.UserRole)
            
            # Handle None/missing values - treat them as -1 so they sort to top/bottom
            if left_data is None:
                left_data = -1
            if right_data is None:
                right_data = -1
            
            return left_data < right_data
        
        # For other columns, use default string comparison
        return super().lessThan(left, right)

from src.database.models import VirtualFile
from src.core.crypto import decrypt_metadata
from src.core.hash_utils import format_size
from src.core.i18n import _


class FileTreeModel(QStandardItemModel):
    """Model for the virtual file tree."""
    
    @property
    def COLUMNS(self):
        return [
            _("tree_col_name"), _("tree_col_date"), _("tree_col_size"), 
            _("tree_col_items"), _("tree_col_comment")
        ]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self._file_map: dict = {}  # Maps file ID to VirtualFile
        self._master_key: bytes = None
        self._repo_path: str = None
        self._icon_provider = QFileIconProvider()
        self._loaded_dirs: set = set()  # Track which directories have been loaded
    
    def set_master_key(self, key: bytes):
        """Set the master key for decryption."""
        self._master_key = key
    
    def set_repository_path(self, repo_path: str):
        """Set the current repository path."""
        self._repo_path = repo_path
    
    # Legacy compatibility
    def set_repository_id(self, repo_id: int):
        """Deprecated - use set_repository_path instead."""
        pass
    
    def load_files(self):
        """Load files from database."""
        self.clear()
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self._file_map.clear()
        self._loaded_dirs.clear()
        
        if not self._repo_path or not self._master_key:
            return
        
        # Load root level files
        root_files = VirtualFile.get_children(self._repo_path, None)
        for vf in root_files:
            self._add_file_item(vf, self.invisibleRootItem())
            
    def mimeTypes(self):
        """Supported mime types."""
        types = super().mimeTypes()
        if "text/uri-list" not in types:
            types.append("text/uri-list")
        return types

    def canDropMimeData(self, data, action, row, column, parent):
        """Check if we can drop this data."""
        if data.hasUrls():
            return True
        return super().canDropMimeData(data, action, row, column, parent)
        
    def dropMimeData(self, data, action, row, column, parent):
        """
        Handle drop data. 
        Note: The View handles the actual file logic in dropEvent, 
        but we implement this to satisfy the framework's validity checks.
        """
        if data.hasUrls():
            return True
        return super().dropMimeData(data, action, row, column, parent)
    
    def _add_file_item(self, virtual_file: VirtualFile, parent_item: QStandardItem):
        """Add a virtual file as a tree item."""
        # Decrypt name
        try:
            name = decrypt_metadata(
                virtual_file.name_encrypted,
                self._master_key,
                virtual_file.name_nonce
            )
        except Exception:
            name = _("label_encrypt_error")
        
        # Decrypt comment if exists
        comment = ""
        if virtual_file.comment_encrypted and virtual_file.comment_nonce:
            try:
                comment = decrypt_metadata(
                    virtual_file.comment_encrypted,
                    self._master_key,
                    virtual_file.comment_nonce
                )
            except Exception:
                comment = ""
        
        # For directories, just get the count (without loading all children)
        has_children = False
        item_count_str = "-"
        if virtual_file.is_directory:
            # Quick count query instead of loading all children
            children_count = VirtualFile.count_children(self._repo_path, virtual_file.id)
            item_count_str = str(children_count)
            has_children = children_count > 0
            
        # Create row items
        name_item = QStandardItem(name)
        name_item.setData(virtual_file.id, Qt.ItemDataRole.UserRole)
        
        # Set flags
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDragEnabled
        if virtual_file.is_directory:
            flags |= Qt.ItemFlag.ItemIsDropEnabled
            name_item.setIcon(self._icon_provider.icon(QFileIconProvider.IconType.Folder))
        else:
            # Files cannot accept drops (though we handle dropping 'on' them as dropping 'near' them in View)
            # Standard View logic stops highlighting if DropEnabled is missing, which is correct for files
            name_item.setIcon(self._icon_provider.icon(QFileIconProvider.IconType.File))
            
        name_item.setFlags(flags)
        
        # Date
        if virtual_file.upload_date:
            if isinstance(virtual_file.upload_date, str):
                date_str = virtual_file.upload_date[:19].replace("T", " ")
            else:
                date_str = virtual_file.upload_date.strftime("%Y-%m-%d %H:%M:%S")
        else:
            date_str = ""
        date_item = QStandardItem(date_str)
        date_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDragEnabled)
        date_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        
        # Size
        if virtual_file.is_directory:
            size_str = "-"
        else:
            size_str = format_size(virtual_file.size)
        size_item = QStandardItem(size_str)
        size_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDragEnabled)
        size_item.setData(virtual_file.size, Qt.ItemDataRole.UserRole)  # For sorting
        size_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        # Item Count
        count_item = QStandardItem(item_count_str)
        count_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDragEnabled)
        if item_count_str != "-":
            count_item.setData(int(item_count_str), Qt.ItemDataRole.UserRole) # For sorting
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Comment
        comment_item = QStandardItem(comment)
        comment_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDragEnabled)
        
        # Add row
        parent_item.appendRow([name_item, date_item, size_item, count_item, comment_item])
        
        # Store mapping using file ID as key
        self._file_map[virtual_file.id] = virtual_file
        
        # For directories with children, add a placeholder so expand arrow appears
        if virtual_file.is_directory and has_children:
            placeholder = QStandardItem("...")
            placeholder.setFlags(Qt.ItemFlag.ItemIsEnabled)
            name_item.appendRow([placeholder, QStandardItem(), QStandardItem(), QStandardItem(), QStandardItem()])
    
    def load_children(self, parent_item: QStandardItem):
        """Load children for a directory item (called on expand)."""
        file_id = parent_item.data(Qt.ItemDataRole.UserRole)
        
        # Skip if already loaded
        if file_id in self._loaded_dirs:
            return
        
        # Mark as loaded
        self._loaded_dirs.add(file_id)
        
        # Remove placeholder
        parent_item.removeRows(0, parent_item.rowCount())
        
        # Load actual children
        children = VirtualFile.get_children(self._repo_path, file_id)
        for child in children:
            self._add_file_item(child, parent_item)
    
    def get_virtual_file(self, item: QStandardItem) -> Optional[VirtualFile]:
        """Get VirtualFile for an item."""
        if item is None:
            return None
        file_id = item.data(Qt.ItemDataRole.UserRole)
        return self._file_map.get(file_id)
    
    def get_virtual_file_by_index(self, index: QModelIndex) -> Optional[VirtualFile]:
        """Get VirtualFile for an index."""
        if not index.isValid():
            return None
        # Get the first column item (name)
        name_index = self.index(index.row(), 0, index.parent())
        item = self.itemFromIndex(name_index)
        if item is None:
            return None
        file_id = item.data(Qt.ItemDataRole.UserRole)
        return self._file_map.get(file_id)
    
    def get_parent_id(self, index: QModelIndex) -> Optional[int]:
        """Get parent directory ID for an index."""
        if not index.isValid():
            return None
        
        parent_index = index.parent()
        if not parent_index.isValid():
            return None
        
        vf = self.get_virtual_file_by_index(parent_index)
        return vf.id if vf else None


class FileTreeView(QTreeView):
    """Tree view for file explorer with drag-and-drop."""
    
    files_dropped = pyqtSignal(list, object)  # (file_paths, target_parent_id)
    items_moved = pyqtSignal(list, object)  # (file_ids, new_parent_id)
    context_menu_requested = pyqtSignal(QModelIndex, object)  # (index, global_pos)
    rename_requested = pyqtSignal(object)  # (VirtualFile)
    delete_requested = pyqtSignal(list)  # (list of VirtualFiles)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_view()
    
    def _setup_view(self):
        """Setup view properties."""
        # Enable drag-and-drop
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setDropIndicatorShown(True)
        
        # Selection
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        
        # Appearance
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setAnimated(True)
        self.setIndentation(20)
        self.setRootIsDecorated(True)
        
        # Header
        header = self.header()
        header.setStretchLastSection(True)
        header.setSortIndicatorShown(True)
        header.setSectionsClickable(True)
        
        # Enable sorting
        self.setSortingEnabled(True)
        
        # Context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)
    
    def setModel(self, model: FileTreeModel):
        """Set the model and configure header."""
        self._source_model = model
        
        # Use proxy model for proper sorting
        self._proxy_model = FileSortProxyModel()
        self._proxy_model.setSourceModel(model)
        super().setModel(self._proxy_model)
        
        # Connect expanded signal for lazy loading
        self.expanded.connect(self._on_expanded)
        
        header = self.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch) # Comment
        
        header.resizeSection(1, 150) # Date
        header.resizeSection(2, 100) # Size
        header.resizeSection(3, 80)  # Count
        
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter."""
        super().dragEnterEvent(event)
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dragMoveEvent(self, event):
        """Handle drag move to show drop indicator."""
        super().dragMoveEvent(event)
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event: QDropEvent):
        """Handle drop event."""
        # Get drop target
        drop_index = self.indexAt(event.position().toPoint())
        target_parent_id = None
        
        if drop_index.isValid():
            # Map proxy index to source index
            source_drop_index = self._proxy_model.mapToSource(drop_index)
            vf = self._source_model.get_virtual_file_by_index(source_drop_index)
            if vf:
                if vf.is_directory:
                    target_parent_id = vf.id
                else:
                    # Drop on file - use its parent
                    target_parent_id = vf.parent_id
        
        if event.mimeData().hasUrls():
            # External drop from Windows Explorer
            file_paths = []
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_paths.append(url.toLocalFile())
            
            if file_paths:
                self.files_dropped.emit(file_paths, target_parent_id)
                event.acceptProposedAction()
        else:
            # Internal move
            selected = self.selectedIndexes()
            if selected:
                # Get unique file IDs (first column only)
                file_ids = set()
                for idx in selected:
                    if idx.column() == 0:
                        # Map proxy index to source index
                        source_idx = self._proxy_model.mapToSource(idx)
                        vf = self._source_model.get_virtual_file_by_index(source_idx)
                        if vf:
                            file_ids.add(vf.id)
                
                if file_ids:
                    self.items_moved.emit(list(file_ids), target_parent_id)
                
                event.acceptProposedAction()
    
    def _on_expanded(self, index: QModelIndex):
        """Handle directory expansion - load children lazily."""
        if not index.isValid():
            return
        # Map proxy index to source index
        source_index = self._proxy_model.mapToSource(index)
        item = self._source_model.itemFromIndex(source_index)
        if item:
            self._source_model.load_children(item)
    
    def _on_context_menu(self, pos):
        """Handle context menu request."""
        index = self.indexAt(pos)
        global_pos = self.viewport().mapToGlobal(pos)
        self.context_menu_requested.emit(index, global_pos)
    
    def get_selected_files(self) -> List[VirtualFile]:
        """Get list of selected VirtualFiles."""
        selected = self.selectedIndexes()
        files = []
        seen_ids = set()
        
        for idx in selected:
            if idx.column() == 0:  # Only process first column
                # Map proxy index to source index
                source_idx = self._proxy_model.mapToSource(idx)
                vf = self._source_model.get_virtual_file_by_index(source_idx)
                if vf and vf.id not in seen_ids:
                    files.append(vf)
                    seen_ids.add(vf.id)
        
        return files

    def keyPressEvent(self, event: QKeyEvent):
        """Handle keyboard shortcuts."""
        if event.key() == Qt.Key.Key_F2:
            # F2 - Rename
            files = self.get_selected_files()
            if len(files) == 1:
                self.rename_requested.emit(files[0])
            event.accept()
        elif event.key() == Qt.Key.Key_Delete:
            # Delete - Delete files
            files = self.get_selected_files()
            if files:
                self.delete_requested.emit(files)
            event.accept()
        else:
            super().keyPressEvent(event)
