"""
Secure Vault - Progress Widget
Progress bar for file operations.
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QProgressBar, QPushButton
)
from PyQt6.QtCore import pyqtSignal, Qt
from src.core.i18n import _


class ProgressWidget(QWidget):
    """Widget showing operation progress."""
    
    cancel_requested = pyqtSignal()
    
    # Statuses that allow cancellation
    # Statuses that allow cancellation (deletion-related statuses like "Cleaning" are excluded)
    ACTIVE_STATUSES = ["Encrypting", "Decrypting", "Exporting", "Compressing", "Updating"]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(12)
        
        # Left: Status and Progress
        left_container = QWidget()
        left_layout = QHBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)
        
        # Status label
        self.status_label = QLabel(_("status_ready"))
        self.status_label.setMinimumWidth(120)
        self.status_label.setProperty("class", "status-text")
        left_layout.addWidget(self.status_label)
        
        # Progress bar (use 0-10000 range for 0.01% precision)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 10000)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(12)
        left_layout.addWidget(self.progress_bar, 1)
        
        layout.addWidget(left_container, 3)
        
        # Right: Speed/ETA and Cancel
        right_container = QWidget()
        right_layout = QHBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)
        
        # Info label (Speed • ETA)
        self.info_label = QLabel("")
        self.info_label.setFixedWidth(200)
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.info_label.setProperty("class", "info-text")
        right_layout.addWidget(self.info_label)
        
        # Cancel button
        self.cancel_btn = QPushButton(_("btn_cancel"))
        self.cancel_btn.setFixedWidth(60)
        self.cancel_btn.setProperty("class", "cancel-btn")
        
        # Reserve space when hidden
        sp = self.cancel_btn.sizePolicy()
        sp.setRetainSizeWhenHidden(True)
        self.cancel_btn.setSizePolicy(sp)
        
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)
        right_layout.addWidget(self.cancel_btn)
        
        layout.addWidget(right_container, 1)
        
        # Optional: Add some basic styling for labels
        self.setStyleSheet("""
            QLabel.status-text { font-weight: 500; }
            QLabel.info-text { color: #888; font-size: 11px; }
            QProgressBar { 
                border-radius: 6px; 
                background: #e0e0e0; 
                text-align: center; 
                color: black;
            }
            QProgressBar::chunk { 
                background: #2196F3; 
                border-radius: 6px; 
            }
        """)

    def set_progress(self, current: object, total: object, message: str = "", speed: str = "", eta: str = ""):
        """
        Update progress.
        
        Args:
            current: Current progress value (bytes)
            total: Total value (bytes)
            message: Status message
            speed: Speed string (e.g., "15.4 MB/s")
            eta: ETA string (e.g., "2:30 left")
        """
        if total > 0:
            # Calculate percentage with decimal precision
            percentage_float = (current / total) * 100
            # Map to 0-10000 for visual precision
            visual_value = int((current / total) * 10000)
            # Minimum 1 when work has started (0.01% visual progress)
            if current > 0 and visual_value < 1:
                visual_value = 1
            self.progress_bar.setValue(min(visual_value, 10000))
            
            # Always show percentage with appropriate precision
            if percentage_float < 0.1 and current > 0:
                self.progress_bar.setFormat(f"{percentage_float:.3f}%")
            elif percentage_float < 10:
                self.progress_bar.setFormat(f"{percentage_float:.2f}%")
            else:
                self.progress_bar.setFormat(f"{percentage_float:.1f}%")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("0%")
        
        # Update info label
        info_parts = []
        if speed:
            info_parts.append(speed)
        if eta:
            info_parts.append(eta)
        
        self.info_label.setText(" • ".join(info_parts))
        
        if message:
            self.set_status(message)
    
    def set_status(self, message: str):
        """Set status message and update cancel button visibility."""
        self.status_label.setText(message)
        
        # Show cancel button if status starts with an active prefix
        is_active = False
        upper_msg = message.upper()
        for status in self.ACTIVE_STATUSES:
            if upper_msg.startswith(status.upper()):
                is_active = True
                break
        
        self.cancel_btn.setVisible(is_active)
    
    def reset(self):
        """Reset progress to initial state."""
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0%")
        self.info_label.setText("")
        self.set_status("Ready")
    
    def set_complete(self, message: str = ""):
        """Mark operation as complete."""
        self.progress_bar.setValue(10000)  # Max value for 0-10000 range
        self.progress_bar.setFormat("100%")
        self.info_label.setText("")
        if message:
            self.set_status(message)
        else:
            self.set_status(_("status_ready"))
    
    def set_error(self, message: str = _("label_error")):
        """Show error state."""
        self.status_label.setText(f"❌ {message}")
        self.status_label.setStyleSheet("color: #f14c4c;")
        self.info_label.setText("")
        self.cancel_btn.setVisible(False)
    
    def clear_error(self):
        """Clear error styling."""
        self.status_label.setStyleSheet("")
