"""
Secure Vault - File Operations
Handles file import, export, and encryption/decryption operations.
"""

import os
from pathlib import Path
from typing import Tuple, Optional, Callable
from src.core.i18n import _

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.crypto import (
    encrypt_metadata, decrypt_metadata, BLOCK_SIZE
)
from src.core.hash_utils import iter_file_blocks, get_file_size
from src.database.models import VirtualFile, Block, FileBlockMapping, Repository
from src.operations.block_manager import BlockManager
from src.utils.logger import get_logger
from src.database.database import get_repository_database
from src.repository.repository import can_store_file, get_disk_free_space
import collections


def check_target_capacity(target_path: Path, required_size: int) -> bool:
    """Verify if there is enough space on the target drive."""
    try:
        free_space = get_disk_free_space(str(target_path))
        return free_space >= required_size
    except Exception:
        return True # Default to True if check fails to avoid blocking users


class ProgressTracker:
    """Tracks progress, speed and ETA for file operations."""
    
    def __init__(self, callback: Optional[Callable] = None, interval: float = 0.2):
        """
        Args:
            callback: Function to call on update (current, total, message, speed, eta)
            interval: Minimum seconds between UI updates to avoid flooding
        """
        self.callback = callback
        self.interval = interval
        self.last_update_time = 0
        
        self.total_bytes = 0
        self.processed_bytes = 0
        self.message = ""
        
        # Performance tracking
        self.start_time = time.time()
        self.history = collections.deque(maxlen=20)  # (time, processed) samples
        self._last_speed = 0
        self._last_eta = ""

    def set_total(self, total: int):
        self.total_bytes = total
        self.start_time = time.time()
        self.history.clear()

    def update(self, processed_delta: int, message: str = None, force: bool = False):
        """Update progress and trigger callback if interval passed."""
        self.processed_bytes += processed_delta
        if message is not None:
            self.message = message
            
        now = time.time()
        self.history.append((now, self.processed_bytes))
        
        # Throttled update
        if force or (now - self.last_update_time >= self.interval):
            speed_val, speed_str = self._calculate_speed()
            eta_str = self._calculate_eta(speed_val)
            
            if self.callback:
                self.callback(
                    self.processed_bytes,
                    self.total_bytes,
                    self.message,
                    speed_str,
                    eta_str
                )
            self.last_update_time = now

    def _calculate_speed(self) -> Tuple[float, str]:
        """Calculate throughput in bytes/second."""
        if len(self.history) < 2:
            return 0, ""
            
        t1, p1 = self.history[0]
        t2, p2 = self.history[-1]
        
        duration = t2 - t1
        if duration <= 0:
            return 0, ""
            
        speed = (p2 - p1) / duration
        self._last_speed = speed
        
        if speed < 1024:
            return speed, f"{speed:.1f} B/s"
        elif speed < 1024 * 1024:
            return speed, f"{speed/1024:.1f} KB/s"
        else:
            return speed, f"{speed/(1024*1024):.1f} MB/s"

    def _calculate_eta(self, speed: float) -> str:
        """Estimate time remaining."""
        if speed <= 0 or self.total_bytes <= 0:
            return ""
            
        remaining_bytes = self.total_bytes - self.processed_bytes
        if remaining_bytes <= 0:
            return _("eta_soon")
            
        seconds = remaining_bytes / speed
        
        if seconds < 60:
            return _("eta_seconds", seconds=int(seconds))
        elif seconds < 3600:
            return _("eta_minutes", m=int(seconds // 60), s=int(seconds % 60))
        else:
            return _("eta_hours", h=int(seconds // 3600), m=int((seconds % 3600) // 60))


def fast_scandir(path: Path, callback: Optional[Callable] = None, state: dict = None) -> int:
    """Rapidly calculate total size using os.scandir with optional throttled feedback."""
    total = 0
    try:
        if path.is_file():
            return path.stat().st_size
        
        # Throttling logic
        if callback and state:
            now = time.time()
            if now - state.get('last_update', 0) >= 0.2:
                callback(0, 0, f"{_('status_calculating')}: {path.name}")
                state['last_update'] = now

        with os.scandir(str(path)) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += fast_scandir(Path(entry.path), callback, state)
    except (PermissionError, OSError):
        pass
    return total
class FileOperationError(Exception):
    """Exception for file operation failures."""
    pass


class OperationCancelled(Exception):
    """Exception raised when an operation is cancelled by the user."""
    pass





class FileImporter:
    """Handles file and folder import with encryption."""
    
        
    def __init__(
        self,
        repository: Repository,
        master_key: bytes,
        progress_callback: Optional[Callable[[int, int, str, str, str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
        operation: Optional["Operation"] = None
    ):
        """
        Initialize file importer.
        
        Args:
            repository: Target repository
            master_key: Master encryption key
            progress_callback: Callback for progress updates
            is_cancelled: Optional callback to check for cancellation
            operation: Existing operation to resume
        """
        self.repository = repository
        self.master_key = master_key
        self.operation = operation
        
        # BlockManager - write directly to repository
        self.block_manager = BlockManager(
            repository.path, 
            master_key
        )
        
        self.is_cancelled = is_cancelled or (lambda: False)
        self.logger = get_logger()
        
        # Unified throttled callback for both UI and DB
        def unified_callback(current, total, msg, speed, eta):
            if progress_callback:
                progress_callback(current, total, msg, speed, eta)
            if self.operation:
                self.operation.update_progress(self.repository.path, current)
                
        self.progress_tracker = ProgressTracker(unified_callback)
        self._created_file_ids: list[int] = []  # Track created files for rollback

    def set_total_bytes(self, total_bytes: int):
        """Set total bytes for the current import session."""
        self.progress_tracker.set_total(total_bytes)
    
    def import_file(
        self,
        file_path: Path,
        parent_id: Optional[int] = None
    ) -> VirtualFile:
        """
        Import a single file.
        
        Args:
            file_path: Path to file to import
            parent_id: Parent directory ID (None for root)
        
        Returns:
            Created VirtualFile object
        """
        file_size = get_file_size(file_path)
        
        # Check capacity
        if not can_store_file(self.repository, file_size):
            error_msg = f"Insufficient storage capacity for {file_path.name} ({file_size} bytes)"
            self.logger.error(error_msg)
            raise FileOperationError(error_msg)
            
        # Check for existing files and generate unique name
        from src.utils.file_utils import get_unique_filename
        
        # Get existing names in the target directory
        existing_files = VirtualFile.get_children(self.repository.path, parent_id)
        existing_names = set()
        for vf in existing_files:
            try:
                name = decrypt_metadata(
                    vf.name_encrypted,
                    self.master_key,
                    vf.name_nonce
                )
                existing_names.add(name)
            except Exception:
                continue
                
        # RESUMPTION LOGIC: Check if this file was already partially imported
        virtual_file = None
        if self.operation:
            # Check for existing file with exact name and size in target directory
            # (In a real production app, we might store the specific VF ID in the Operation record)
            for vf in existing_files:
                try:
                    name = decrypt_metadata(vf.name_encrypted, self.master_key, vf.name_nonce)
                    if name == file_path.name and vf.size == file_size:
                        virtual_file = vf
                        self.logger.info(f"Found existing partial virtual file for {name}, resuming...")
                        break
                except Exception:
                    continue
        
        if virtual_file is None:
            # Generate unique name if not resuming or file not found
            final_name = get_unique_filename(file_path.name, existing_names)
            
            # Encrypt filename
            name_encrypted, name_nonce = encrypt_metadata(
                final_name, self.master_key
            )
            
            # Create virtual file entry
            virtual_file = VirtualFile.create(
                repo_path=self.repository.path,
                parent_id=parent_id,
                name_encrypted=name_encrypted,
                name_nonce=name_nonce,
                is_directory=False,
                size=file_size
            )
        
        # Track created file immediately for rollback
        if virtual_file.id not in self._created_file_ids:
            self._created_file_ids.append(virtual_file.id)
        
        self.logger.debug(f"Starting/Resuming import: {file_path.name} ({file_size} bytes) -> ID: {virtual_file.id}")
        
        # Process file blocks in parallel batches to cap RAM usage
        BATCH_SIZE = 16
        block_order = 0
        blocks_to_map = [] # Initialize here
        
        # RESUMPTION LOGIC: Skip already mapped blocks
        existing_mappings = FileBlockMapping.get_blocks_for_file(virtual_file.id, self.repository.path)
        if existing_mappings:
            block_order = len(existing_mappings)
            self.logger.info(f"Skipping {block_order} blocks already imported for {file_path.name}")
            # Update progress tracker
            self.progress_tracker.update(block_order * BLOCK_SIZE, f"Resuming: {file_path.name}")
        
        # Use ThreadPoolExecutor for CPU/IO intensive preparation
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Use an iterator to read the file lazily
            block_iterator = iter_file_blocks(file_path, BLOCK_SIZE)
            
            # Skip already processed blocks
            for _ in range(block_order):
                next(block_iterator, None)
            
            while True:
                if self.is_cancelled():
                    raise OperationCancelled("Import cancelled by user")
                    
                # Collect a batch of futures
                futures = []
                for _ in range(BATCH_SIZE):
                    try:
                        block_data = next(block_iterator)
                        future = executor.submit(self.block_manager.prepare_block, block_data)
                        futures.append(future)
                    except StopIteration:
                        break
                
                if not futures:
                    break
                    
                # Process and commit the batch
                db = get_repository_database(self.repository.path)
                with db.transaction():
                    batch_mappings = []
                    for future in futures:
                        if self.is_cancelled():
                            raise OperationCancelled("Import cancelled by user")
                            
                        prepared = future.result()
                        block, _ = self.block_manager.store_prepared_block(prepared)
                        batch_mappings.append((virtual_file.id, block.id, block_order))
                        block_order += 1
                        
                        self.progress_tracker.update(
                            prepared["original_size"], 
                            f"Encrypting: {file_path.name}"
                        )
                    
                    # Commit this batch immediately for breakpoint support
                    FileBlockMapping.create_batch(batch_mappings, self.repository.path)
        
        return virtual_file
    
    def import_folder(
        self,
        folder_path: Path,
        parent_id: Optional[int] = None
    ) -> VirtualFile:
        """
        Import a folder recursively.
        
        Args:
            folder_path: Path to folder to import
            parent_id: Parent directory ID (None for root)
        
        Returns:
            Created VirtualFile object for the folder
        """
        # Use pre-calculated total, or calculate if starting with a single folder
        if self.progress_tracker.total_bytes == 0:
            self.progress_tracker.set_total(self._calculate_folder_size(folder_path))
            self.progress_tracker.processed_bytes = 0
        
        return self._import_folder_recursive(folder_path, parent_id)
    
    def _import_folder_recursive(
        self,
        folder_path: Path,
        parent_id: Optional[int]
    ) -> VirtualFile:
        """Recursively import folder contents."""
        # Check for existing names and generate unique name
        from src.utils.file_utils import get_unique_filename
        
        existing_files = VirtualFile.get_children(self.repository.path, parent_id)
        existing_names = set()
        for vf in existing_files:
            try:
                name = decrypt_metadata(
                    vf.name_encrypted,
                    self.master_key,
                    vf.name_nonce
                )
                existing_names.add(name)
            except Exception:
                continue
                
        # RESUMPTION LOGIC: Check if this folder was already partially imported
        virtual_dir = None
        if self.operation:
            for vf in existing_files:
                try:
                    name = decrypt_metadata(vf.name_encrypted, self.master_key, vf.name_nonce)
                    if name == folder_path.name and vf.is_directory:
                        virtual_dir = vf
                        self.logger.info(f"Found existing virtual folder for {name}, merging...")
                        break
                except Exception:
                    continue
        
        if virtual_dir is None:
            final_name = get_unique_filename(folder_path.name, existing_names)
            
            # Encrypt folder name
            name_encrypted, name_nonce = encrypt_metadata(
                final_name, self.master_key
            )
            
            # Create virtual directory entry
            virtual_dir = VirtualFile.create(
                repo_path=self.repository.path,
                parent_id=parent_id,
                name_encrypted=name_encrypted,
                name_nonce=name_nonce,
                is_directory=True,
                size=0
            )
        
        # Track created directory for rollback
        if virtual_dir.id not in self._created_file_ids:
            self._created_file_ids.append(virtual_dir.id)
        
        # Import contents
        for item in folder_path.iterdir():
            if self.is_cancelled():
                raise OperationCancelled("Import cancelled by user")
                
            if item.is_file():
                self.import_file(item, virtual_dir.id)
            elif item.is_dir():
                self._import_folder_recursive(item, virtual_dir.id)
        
        return virtual_dir
    
    def _calculate_folder_size(self, folder_path: Path) -> int:
        """Calculate total size of folder contents."""
        total = 0
        try:
            for item in folder_path.rglob("*"):
                if item.is_file():
                    total += get_file_size(item)
        except Exception:
            pass
        return total

    @staticmethod
    def calculate_total_import_size(file_paths: list[Path], progress_callback: Optional[Callable] = None) -> int:
        """Calculate total size for a list of paths with throttled feedback."""
        total = 0
        state = {'last_update': 0}
        for i, path in enumerate(file_paths):
            total += fast_scandir(path, progress_callback, state)
            
            # Ensure at least one update for each top-level item if it's long
            if progress_callback:
                progress_callback(0, 0, f"{_('status_calculating')}: {path.name} ({i+1}/{len(file_paths)})", "", "")
        return total
    
    
    
    def get_created_file_ids(self) -> list[int]:
        """Get list of created file IDs for external tracking."""
        return self._created_file_ids.copy()


class FileExporter:
    """Handles file and folder export with decryption."""
    
    def __init__(
        self,
        repository: Repository,
        master_key: bytes,
        progress_callback: Optional[Callable[[int, int, str, str, str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
        operation: Optional["Operation"] = None
    ):
        """
        Initialize file exporter.
        
        Args:
            repository: Source repository
            master_key: Master encryption key
            progress_callback: Callback for progress updates
            is_cancelled: Optional callback to check for cancellation
            operation: Existing operation to resume
        """
        self.repository = repository
        self.master_key = master_key
        self.operation = operation
        self.block_manager = BlockManager(repository.path, master_key)
        self.is_cancelled = is_cancelled or (lambda: False)
        self.logger = get_logger()
        
        # Unified throttled callback for both UI and DB
        def unified_callback(current, total, msg, speed, eta):
            if progress_callback:
                progress_callback(current, total, msg, speed, eta)
            if self.operation:
                self.operation.update_progress(self.repository.path, current)
                
        self.progress_tracker = ProgressTracker(unified_callback)
        self._output_dir: Optional[Path] = None  # Track final output
        self._missing_blocks: list[str] = []
        
    def set_progress_params(self, processed: int, total: int):
        """Manually set progress tracking params for multi-file operations."""
        self.progress_tracker.processed_bytes = processed
        self.progress_tracker.set_total(total)
        # Force an immediate callback to ensure UI receives correct total_bytes
        self.progress_tracker.update(0, "Starting...", force=True)
    
    def export_decrypted(
        self,
        virtual_file: VirtualFile,
        output_dir: Path,
        total_work: Optional[int] = None,
        reset_progress: bool = False
    ) -> Tuple[bool, list[str]]:
        """
        Export file or folder decrypted.
        """
        self._missing_blocks = []
        
        # Initialize progress if requested or if not already set
        if reset_progress or total_work is not None or self.progress_tracker.total_bytes == 0:
            if total_work is not None:
                self.progress_tracker.set_total(total_work)
            elif self.progress_tracker.total_bytes == 0:
                self.progress_tracker.set_total(self._calculate_total_size(virtual_file))
            
            if reset_progress:
                self.progress_tracker.processed_bytes = 0
        
        # Ensure total is at least 1 to avoid division by zero
        if self.progress_tracker.total_bytes <= 0:
            self.progress_tracker.set_total(1)
        
        # Store final output dir
        self._output_dir = output_dir
        
        # Check target disk space
        if not check_target_capacity(output_dir, self.progress_tracker.total_bytes):
            from src.utils.format import format_size
            error_msg = _("error_disk_full", size=format_size(self.progress_tracker.total_bytes))
            self.logger.error(error_msg)
            raise FileOperationError(error_msg)

        # Decrypt name
        name = decrypt_metadata(
            virtual_file.name_encrypted,
            self.master_key,
            virtual_file.name_nonce
        )
        
        if virtual_file.is_directory:
            self._export_folder_recursive(virtual_file, output_dir, name)
        else:
            self._export_file(virtual_file, output_dir, name)
        
        success = len(self._missing_blocks) == 0
        if success:
            self.logger.debug(f"Successfully exported: {name} to {output_dir}")
        else:
            self.logger.warning(f"Export finished with missing blocks for: {name}")
            
        return success, self._missing_blocks
    



    
    def _export_file(
        self,
        virtual_file: VirtualFile,
        output_dir: Path,
        name: str
    ) -> None:
        """Export a single file."""
        output_path = output_dir / name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        blocks = FileBlockMapping.get_blocks_for_file(
            virtual_file.id, self.repository.path
        )
        
        # RESUMPTION LOGIC: Check if file already exists and its size
        start_block_index = 0
        file_mode = "wb"
        if output_path.exists():
            existing_size = output_path.stat().st_size
            # Calculate how many full blocks we can skip
            # (Be conservative: if size is not a multiple of BLOCK_SIZE, 
            # we resume from the last full block)
            start_block_index = existing_size // BLOCK_SIZE
            if start_block_index > 0:
                self.logger.info(f"Resuming export of {name} from block {start_block_index}")
                file_mode = "ab" # Append mode
                # Seed progress tracker
                already_done = start_block_index * BLOCK_SIZE
                self.progress_tracker.update(already_done, f"Resuming: {name}")
                if start_block_index >= len(blocks):
                    # File might be already done
                    return

        # Trigger initial progress update so UI shows activity immediately
        self.progress_tracker.update(0, f"Decrypting: {name}", force=True)
        
        # Parallel block retrieval and decryption in batches
        BATCH_SIZE = 16
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Skip already exported blocks
            relevant_blocks = blocks[start_block_index:]
            
            with open(output_path, file_mode) as f:
                for i in range(0, len(relevant_blocks), BATCH_SIZE):
                    if self.is_cancelled():
                        raise OperationCancelled("Export cancelled by user")
                    
                    batch = relevant_blocks[i:i + BATCH_SIZE]
                    futures = []
                    
                    for block in batch:
                        if not self.block_manager.block_exists(block):
                            self._missing_blocks.append(f"{name}: Block {block.relative_path}")
                            futures.append(None)
                            continue
                        
                        future = executor.submit(self.block_manager.retrieve_block_data, block)
                        futures.append(future)
                    
                    for future in futures:
                        if future is None:
                            continue
                        
                        try:
                            # Still check cancellation per result for extreme responsiveness
                            if self.is_cancelled():
                                raise OperationCancelled("Export cancelled by user")
                                
                            data = future.result()
                            f.write(data)
                            
                            self.progress_tracker.update(len(data), f"Decrypting: {name}")
                        except OperationCancelled:
                            raise
                        except Exception as e:
                            self._missing_blocks.append(f"{name}: {str(e)}")
    
    def _export_folder_recursive(
        self,
        virtual_dir: VirtualFile,
        output_dir: Path,
        name: str
    ) -> None:
        """Recursively export folder contents."""
        folder_path = output_dir / name
        folder_path.mkdir(parents=True, exist_ok=True)
        
        # Get children
        children = VirtualFile.get_children(
            self.repository.path,
            virtual_dir.id
        )
        
        for child in children:
            if self.is_cancelled():
                raise OperationCancelled("Export cancelled by user")
                
            child_name = decrypt_metadata(
                child.name_encrypted,
                self.master_key,
                child.name_nonce
            )
            
            if child.is_directory:
                self._export_folder_recursive(child, folder_path, child_name)
            else:
                self._export_file(child, folder_path, child_name)
    
    def _calculate_total_size(self, virtual_file: VirtualFile) -> int:
        """Calculate total size for progress tracking."""
        if not virtual_file.is_directory:
            return virtual_file.size
        
        total = 0
        children = VirtualFile.get_children(
            self.repository.path,
            virtual_file.id
        )
        for child in children:
            total += self._calculate_total_size(child)
        return total

    @staticmethod
    def calculate_total_export_size(files: list[VirtualFile], repository_path: str, progress_callback: Optional[Callable] = None) -> int:
        """Calculate total size for a list of virtual files with throttled feedback."""
        total = 0
        state = {'last_update': 0}
        for i, vf in enumerate(files):
            total += FileExporter._calculate_recursive_size(vf, repository_path, progress_callback, state)
            
            if progress_callback:
                # Force update for major items
                progress_callback(0, 0, f"{_('status_calculating')} ({i+1}/{len(files)})", "", "")
        return total

    @staticmethod
    def _calculate_recursive_size(vf: VirtualFile, repository_path: str, callback: Optional[Callable] = None, state: dict = None) -> int:
        """Helper to calculate size recursively with throttling."""
        if not vf.is_directory:
            return vf.size
        
        # Throttling
        if callback and state:
            now = time.time()
            if now - state.get('last_update', 0) >= 0.2:
                callback(0, 0, f"{_('status_calculating')}")
                state['last_update'] = now

        total = 0
        children = VirtualFile.get_children(repository_path, vf.id)
        for child in children:
            total += FileExporter._calculate_recursive_size(child, repository_path, callback, state)
        return total



def check_blocks_exist(virtual_file: VirtualFile, repository: Repository) -> list[str]:
    """
    Check if all blocks for a file exist.
    
    Args:
        virtual_file: File to check
        repository: Repository
    
    Returns:
        List of missing block paths
    """
    block_manager = BlockManager(repository.path, b"")  # Key not needed for existence check
    missing = []
    
    if virtual_file.is_directory:
        children = VirtualFile.get_children(
            repository.path,
            virtual_file.id
        )
        for child in children:
            missing.extend(check_blocks_exist(child, repository))
    else:
        blocks = FileBlockMapping.get_blocks_for_file(virtual_file.id, repository.path)
        for block in blocks:
            if not block_manager.block_exists(block):
                missing.append(block.relative_path)
    
    return missing





class BatchFileDeleter:
    """Handles efficient deletion of large file trees."""
    
    def __init__(
        self, 
        repository: Repository, 
        master_key: bytes,
        progress_callback: Optional[Callable[[int, int, str, str, str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
        operation: Optional["Operation"] = None
    ):
        self.repository = repository
        self.master_key = master_key
        self.block_manager = BlockManager(repository.path, master_key)
        self.operation = operation
        self.is_cancelled = is_cancelled or (lambda: False)
        self.logger = get_logger()
        self._processed_count = 0
        self._total_count = 0
        
        # Unified callback that also updates DB
        def unified_callback(current, total, msg, speed, eta):
            if progress_callback:
                progress_callback(current, total, msg, speed, eta)
            if self.operation:
                # For deletion, processed_size is current percentage if total=100
                self.operation.update_progress(self.repository.path, current)
                
        self.progress_tracker = ProgressTracker(unified_callback)
        
    def delete(self, virtual_files: list[VirtualFile]) -> None:
        """Optimized deletion of multiple virtual files/folders."""
        all_ids = []
        file_ids = []
        
        # 1. Collect all items recursively
        self.progress_tracker.set_total(0)
        self.progress_tracker.update(0, "Scanning items...")
            
        for vf in virtual_files:
            if self.is_cancelled():
                raise OperationCancelled("Deletion cancelled")
                
            items = self._collect_items(vf)
            all_ids.extend([item.id for item in items])
            file_ids.extend([item.id for item in items if not item.is_directory])
            
            # Progress update during collection if many items
            if len(all_ids) % 100 == 0:
                self.progress_tracker.update(0, f"Scanning: {len(all_ids)} items found")
            
        self._total_count = len(all_ids)
        if self._total_count == 0:
            return
            
        # Weighted progress distribution:
        # 40% Metadata updates
        # 50% Physical unlinking
        # 10% Database records removal
        
        # 2. Process deletions in batches (Metadata Phase - 40%)
        BATCH_SIZE = 500
        combined_blocks_to_delete = []
        
        # We delete block mappings and decrement references for files
        for i in range(0, len(file_ids), BATCH_SIZE):
            if self.is_cancelled():
                raise OperationCancelled("Deletion cancelled")
                
            batch_ids = file_ids[i:i+BATCH_SIZE]
            
            # Remove mappings and collect block IDs
            all_block_ids = []
            for fid in batch_ids:
                bids = FileBlockMapping.remove_mappings_for_file(fid, self.repository.path)
                all_block_ids.extend(bids)
                
            # Decrement references in batch
            if all_block_ids:
                blocks = Block.decrement_batch(all_block_ids, self.repository.path)
                combined_blocks_to_delete.extend(blocks)
                
            # Update progress for Metadata Phase (0% to 40%)
            self._processed_count += len(batch_ids)
            # Progress is 0.4 * (processed_count / total_count)
            progress_val = int(0.4 * (self._processed_count / self._total_count) * 100)
            self.progress_tracker.update(0, f"Updating metadata: {self._processed_count}/{self._total_count}")
            # Note: ProgressTracker.update is designed for byte-based progress.
            # Here we manually trigger the callback for percentage-based progress.
            if self.progress_tracker.callback:
                self.progress_tracker.callback(progress_val, 100, self.progress_tracker.message, "", "")

        # 3. Unlink physical blocks in parallel
        if combined_blocks_to_delete:
            if self.progress_tracker.callback:
                self.progress_tracker.callback(40, 100, "Cleaning storage...", "", "")
                
            total_blocks = len(combined_blocks_to_delete)
            processed_blocks = 0
            
            with ThreadPoolExecutor(max_workers=8) as executor:
                # Submit all and track completion for progress
                futures = [executor.submit(self.block_manager.delete_block_file, b) for b in combined_blocks_to_delete]
                
                for future in as_completed(futures):
                    processed_blocks += 1
                    if processed_blocks % 10 == 0 or processed_blocks == total_blocks:
                        # Storage Phase (40% to 90%)
                        progress_val = 40 + int(0.5 * (processed_blocks / total_blocks) * 100)
                        self.progress_tracker.update(0, f"Cleaning storage: {processed_blocks}/{total_blocks} blocks")
                        if self.progress_tracker.callback:
                            self.progress_tracker.callback(progress_val, 100, self.progress_tracker.message, "", "")
        else:
            # Skip storage phase if no blocks
            self.progress_tracker.update(0, "Finalizing...")
            if self.progress_tracker.callback:
                self.progress_tracker.callback(90, 100, "Finalizing...", "", "")
                    
        db = get_repository_database(self.repository.path)
        with db.transaction():
            total_ids_to_del = len(all_ids)
            for i in range(0, total_ids_to_del, BATCH_SIZE):
                batch_ids = all_ids[i:i+BATCH_SIZE]
                placeholders = ",".join(["?"] * len(batch_ids))
                db.execute(f"DELETE FROM files WHERE id IN ({placeholders})", tuple(batch_ids))
                
                # Final Database Phase (90% to 100%)
                progress_val = 90 + int(0.1 * ((i + len(batch_ids)) / total_ids_to_del) * 100)
                self.progress_tracker.update(0, "Finalizing database...")
                if self.progress_tracker.callback:
                    self.progress_tracker.callback(progress_val, 100, "Finalizing database...", "", "")
                
        self.progress_tracker.update(0, "Deletion complete", force=True)
        if self.progress_tracker.callback:
            self.progress_tracker.callback(100, 100, "Deletion complete", "", "")

    def _collect_items(self, vf: VirtualFile) -> list[VirtualFile]:
        """Recursively collect all items in a tree."""
        items = [vf]
        if vf.is_directory:
            children = VirtualFile.get_children(self.repository.path, vf.id)
            for child in children:
                items.extend(self._collect_items(child))
        return items


