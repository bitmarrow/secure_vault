"""
Secure Vault - Repository Management
Handles repository creation, selection, and capacity management.
Each repository maintains its own database in .vault/ subdirectory.
"""

import os
import shutil
import json
import ctypes
import platform
from pathlib import Path
from typing import List, Optional, Tuple
from src.core.i18n import _

from src.database.models import Repository
from src.database.database import (
    get_repository_database, close_repository_database, 
    get_global_database, RepositoryDatabase
)
from src.core.config import get_config
from src.core.crypto import compute_key_hash


def get_disk_free_space(path: str) -> int:
    """
    Get free disk space for the given path.
    Uses platform-specific calls for better accuracy on Windows.
    """
    path_obj = Path(path)
    # Get the root or parent that actually exists
    check_path = path_obj
    while not check_path.exists() and check_path.parent != check_path:
        check_path = check_path.parent

    try:
        if platform.system() == "Windows":
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(str(check_path)), None, None, ctypes.pointer(free_bytes)
            )
            return free_bytes.value
        else:
            usage = shutil.disk_usage(check_path)
            return usage.free
    except Exception:
        return 0


def get_disk_total_space(path: str) -> int:
    """Get total disk space for the given path."""
    path_obj = Path(path)
    # Get the root or parent that actually exists
    check_path = path_obj
    while not check_path.exists() and check_path.parent != check_path:
        check_path = check_path.parent

    try:
        usage = shutil.disk_usage(check_path)
        return usage.total
    except (OSError, ValueError):
        return 0


def validate_repository_path(path: str) -> Tuple[bool, str]:
    """
    Validate a repository path.
    
    Args:
        path: Directory path to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    path_obj = Path(path)
    
    # Check if path exists or can be created
    if path_obj.exists():
        if not path_obj.is_dir():
            return False, "Path is not a directory"
    else:
        # Check if parent exists
        if not path_obj.parent.exists():
            return False, "Parent directory does not exist"
    
    # Check write permissions
    test_path = path_obj if path_obj.exists() else path_obj.parent
    if not os.access(test_path, os.W_OK):
        return False, "No write permission for this location"
    
    return True, ""


def validate_capacity(path: str, max_capacity: int) -> Tuple[bool, str]:
    """
    Validate repository capacity against disk space.
    
    Args:
        path: Repository path
        max_capacity: Maximum capacity in bytes
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    disk_total = get_disk_total_space(path if Path(path).exists() else str(Path(path).parent))
    
    if max_capacity > disk_total:
        return False, f"Capacity exceeds disk size"
    
    if max_capacity <= 0:
        return False, "Capacity must be greater than 0"
    
    return True, ""


def create_repository(name: str, path: str, max_capacity: int, master_key: bytes) -> Repository:
    """
    Create a new repository with its own database.
    
    Args:
        name: Repository name
        path: Repository path
        max_capacity: Maximum capacity in bytes
        master_key: The master key to associate with this repository
    
    Returns:
        Created Repository object
    
    Raises:
        ValueError: If validation fails
    """
    # Validate path
    is_valid, error = validate_repository_path(path)
    if not is_valid:
        raise ValueError(error)
    
    # Validate capacity
    is_valid, error = validate_capacity(path, max_capacity)
    if not is_valid:
        raise ValueError(error)
    
    # Create directory if it doesn't exist
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    
    # Initialize repository database and directory structure
    repo_db = RepositoryDatabase(path)
    repo_db.init_directory()
    repo_db.connect()
    repo_db.close()
    
    # Create repository in global database
    repo = Repository.create(name, path, max_capacity)
    
    # Generate config file with key hash
    key_hash = compute_key_hash(master_key)
    save_repository_config(repo, key_hash)
    
    return repo


def save_repository_config(repo: Repository, master_key_hash: str = None) -> None:
    """
    Save repository configuration to a JSON file in the .vault directory.
    
    Args:
        repo: Repository to save config for
    """
    config_path = Path(repo.path) / RepositoryDatabase.VAULT_DIR / "config.json"
    config_data = {
        "name": repo.name,
        "max_capacity": repo.max_capacity,
        "version": "1.0"
    }
    
    if master_key_hash:
        config_data["master_key_hash"] = master_key_hash
    
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2, ensure_ascii=False)


def load_repository_config(config_path: str) -> dict:
    """
    Load repository configuration from a JSON file.
    
    Args:
        config_path: Path to config.json file
    
    Returns:
        Config dictionary
    
    Raises:
        ValueError: If config is invalid
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    
    # Validate required fields (path is now derived from config.json location)
    required = ["name", "max_capacity", "master_key_hash"]
    for field in required:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")
    
    return config


def generate_unique_name(base_name: str) -> str:
    """
    Generate a unique repository name by adding (n) suffix if needed.
    
    Args:
        base_name: Original name
    
    Returns:
        Unique name
    """
    existing_repos = list_repositories()
    existing_names = {r.name.lower() for r in existing_repos}
    
    if base_name.lower() not in existing_names:
        return base_name
    
    counter = 1
    while True:
        new_name = f"{base_name}({counter})"
        if new_name.lower() not in existing_names:
            return new_name
        counter += 1


def import_repository(config_path: str, master_key: bytes) -> tuple:
    """
    Import a repository from its config file.
    
    The actual repository path is derived from the config.json location
    (parent of .vault directory), not from the path stored in config.
    This allows importing repositories that have been moved.
    
    Args:
        config_path: Path to config.json file
    
    Returns:
        Tuple of (Repository, was_renamed: bool, error_message: str or None)
    
    Raises:
        ValueError: If import fails
    """
    config = load_repository_config(config_path)
    
    # Derive actual repo path from config.json location
    # config.json is in .vault/, so parent of .vault is the repo path
    config_file = Path(config_path).resolve()
    vault_dir = config_file.parent  # .vault directory
    repo_path = str(vault_dir.parent)  # actual repository path
    
    # Verify master key hash - required for security
    if "master_key_hash" not in config:
        raise ValueError(_("error_no_key_hash"))
    
    current_hash = compute_key_hash(master_key)
    if config["master_key_hash"] != current_hash:
        raise ValueError(_("error_key_mismatch"))
    
    # Check if path already exists in our database
    existing_repos = list_repositories()
    normalized_path = str(Path(repo_path).resolve())
    
    for repo in existing_repos:
        if str(Path(repo.path).resolve()) == normalized_path:
            raise ValueError(_("error_path_exists"))
    
    # Check if the repository directory and database exist
    db_path = vault_dir / RepositoryDatabase.DB_NAME
    
    if not vault_dir.exists() or not db_path.exists():
        raise ValueError(_("error_repo_corrupt"))
    
    # Check name and rename if needed
    original_name = config["name"]
    final_name = generate_unique_name(original_name)
    was_renamed = final_name != original_name
    
    # Register in global database
    repo = Repository.create(final_name, repo_path, config["max_capacity"])
    
    # Update config with correct path and preserve key hash for security
    current_key_hash = compute_key_hash(master_key)
    save_repository_config(repo, current_key_hash)
    
    return repo, was_renamed, None


def rename_repository(repo_id: int, new_name: str) -> tuple:
    """
    Rename a repository.
    
    Args:
        repo_id: Repository ID
        new_name: New name
    
    Returns:
        Tuple of (success: bool, error_message: str or None)
    """
    new_name = new_name.strip()
    if not new_name:
        return False, _("error_name_empty")
    
    # Check for duplicate name
    existing_repos = list_repositories()
    for repo in existing_repos:
        if repo.id != repo_id and repo.name.lower() == new_name.lower():
            return False, _("error_name_used")
    
    # Get repository
    repo = Repository.get_by_id(repo_id)
    if repo is None:
        return False, _("error_repo_not_found")
    
    # Update in global database
    db = get_global_database()
    db.execute(
        "UPDATE repositories SET name = ? WHERE id = ?",
        (new_name, repo_id)
    )
    db._connection.commit()
    
    # Update config file
    repo.name = new_name
    save_repository_config(repo)
    
    return True, None


def list_repositories() -> List[Repository]:
    """
    Get all repositories.
    
    Returns:
        List of Repository objects
    """
    return Repository.get_all()


def get_repository(repo_id: int) -> Optional[Repository]:
    """
    Get repository by ID.
    
    Args:
        repo_id: Repository ID
    
    Returns:
        Repository object or None
    """
    return Repository.get_by_id(repo_id)


def delete_repository(repo_id: int, delete_files: bool = True) -> None:
    """
    Delete a repository and optionally all its data.
    
    With per-repository databases, deletion is simple:
    just delete the entire .vault directory.
    
    Args:
        repo_id: Repository ID
        delete_files: If True, delete the .vault directory with all data
    """
    repo = Repository.get_by_id(repo_id)
    if repo is None:
        return
    
    # Close any open connection to this repo's database
    close_repository_database()
    
    if delete_files:
        # Delete the entire .vault directory (contains db and blocks)
        vault_dir = Path(repo.path) / RepositoryDatabase.VAULT_DIR
        if vault_dir.exists():
            shutil.rmtree(vault_dir)
    
    # Delete from global database
    repo.delete()
    
    # Clear active repository if it was this one
    config = get_config()
    if config.active_repository_id == repo_id:
        config.active_repository_id = None


def get_active_repository() -> Optional[Repository]:
    """
    Get the currently active repository.
    Verifies that the repository still exists in database and on disk.
    
    Returns:
        Active Repository object or None
    """
    config = get_config()
    if config.active_repository_id is not None:
        repo = Repository.get_by_id(config.active_repository_id)
        if repo:
            # Verify physical path
            vault_dir = Path(repo.path) / RepositoryDatabase.VAULT_DIR
            if vault_dir.exists():
                return repo
                
    return None


def set_active_repository(repo_id: int) -> None:
    """
    Set the active repository and switch database connection.
    
    Args:
        repo_id: Repository ID to activate
    """
    repo = Repository.get_by_id(repo_id)
    if repo is None:
        return
    
    # Switch to repository's database
    get_repository_database(repo.path)
    
    # Update config
    config = get_config()
    config.active_repository_id = repo_id


def can_store_file(repo: Repository, file_size: int) -> bool:
    """
    Check if a file can be stored in the repository.
    
    Args:
        repo: Repository to check
        file_size: Size of file to store
    
    Returns:
        True if file can be stored
    """
    used_capacity = repo.get_used_capacity()
    remaining_capacity = repo.max_capacity - used_capacity
    
    # Also check actual disk space
    disk_free = get_disk_free_space(repo.path)
    
    # Use minimum of remaining capacity and disk free space
    available = min(remaining_capacity, disk_free)
    
    return file_size <= available


def get_repository_stats(repo: Repository) -> dict:
    """
    Get repository statistics.
    
    Args:
        repo: Repository to get stats for
    
    Returns:
        Dictionary with used, max, available, and disk_free
    """
    used = repo.get_used_capacity()
    disk_free = get_disk_free_space(repo.path)
    
    return {
        "used": used,
        "max_capacity": repo.max_capacity,
        "available": repo.max_capacity - used,
        "disk_free": disk_free
    }

