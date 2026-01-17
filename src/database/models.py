"""
Secure Vault - Database Models
Data access objects for database operations with per-repository support.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
import json

from src.database.database import get_global_database, get_repository_database


@dataclass
class Repository:
    """Repository data model (stored in global database)."""
    id: Optional[int]
    name: str
    path: str
    max_capacity: int
    created_at: Optional[datetime] = None
    
    @classmethod
    def create(cls, name: str, path: str, max_capacity: int) -> "Repository":
        """Create a new repository."""
        db = get_global_database()
        cursor = db.execute(
            "INSERT INTO repositories (name, path, max_capacity) VALUES (?, ?, ?)",
            (name, path, max_capacity)
        )
        db._connection.commit()
        repo_id = cursor.lastrowid
        
        return cls(id=repo_id, name=name, path=path, max_capacity=max_capacity)
    
    @classmethod
    def get_by_id(cls, repo_id: int) -> Optional["Repository"]:
        """Get repository by ID."""
        db = get_global_database()
        row = db.fetchone(
            "SELECT * FROM repositories WHERE id = ?",
            (repo_id,)
        )
        if row:
            return cls(
                id=row["id"],
                name=row["name"],
                path=row["path"],
                max_capacity=row["max_capacity"],
                created_at=row["created_at"]
            )
        return None
    
    @classmethod
    def get_by_path(cls, path: str) -> Optional["Repository"]:
        """Get repository by path."""
        db = get_global_database()
        row = db.fetchone(
            "SELECT * FROM repositories WHERE path = ?",
            (path,)
        )
        if row:
            return cls(
                id=row["id"],
                name=row["name"],
                path=row["path"],
                max_capacity=row["max_capacity"],
                created_at=row["created_at"]
            )
        return None
    
    @classmethod
    def get_all(cls) -> List["Repository"]:
        """Get all repositories."""
        db = get_global_database()
        rows = db.fetchall("SELECT * FROM repositories ORDER BY name")
        return [
            cls(
                id=row["id"],
                name=row["name"],
                path=row["path"],
                max_capacity=row["max_capacity"],
                created_at=row["created_at"]
            )
            for row in rows
        ]
    
    def delete(self) -> None:
        """Delete this repository from global database."""
        if self.id is None:
            return
        db = get_global_database()
        db.execute("DELETE FROM repositories WHERE id = ?", (self.id,))
        db._connection.commit()
    
    def get_used_capacity(self) -> int:
        """Calculate the used capacity of this repository."""
        repo_db = get_repository_database(self.path)
        if repo_db is None:
            return 0
        row = repo_db.fetchone(
            "SELECT COALESCE(SUM(size), 0) as total_size FROM blocks"
        )
        return row["total_size"] if row else 0

    def cleanup_orphaned_blocks(self) -> int:
        """
        Cleanup blocks that have no associated file mapping.
        These 'ghost' blocks can occur if an import is cancelled strictly at the DB level
        but not fully rolled back.
        
        Returns:
            Bytes freed
        """
        db = get_repository_database(self.path)
        if db is None:
            return 0
            
        freed_bytes = 0
        with db.transaction():
            # Find orphans: blocks not in file_blocks
            rows = db.fetchall(
                """
                SELECT id, relative_path, size FROM blocks 
                WHERE id NOT IN (SELECT DISTINCT block_id FROM file_blocks)
                """
            )
            
            if not rows:
                return 0
                
            block_ids = [row["id"] for row in rows]
            
            # Delete files
            blocks_dir = db.blocks_path
            for row in rows:
                try:
                    full_path = blocks_dir / row["relative_path"]
                    if full_path.exists():
                        full_path.unlink()
                    freed_bytes += row["size"]
                except Exception:
                    pass
            
            # Delete DB entries
            placeholders = ",".join(["?"] * len(block_ids))
            db.execute(
                f"DELETE FROM blocks WHERE id IN ({placeholders})",
                tuple(block_ids)
            )
            
        return freed_bytes


@dataclass
class VirtualFile:
    """Virtual file/directory data model (stored in repository database)."""
    id: Optional[int]
    parent_id: Optional[int]
    name_encrypted: bytes
    name_nonce: bytes
    is_directory: bool
    size: int
    comment_encrypted: Optional[bytes]
    comment_nonce: Optional[bytes]
    upload_date: Optional[datetime] = None
    
    # Decrypted fields (populated after decryption)
    name: Optional[str] = None
    comment: Optional[str] = None
    
    # For compatibility - will be set from repo context
    repository_id: Optional[int] = None
    
    @classmethod
    def create(
        cls,
        repo_path: str,
        parent_id: Optional[int],
        name_encrypted: bytes,
        name_nonce: bytes,
        is_directory: bool,
        size: int = 0,
        comment_encrypted: Optional[bytes] = None,
        comment_nonce: Optional[bytes] = None
    ) -> "VirtualFile":
        """Create a new virtual file entry."""
        db = get_repository_database(repo_path)
        with db.transaction():
            cursor = db.execute(
                """
                INSERT INTO files 
                (parent_id, name_encrypted, name_nonce, 
                 is_directory, size, comment_encrypted, comment_nonce)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (parent_id, name_encrypted, name_nonce,
                 1 if is_directory else 0, size, comment_encrypted, comment_nonce)
            )
            file_id = cursor.lastrowid
        
        return cls(
            id=file_id,
            parent_id=parent_id,
            name_encrypted=name_encrypted,
            name_nonce=name_nonce,
            is_directory=is_directory,
            size=size,
            comment_encrypted=comment_encrypted,
            comment_nonce=comment_nonce
        )
    
    @classmethod
    def get_by_id(cls, file_id: int, repo_path: str = None) -> Optional["VirtualFile"]:
        """Get virtual file by ID."""
        db = get_repository_database(repo_path)
        if db is None:
            return None
        row = db.fetchone("SELECT * FROM files WHERE id = ?", (file_id,))
        if row:
            return cls._from_row(row)
        return None
    
    @classmethod
    def get_batch(cls, file_ids: list[int], repo_path: str = None) -> List["VirtualFile"]:
        """Get multiple virtual files by ID in a single query."""
        if not file_ids:
            return []
        db = get_repository_database(repo_path)
        if db is None:
            return []
        
        results = []
        CHUNK_SIZE = 900
        for i in range(0, len(file_ids), CHUNK_SIZE):
            chunk = file_ids[i:i + CHUNK_SIZE]
            placeholders = ",".join(["?"] * len(chunk))
            rows = db.fetchall(f"SELECT * FROM files WHERE id IN ({placeholders})", tuple(chunk))
            results.extend([cls._from_row(row) for row in rows])
        return results

    @classmethod
    def get_children(cls, repo_path: str, parent_id: Optional[int]) -> List["VirtualFile"]:
        """Get children of a directory."""
        db = get_repository_database(repo_path)
        if db is None:
            return []
        if parent_id is None:
            rows = db.fetchall(
                "SELECT * FROM files WHERE parent_id IS NULL"
            )
        else:
            rows = db.fetchall(
                "SELECT * FROM files WHERE parent_id = ?",
                (parent_id,)
            )
        return [cls._from_row(row) for row in rows]
    
    @classmethod
    def count_children(cls, repo_path: str, parent_id: Optional[int]) -> int:
        """Count children of a directory (efficient - no data loading)."""
        db = get_repository_database(repo_path)
        if db is None:
            return 0
        if parent_id is None:
            result = db.fetchone(
                "SELECT COUNT(*) FROM files WHERE parent_id IS NULL"
            )
        else:
            result = db.fetchone(
                "SELECT COUNT(*) FROM files WHERE parent_id = ?",
                (parent_id,)
            )
        return result[0] if result else 0
    
    @classmethod
    def get_all_in_repository(cls, repo_path: str) -> List["VirtualFile"]:
        """Get all files in a repository."""
        db = get_repository_database(repo_path)
        if db is None:
            return []
        rows = db.fetchall("SELECT * FROM files")
        return [cls._from_row(row) for row in rows]
    
    @classmethod
    def _from_row(cls, row) -> "VirtualFile":
        """Create VirtualFile from database row."""
        return cls(
            id=row["id"],
            parent_id=row["parent_id"],
            name_encrypted=row["name_encrypted"],
            name_nonce=row["name_nonce"],
            is_directory=bool(row["is_directory"]),
            size=row["size"],
            comment_encrypted=row["comment_encrypted"],
            comment_nonce=row["comment_nonce"],
            upload_date=row["upload_date"]
        )
    
    def update_name(self, name_encrypted: bytes, name_nonce: bytes, repo_path: str = None) -> None:
        """Update encrypted name."""
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            db.execute(
                "UPDATE files SET name_encrypted = ?, name_nonce = ? WHERE id = ?",
                (name_encrypted, name_nonce, self.id)
            )
        self.name_encrypted = name_encrypted
        self.name_nonce = name_nonce
    
    def update_comment(
        self,
        comment_encrypted: Optional[bytes],
        comment_nonce: Optional[bytes],
        repo_path: str = None
    ) -> None:
        """Update encrypted comment."""
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            db.execute(
                "UPDATE files SET comment_encrypted = ?, comment_nonce = ? WHERE id = ?",
                (comment_encrypted, comment_nonce, self.id)
            )
        self.comment_encrypted = comment_encrypted
        self.comment_nonce = comment_nonce
    
    def delete(self, repo_path: str = None) -> None:
        """Delete this file/directory and its children."""
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            # CASCADE will handle children and file_blocks
            db.execute("DELETE FROM files WHERE id = ?", (self.id,))

    @classmethod
    def delete_batch(cls, file_ids: list[int], repo_path: str = None) -> None:
        """Delete multiple virtual files efficiently."""
        if not file_ids:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            CHUNK_SIZE = 900
            for i in range(0, len(file_ids), CHUNK_SIZE):
                chunk = file_ids[i:i + CHUNK_SIZE]
                placeholders = ",".join(["?"] * len(chunk))
                db.execute(f"DELETE FROM files WHERE id IN ({placeholders})", chunk)
    
    def move(self, new_parent_id: Optional[int], repo_path: str = None) -> None:
        """Move file to a new parent directory."""
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            db.execute(
                "UPDATE files SET parent_id = ? WHERE id = ?",
                (new_parent_id, self.id)
            )
        self.parent_id = new_parent_id

    @classmethod
    def move_batch(cls, file_ids: list[int], new_parent_id: Optional[int], repo_path: str = None) -> None:
        """Move multiple files to a new parent directory in a single transaction."""
        if not file_ids:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            CHUNK_SIZE = 900
            for i in range(0, len(file_ids), CHUNK_SIZE):
                chunk = file_ids[i:i + CHUNK_SIZE]
                placeholders = ",".join(["?"] * len(chunk))
                db.execute(
                    f"UPDATE files SET parent_id = ? WHERE id IN ({placeholders})",
                    [new_parent_id] + chunk
                )


@dataclass
class Block:
    """Block storage data model (stored in repository database)."""
    id: Optional[int]
    hash: str
    relative_path: str
    size: int
    salt: bytes
    nonce: bytes
    reference_count: int = 1
    
    @classmethod
    def get_by_hash(cls, block_hash: str, repo_path: str = None) -> Optional["Block"]:
        """Get block by hash (for deduplication)."""
        db = get_repository_database(repo_path)
        if db is None:
            return None
        row = db.fetchone("SELECT * FROM blocks WHERE hash = ?", (block_hash,))
        if row:
            return cls._from_row(row)
        return None
    
    @classmethod
    def create(
        cls,
        block_hash: str,
        relative_path: str,
        size: int,
        salt: bytes,
        nonce: bytes,
        repo_path: str = None
    ) -> "Block":
        """Create a new block entry."""
        db = get_repository_database(repo_path)
        if db is None:
            raise RuntimeError("Database not available")
            
        with db.transaction():
            cursor = db.execute(
                """
                INSERT INTO blocks (hash, relative_path, size, salt, nonce, reference_count)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (block_hash, relative_path, size, salt, nonce)
            )
            block_id = cursor.lastrowid
        
        return cls(
            id=block_id,
            hash=block_hash,
            relative_path=relative_path,
            size=size,
            salt=salt,
            nonce=nonce,
            reference_count=1
        )
    
    @classmethod
    def _from_row(cls, row) -> "Block":
        """Create Block from database row."""
        return cls(
            id=row["id"],
            hash=row["hash"],
            relative_path=row["relative_path"],
            size=row["size"],
            salt=row["salt"],
            nonce=row["nonce"],
            reference_count=row["reference_count"]
        )
    
    def increment_reference(self, repo_path: str = None) -> None:
        """Increment reference count (for deduplication)."""
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            db.execute(
                "UPDATE blocks SET reference_count = reference_count + 1 WHERE id = ?",
                (self.id,)
            )
        self.reference_count += 1
    
    def decrement_reference(self, repo_path: str = None) -> bool:
        """
        Decrement reference count.
        
        Returns:
            True if block should be deleted (reference_count == 0)
        """
        if self.id is None:
            return False
        db = get_repository_database(repo_path)
        if db is None:
            return False
        with db.transaction():
            db.execute(
                "UPDATE blocks SET reference_count = reference_count - 1 WHERE id = ?",
                (self.id,)
            )
        # We need to reload the block to get accurate reference count if needed,
        # but usually we just care if it's <= 0.
        # This instance might be stale, so fetch if needed.
        row = db.fetchone("SELECT reference_count FROM blocks WHERE id = ?", (self.id,))
        if row:
            self.reference_count = row["reference_count"]
        return self.reference_count <= 0

    @classmethod
    def decrement_batch(cls, block_ids: List[int], repo_path: str = None) -> List["Block"]:
        """
        Decrement reference counts for multiple blocks in a single transaction.
        
        Returns:
            List of Block objects that reached zero references and should be deleted from disk.
        """
        if not block_ids:
            return []
            
        db = get_repository_database(repo_path)
        if db is None:
            return []
            
        blocks_to_delete = []
        with db.transaction():
            # Decrement all
            for block_id in block_ids:
                db.execute(
                    "UPDATE blocks SET reference_count = reference_count - 1 WHERE id = ?",
                    (block_id,)
                )
            
            # Find those that reach zero
            # SQLite specific: using IN with placeholder for batch
            placeholders = ",".join(["?"] * len(block_ids))
            rows = db.fetchall(
                f"SELECT * FROM blocks WHERE id IN ({placeholders}) AND reference_count <= 0",
                tuple(block_ids)
            )
            
            for row in rows:
                blocks_to_delete.append(cls._from_row(row))
            
            # Remove from database those that reach zero
            if blocks_to_delete:
                db.execute(
                    f"DELETE FROM blocks WHERE id IN ({placeholders}) AND reference_count <= 0",
                    tuple(block_ids)
                )
                
        return blocks_to_delete
    
    def delete(self, repo_path: str = None) -> None:
        """Delete this block."""
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
        with db.transaction():
            db.execute("DELETE FROM blocks WHERE id = ?", (self.id,))


class FileBlockMapping:
    """File-to-block mapping operations."""
    
    @staticmethod
    def create_batch(mappings: list[tuple[int, int, int]], repo_path: str = None) -> None:
        """Add multiple file-to-block mappings in batch."""
        if not mappings:
            return
        db = get_repository_database(repo_path)
        if db is None:
            return
            
        with db.transaction():
            db.executemany(
                "INSERT INTO file_blocks (file_id, block_id, block_order) VALUES (?, ?, ?)",
                mappings
            )
    
    @staticmethod
    def get_blocks_for_file(file_id: int, repo_path: str = None) -> List[Block]:
        """Get all blocks for a file in order."""
        db = get_repository_database(repo_path)
        if db is None:
            return []
        rows = db.fetchall(
            """
            SELECT b.* FROM blocks b
            INNER JOIN file_blocks fb ON b.id = fb.block_id
            WHERE fb.file_id = ?
            ORDER BY fb.block_order
            """,
            (file_id,)
        )
        return [Block._from_row(row) for row in rows]
    
    @staticmethod
    def remove_mappings_for_file(file_id: int, repo_path: str = None) -> List[int]:
        """
        Remove all mappings for a file and return block IDs.
        
        Returns:
            List of block IDs that were mapped to this file
        """
        db = get_repository_database(repo_path)
        if db is None:
            return []
        rows = db.fetchall(
            "SELECT block_id FROM file_blocks WHERE file_id = ?",
            (file_id,)
        )
        block_ids = [row["block_id"] for row in rows]
        
        with db.transaction():
            db.execute("DELETE FROM file_blocks WHERE file_id = ?", (file_id,))
        
        return block_ids

    @staticmethod
    def remove_mappings_for_files_batch(file_ids: list[int], repo_path: str = None) -> List[int]:
        """Remove all block mappings for multiple files and return unique block IDs."""
        if not file_ids:
            return []
        db = get_repository_database(repo_path)
        if db is None:
            return []
            
        all_block_ids = set()
        with db.transaction():
            CHUNK_SIZE = 900
            for i in range(0, len(file_ids), CHUNK_SIZE):
                chunk = file_ids[i:i + CHUNK_SIZE]
                placeholders = ",".join(["?"] * len(chunk))
                
                rows = db.fetchall(f"SELECT block_id FROM file_blocks WHERE file_id IN ({placeholders})", tuple(chunk))
                for row in rows:
                    all_block_ids.add(row["block_id"])
                    
                db.execute(f"DELETE FROM file_blocks WHERE file_id IN ({placeholders})", tuple(chunk))
                
        return list(all_block_ids)


@dataclass
class Operation:
    """Operation data model for crash recovery."""
    id: Optional[int]
    type: str  # 'import', 'export', 'delete'
    status: str  # 'pending', 'processing', 'cancelling', 'completed', 'failed'
    source_paths: str  # JSON list
    target_path: Optional[str] = None
    parent_id: Optional[int] = None
    total_size: int = 0
    processed_size: int = 0
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def create(
        cls,
        repo_path: str,
        type: str,
        source_paths: List[str],
        target_path: Optional[str] = None,
        parent_id: Optional[int] = None,
        total_size: int = 0
    ) -> "Operation":
        db = get_repository_database(repo_path)
        with db.transaction():
            cursor = db.execute(
                """
                INSERT INTO operations 
                (type, status, source_paths, target_path, parent_id, total_size)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (type, 'processing', json.dumps(source_paths), str(target_path) if target_path else None, parent_id, total_size)
            )
            op_id = cursor.lastrowid
        
        return cls(
            id=op_id,
            type=type,
            status='processing',
            source_paths=json.dumps(source_paths),
            target_path=target_path,
            parent_id=parent_id,
            total_size=total_size
        )

    def update_status(self, repo_path: str, status: str, error: str = None) -> None:
        db = get_repository_database(repo_path)
        with db.transaction():
            db.execute(
                "UPDATE operations SET status = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, error, self.id)
            )
        self.status = status
        self.error_message = error

    def update_progress(self, repo_path: str, processed_size: int) -> None:
        db = get_repository_database(repo_path)
        # Avoid too many DB updates for progress
        db.execute(
            "UPDATE operations SET processed_size = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (processed_size, self.id)
        )
        self.processed_size = processed_size 

    @classmethod
    def get_pending(cls, repo_path: str) -> List["Operation"]:
        db = get_repository_database(repo_path)
        if db is None:
            return []
        rows = db.fetchall(
            "SELECT * FROM operations WHERE status IN ('processing', 'cancelling') ORDER BY created_at"
        )
        return [cls._from_row(row) for row in rows]

    @classmethod
    def _from_row(cls, row) -> "Operation":
        return cls(
            id=row["id"],
            type=row["type"],
            status=row["status"],
            source_paths=row["source_paths"],
            target_path=row["target_path"],
            parent_id=row["parent_id"],
            total_size=row["total_size"],
            processed_size=row["processed_size"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            updated_at=row["updated_at"]
        )

    def delete(self, repo_path: str) -> None:
        if self.id is None:
            return
        db = get_repository_database(repo_path)
        with db.transaction():
            db.execute("DELETE FROM operations WHERE id = ?", (self.id,))
