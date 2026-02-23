#!/usr/bin/env python3
"""
Cloud file storage manager for BlackRoad OS.
Nextcloud-inspired with local SQLite backend.
"""

import os
import sqlite3
import json
import hashlib
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

DB_PATH = Path.home() / ".blackroad" / "files.db"
STORAGE_PATH = Path.home() / ".blackroad" / "storage" / "files"


@dataclass
class File:
    """Represents a file."""
    id: str
    path: str
    name: str
    size_bytes: int
    mime_type: str
    owner: str
    shared: bool
    public_link: Optional[str]
    version: int
    etag: str
    created_at: str
    modified_at: str
    tags: List[str]
    is_favorite: bool
    encrypted: bool

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['tags'] = self.tags
        return d


@dataclass
class Share:
    """Represents a file share."""
    id: str
    file_id: str
    share_type: str  # user/group/public/email
    share_with: str
    permissions: List[str]  # read/write/delete/share
    token: str
    password_hash: Optional[str]
    expiry_date: Optional[str]
    download_count: int
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['permissions'] = self.permissions
        return d


@dataclass
class Activity:
    """Represents an activity/audit log."""
    id: str
    user: str
    file_id: str
    action: str  # created/modified/deleted/shared/downloaded
    timestamp: str
    ip: str
    user_agent: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FileManager:
    """Cloud file storage manager."""

    def __init__(self):
        self._init_db()
        self._storage_path = STORAGE_PATH
        self._storage_path.mkdir(parents=True, exist_ok=True)

    def _init_db(self):
        """Initialize SQLite database."""
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                size_bytes INTEGER,
                mime_type TEXT,
                owner TEXT,
                shared BOOLEAN,
                public_link TEXT,
                version INTEGER,
                etag TEXT,
                created_at TEXT,
                modified_at TEXT,
                tags TEXT,
                is_favorite BOOLEAN,
                encrypted BOOLEAN
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                share_type TEXT,
                share_with TEXT,
                permissions TEXT,
                token TEXT UNIQUE,
                password_hash TEXT,
                expiry_date TEXT,
                download_count INTEGER,
                created_at TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                id TEXT PRIMARY KEY,
                user TEXT,
                file_id TEXT,
                action TEXT,
                timestamp TEXT,
                ip TEXT,
                user_agent TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS favorites (
                user TEXT,
                file_id TEXT,
                PRIMARY KEY (user, file_id),
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
        """)

        conn.commit()
        conn.close()

    def upload(self, local_path: str, remote_path: str, owner: str) -> File:
        """Upload a file."""
        local_file = Path(local_path)
        if not local_file.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        # Compute SHA256
        sha256_hash = hashlib.sha256()
        with open(local_file, 'rb') as f:
            sha256_hash.update(f.read())
        etag = sha256_hash.hexdigest()

        # Generate file ID
        file_id = etag[:16]

        # Store file
        remote_dir = self._storage_path / remote_path.strip('/')
        remote_dir.mkdir(parents=True, exist_ok=True)
        stored_path = remote_dir / local_file.name

        shutil.copy2(local_file, stored_path)

        # Get MIME type
        mime_type = self._get_mime_type(local_file.suffix)

        # Create file record
        file_obj = File(
            id=file_id,
            path=f"{remote_path.strip('/')}/{local_file.name}",
            name=local_file.name,
            size_bytes=local_file.stat().st_size,
            mime_type=mime_type,
            owner=owner,
            shared=False,
            public_link=None,
            version=1,
            etag=etag,
            created_at=datetime.now().isoformat(),
            modified_at=datetime.now().isoformat(),
            tags=[],
            is_favorite=False,
            encrypted=False
        )

        self._save_file(file_obj)
        self._log_activity(owner, file_id, "created", "127.0.0.1", "")

        return file_obj

    def download(self, file_id: str, target_path: str) -> str:
        """Download a file."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            raise FileNotFoundError(f"File not found: {file_id}")

        stored_path = self._storage_path / file_obj.path
        if not stored_path.exists():
            raise FileNotFoundError(f"Stored file not found: {stored_path}")

        target_file = Path(target_path)
        target_file.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(stored_path, target_file)
        self._log_activity("unknown", file_id, "downloaded", "127.0.0.1", "")

        return str(target_file)

    def list_files(self, path: str = "/", owner: Optional[str] = None, recursive: bool = False) -> List[File]:
        """List files in a directory."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = "SELECT * FROM files WHERE 1=1"
        params = []

        if owner:
            query += " AND owner = ?"
            params.append(owner)

        if not recursive:
            query += " AND path LIKE ?"
            params.append(f"{path.strip('/')}/%")
        else:
            query += " AND path LIKE ?"
            params.append(f"{path.strip('/')}%")

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_file(row) for row in rows]

    def delete_file(self, file_id: str, user: str) -> bool:
        """Soft delete a file."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            return False

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Soft delete by moving to trash (just marking deleted for now)
        cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))

        conn.commit()
        conn.close()

        self._log_activity(user, file_id, "deleted", "127.0.0.1", "")
        return True

    def move_file(self, file_id: str, new_path: str) -> Optional[File]:
        """Move a file to a new path."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            return None

        # Update path
        file_obj.path = new_path
        file_obj.modified_at = datetime.now().isoformat()

        self._save_file(file_obj)
        return file_obj

    def copy_file(self, file_id: str, target_path: str) -> Optional[File]:
        """Copy a file."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            return None

        # Generate new ID
        new_id = hashlib.md5(f"{file_id}{target_path}{datetime.now().isoformat()}".encode()).hexdigest()[:16]

        stored_path = self._storage_path / file_obj.path
        target_file = self._storage_path / target_path.strip('/') / file_obj.name

        target_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(stored_path, target_file)

        new_file = File(
            id=new_id,
            path=f"{target_path.strip('/')}/{file_obj.name}",
            name=file_obj.name,
            size_bytes=file_obj.size_bytes,
            mime_type=file_obj.mime_type,
            owner=file_obj.owner,
            shared=False,
            public_link=None,
            version=1,
            etag=file_obj.etag,
            created_at=datetime.now().isoformat(),
            modified_at=datetime.now().isoformat(),
            tags=[],
            is_favorite=False,
            encrypted=file_obj.encrypted
        )

        self._save_file(new_file)
        return new_file

    def share_file(self, file_id: str, share_type: str, share_with: str = "", 
                   permissions: str = "read", expiry_days: Optional[int] = None) -> Share:
        """Create a file share."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            raise FileNotFoundError(f"File not found: {file_id}")

        share_id = hashlib.md5(f"{file_id}{share_type}{share_with}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        token = hashlib.sha256(f"{share_id}{datetime.now().isoformat()}".encode()).hexdigest()[:20]

        expiry = None
        if expiry_days:
            expiry = (datetime.now() + timedelta(days=expiry_days)).isoformat()

        share = Share(
            id=share_id,
            file_id=file_id,
            share_type=share_type,
            share_with=share_with,
            permissions=[permissions],
            token=token,
            password_hash=None,
            expiry_date=expiry,
            download_count=0,
            created_at=datetime.now().isoformat()
        )

        self._save_share(share)
        file_obj.shared = True
        file_obj.public_link = token if share_type == "public" else None
        self._save_file(file_obj)

        self._log_activity(file_obj.owner, file_id, "shared", "127.0.0.1", "")

        return share

    def get_public_link(self, token: str) -> Optional[File]:
        """Resolve a public share token."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT file_id FROM shares WHERE token = ? AND share_type = 'public'", (token,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return self._get_file(row[0])
        return None

    def add_tag(self, file_id: str, tag: str) -> bool:
        """Add a tag to a file."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            return False

        if tag not in file_obj.tags:
            file_obj.tags.append(tag)
            self._save_file(file_obj)

        return True

    def search_by_tag(self, tag: str) -> List[File]:
        """Search files by tag."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM files WHERE tags LIKE ?", (f'%"{tag}"%',))
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_file(row) for row in rows]

    def search(self, query: str, owner: Optional[str] = None) -> List[File]:
        """Search files by name or tag."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        sql = "SELECT * FROM files WHERE (name LIKE ? OR tags LIKE ?)"
        params = [f"%{query}%", f'%{query}%']

        if owner:
            sql += " AND owner = ?"
            params.append(owner)

        cursor.execute(sql, params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_file(row) for row in rows]

    def get_activity(self, file_id: Optional[str] = None, user: Optional[str] = None, limit: int = 50) -> List[Activity]:
        """Get activity log."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = "SELECT * FROM activities WHERE 1=1"
        params = []

        if file_id:
            query += " AND file_id = ?"
            params.append(file_id)

        if user:
            query += " AND user = ?"
            params.append(user)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_activity(row) for row in rows]

    def get_storage_stats(self, owner: Optional[str] = None) -> Dict[str, Any]:
        """Get storage statistics."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = "SELECT SUM(size_bytes), COUNT(*), mime_type FROM files WHERE 1=1"
        params = []

        if owner:
            query += " AND owner = ?"
            params.append(owner)

        query += " GROUP BY mime_type"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        total_size = sum(row[0] or 0 for row in rows)
        total_count = sum(row[1] or 0 for row in rows)
        by_mime = {row[2]: row[0] or 0 for row in rows}

        conn.close()

        return {
            "total_size_bytes": total_size,
            "total_files": total_count,
            "by_mime_type": by_mime
        }

    def favorite(self, file_id: str, user: str) -> bool:
        """Mark file as favorite."""
        file_obj = self._get_file(file_id)
        if not file_obj:
            return False

        file_obj.is_favorite = True
        self._save_file(file_obj)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO favorites (user, file_id) VALUES (?, ?)", (user, file_id))
        conn.commit()
        conn.close()

        return True

    def get_favorites(self, user: str) -> List[File]:
        """Get user's favorite files."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT f.* FROM files f
            JOIN favorites fav ON f.id = fav.file_id
            WHERE fav.user = ?
        """, (user,))
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_file(row) for row in rows]

    def _get_file(self, file_id: str) -> Optional[File]:
        """Get file by ID."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return self._row_to_file(row)
        return None

    def _save_file(self, file_obj: File):
        """Save file to database."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO files
            (id, path, name, size_bytes, mime_type, owner, shared, public_link, version, etag, 
             created_at, modified_at, tags, is_favorite, encrypted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (file_obj.id, file_obj.path, file_obj.name, file_obj.size_bytes, file_obj.mime_type,
              file_obj.owner, file_obj.shared, file_obj.public_link, file_obj.version, file_obj.etag,
              file_obj.created_at, file_obj.modified_at, json.dumps(file_obj.tags),
              file_obj.is_favorite, file_obj.encrypted))

        conn.commit()
        conn.close()

    def _save_share(self, share: Share):
        """Save share to database."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO shares
            (id, file_id, share_type, share_with, permissions, token, password_hash, expiry_date, download_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (share.id, share.file_id, share.share_type, share.share_with, json.dumps(share.permissions),
              share.token, share.password_hash, share.expiry_date, share.download_count, share.created_at))

        conn.commit()
        conn.close()

    def _log_activity(self, user: str, file_id: str, action: str, ip: str, user_agent: str):
        """Log activity."""
        activity_id = hashlib.md5(f"{user}{file_id}{action}{datetime.now().isoformat()}".encode()).hexdigest()[:16]

        activity = Activity(
            id=activity_id,
            user=user,
            file_id=file_id,
            action=action,
            timestamp=datetime.now().isoformat(),
            ip=ip,
            user_agent=user_agent
        )

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO activities (id, user, file_id, action, timestamp, ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (activity.id, activity.user, activity.file_id, activity.action, activity.timestamp, activity.ip, activity.user_agent))

        conn.commit()
        conn.close()

    def _row_to_file(self, row) -> File:
        """Convert database row to File object."""
        return File(
            id=row[0],
            path=row[1],
            name=row[2],
            size_bytes=row[3],
            mime_type=row[4],
            owner=row[5],
            shared=row[6],
            public_link=row[7],
            version=row[8],
            etag=row[9],
            created_at=row[10],
            modified_at=row[11],
            tags=json.loads(row[12]) if row[12] else [],
            is_favorite=row[13],
            encrypted=row[14]
        )

    def _row_to_activity(self, row) -> Activity:
        """Convert database row to Activity object."""
        return Activity(
            id=row[0],
            user=row[1],
            file_id=row[2],
            action=row[3],
            timestamp=row[4],
            ip=row[5],
            user_agent=row[6]
        )

    def _get_mime_type(self, suffix: str) -> str:
        """Get MIME type from file suffix."""
        mime_types = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.png': 'image/png',
            '.mp3': 'audio/mpeg',
            '.mp4': 'video/mp4',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        }
        return mime_types.get(suffix.lower(), 'application/octet-stream')


def main():
    """CLI interface."""
    import sys

    manager = FileManager()

    if len(sys.argv) < 2:
        print("Usage: python file_manager.py [ls|upload|download|share|search|stats]")
        return

    cmd = sys.argv[1]

    if cmd == "ls":
        path = sys.argv[2] if len(sys.argv) > 2 else "/"
        files = manager.list_files(path)
        for f in files:
            print(f"  {f.name} ({f.size_bytes} bytes)")

    elif cmd == "upload":
        if len(sys.argv) < 4:
            print("Usage: python file_manager.py upload <local_path> <remote_path>")
            return

        local_path = sys.argv[2]
        remote_path = sys.argv[3]
        file_obj = manager.upload(local_path, remote_path, "default_user")
        print(f"Uploaded: {file_obj.id}")

    elif cmd == "share":
        if len(sys.argv) < 4:
            print("Usage: python file_manager.py share <file_id> <share_type>")
            return

        file_id = sys.argv[2]
        share_type = sys.argv[3]
        expiry_days = None

        if len(sys.argv) > 5 and sys.argv[4] == "--expiry-days":
            expiry_days = int(sys.argv[5])

        share = manager.share_file(file_id, share_type, expiry_days=expiry_days)
        print(f"Shared: {share.token}")

    elif cmd == "stats":
        stats = manager.get_storage_stats()
        print(json.dumps(stats, indent=2))

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
