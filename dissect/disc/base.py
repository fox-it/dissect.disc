from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, BinaryIO, Iterator

from dissect.disc.exceptions import NotASymlinkError


class DiscFormat(Enum):
    ISO9660 = "iso9660"
    ROCKRIDGE = "rockridge"
    JOLIET = "joliet"
    UDF = "udf"


class DiscBase:
    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh

    @property
    def name(self) -> str:
        """Return the name of this disc."""
        raise NotImplementedError()

    def get(self, path: str) -> DiscBaseEntry:
        """Get a DiscBaseEntry from an absolute path."""
        raise NotImplementedError()


class DiscBaseEntry:
    def __init__(self, fs: DiscBase, entry: Any, parent: DiscBaseEntry | None = None):
        raise NotImplementedError()

    def get(self, path: str) -> DiscBaseEntry:
        """Get a DiscBaseEntry relative to this one."""
        raise NotImplementedError()

    def iterdir(self) -> Iterator[DiscBaseEntry]:
        """Iterate over the contents of this directory."""
        raise NotImplementedError()

    def listdir(self) -> dict[str, DiscBaseEntry]:
        """Return a dictionary of DirectoryRecords by name."""
        return {record.name: record for record in self.iterdir()}

    def open(self) -> BinaryIO:
        """Open the file for reading."""
        raise NotImplementedError()

    def is_symlink(self) -> bool:
        """Return True if this entry is a symlink."""
        return False

    @property
    def atime(self) -> datetime:
        """Return the access time."""
        raise NotImplementedError()

    @property
    def mtime(self) -> datetime:
        """Return the modification time."""
        raise NotImplementedError()

    @property
    def ctime(self) -> datetime:
        """Return the creation time."""
        raise NotImplementedError()

    def readlink(self) -> str:
        """Return the target of the symlink."""
        raise NotASymlinkError()

    @property
    def mode(self) -> int:
        """Return the file mode."""
        return 0o644

    @property
    def uid(self) -> int:
        """Return the user ID."""
        return 0

    @property
    def gid(self) -> int:
        """Return the group ID."""
        return 0

    @property
    def nlinks(self) -> int:
        """Return the number of links."""
        return 1

    @property
    def inode(self) -> int:
        """Return the inode number."""
        return 0
