from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.disc.exception import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime


class Format(Enum):
    ISO9660 = "iso9660"
    ROCKRIDGE = "rockridge"
    JOLIET = "joliet"
    UDF = "udf"


class BaseDisc:
    """Base class for disc implementations.

    Args:
        fh: File-like object of the disc.
    """

    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh

    @property
    def name(self) -> str:
        """Return the name of this disc."""
        raise NotImplementedError

    @property
    def application(self) -> str:
        """Return the application identifier of this disc."""
        raise NotImplementedError

    @property
    def publisher(self) -> str:
        """Return the publisher identifier of this disc."""
        raise NotImplementedError

    def get(self, path: str) -> BaseEntry:
        """Get a file entry from an absolute path."""
        raise NotImplementedError


class BaseDirEntry:
    """Base class for directory entries in a disc filesystem.

    Args:
        disc: The disc this entry belongs to.
        entry: The underlying entry object.
        name: The name of this entry.
    """

    def __init__(self, disc: BaseDisc, entry: Any, name: str):
        self.disc = disc
        self.entry = entry
        self.name = name

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    def get(self) -> BaseEntry:
        """Get the file entry this directory entry points to."""
        raise NotImplementedError


class BaseEntry:
    """Base class for entries in a disc filesystem.

    Args:
        disc: The disc this entry belongs to.
        entry: The underlying entry object.
    """

    def __init__(self, disc: BaseDisc, entry: Any):
        self.disc = disc
        self.entry = entry

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} inode={self.inode}>"

    @property
    def inode(self) -> int:
        """The inode number."""
        return 0

    @property
    def nlinks(self) -> int:
        """The number of links."""
        return 1

    @property
    def mode(self) -> int:
        """The file mode."""
        return 0o644

    @property
    def uid(self) -> int:
        """The owner user ID."""
        return 0

    @property
    def gid(self) -> int:
        """The owner group ID."""
        return 0

    @property
    def atime(self) -> datetime:
        """The access time."""
        raise NotImplementedError

    @property
    def mtime(self) -> datetime:
        """The modification time."""
        raise NotImplementedError

    @property
    def ctime(self) -> datetime:
        """The creation time."""
        raise NotImplementedError

    @property
    def btime(self) -> datetime:
        """The birth time."""
        raise NotImplementedError

    @property
    def size(self) -> int:
        """The file size."""
        raise NotImplementedError

    def is_dir(self) -> bool:
        """Return whether this entry is a directory."""
        raise NotImplementedError

    def is_file(self) -> bool:
        """Return True if this entry is a regular file."""
        return not self.is_dir() and not self.is_symlink()

    def is_symlink(self) -> bool:
        """Return True if this entry is a symlink."""
        return False

    def get(self, path: str) -> BaseEntry:
        """Get a entry relative to this one."""
        if not self.is_dir():
            raise NotADirectoryError

        current = self
        for part in path.split("/"):
            if not part:
                continue

            for entry in current.iterdir():
                if entry.name == part:
                    current = entry.get()
                    break
            else:
                # Could not find a matching entry
                raise FileNotFoundError(path)

        return current

    def listdir(self) -> dict[str, BaseDirEntry]:
        """Return a dictionary of the entries in this directory by name."""
        return {entry.name: entry for entry in self.iterdir()}

    def iterdir(self) -> Iterator[BaseDirEntry]:
        """Iterate over the contents of this directory."""
        raise NotImplementedError

    def readlink(self) -> str:
        """Return the target of the symlink."""
        raise NotASymlinkError

    def open(self) -> BinaryIO:
        """Open the file for reading."""
        raise NotImplementedError
