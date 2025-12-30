from __future__ import annotations

from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.disc.exception import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from typing_extensions import Self


class Format(Enum):
    ISO9660 = "iso9660"
    ROCKRIDGE = "rockridge"
    JOLIET = "joliet"
    UDF = "udf"


class BaseDisc:
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
        """Get a DiscBaseEntry from an absolute path."""
        raise NotImplementedError


class BaseEntry:
    def __init__(self, disc: BaseDisc, entry: Any):
        self.disc = disc
        self.entry = entry

    @cached_property
    def name(self) -> str:
        """The name of this entry."""
        raise NotImplementedError

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
                    current = entry
                    break
            else:
                # Could not find a matching entry
                raise FileNotFoundError(path)

        return current

    def listdir(self) -> dict[str, Self]:
        """Return a dictionary of the entries in this directory by name."""
        return {entry.name: entry for entry in self.iterdir()}

    def iterdir(self) -> Iterator[Self]:
        """Iterate over the contents of this directory."""
        raise NotImplementedError

    def readlink(self) -> str:
        """Return the target of the symlink."""
        raise NotASymlinkError

    def open(self) -> BinaryIO:
        """Open the file for reading."""
        raise NotImplementedError
