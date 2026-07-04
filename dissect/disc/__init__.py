from __future__ import annotations

from dissect.disc.disc import Disc
from dissect.disc.exception import (
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
)

__all__ = [
    "Disc",
    "Error",
    "FileNotFoundError",
    "NotADirectoryError",
    "NotASymlinkError",
]
