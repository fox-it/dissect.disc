from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream

from dissect.disc.base import BaseDirEntry, BaseDisc, BaseEntry
from dissect.disc.exception import FileNotFoundError, IsADirectoryError
from dissect.disc.iso.c_iso9660 import c_iso

if TYPE_CHECKING:
    from collections.abc import Iterator


class ISO9660(BaseDisc):
    """Disc implementation that is ISO9660 compliant.

    As Joliet is basically ISO9660 with UTF-16-BE encoding, this implementation also supports Joliet discs.

    References:
        - http://www.idea2ic.com/File_Formats/iso9660.pdf
        - https://wiki.osdev.org/ISO_9660
        - https://pismotec.com/cfs/iso9660-1999.html
        - https://github.com/torvalds/linux/blob/master/fs/isofs/joliet.c
        - http://littlesvr.ca/isomaster/resources/JolietSpecification.html

    Args:
        fh: File-like object of the ISO file.
    """

    def __init__(self, fh: BinaryIO, encoding: str = "utf-8") -> None:
        super().__init__(fh)
        self.encoding = encoding
        self.primary_volume = self._find_primary_volume_descriptor()

        self.root = self._make_entry(c_iso.iso_directory_record(self.primary_volume.root_directory_record))

    def _find_primary_volume_descriptor(self) -> c_iso.iso_primary_descriptor:
        for block, descriptor in read_descriptors(self.fh):
            if descriptor.type == c_iso.ISO_VD_PRIMARY:
                return c_iso.iso_primary_descriptor(block)
        else:
            raise ValueError("No ISO9660 primary volume descriptor found")

    @property
    def name(self) -> str:
        return decode_identifier(self.primary_volume.volume_id, self.encoding)

    @property
    def application(self) -> str:
        return decode_identifier(self.primary_volume.application_id, self.encoding)

    @property
    def publisher(self) -> str:
        return decode_identifier(self.primary_volume.publisher_id, self.encoding)

    @property
    def block_size(self) -> int:
        return self.primary_volume.logical_block_size

    def _make_entry(self, record: c_iso.iso_directory_record) -> ISO9660Entry:
        return ISO9660Entry(self, record)

    def _make_direntry(self, record: c_iso.iso_directory_record) -> ISO9660DirEntry:
        return ISO9660DirEntry(self, record)

    def get(self, path: str, use_path_table: bool = False) -> ISO9660Entry:
        """Return an entry for a given path.

        For ISOs, this can be done in two ways: by using the path table, or by traversing the filesystem from the root
        record. Linux systems do not use the path table, Windows systems do.
        """
        # Remove trailing slash and left-pad with leading slash
        if not path.startswith("/"):
            path = "/" + path
        path = path.removesuffix("/")

        if not use_path_table:
            return self.root.get(path)

        lookup_path = path
        lookup_filename = None
        if lookup_path not in self.path_table:
            # Only directories are in the path table, so if we can't find the initial path maybe we need to look up
            # its parent directory first.
            lookup_path, _, lookup_filename = lookup_path.rpartition("/")

        # Either the parent or the requested path itself should be in the path table
        if lookup_path not in self.path_table:
            raise FileNotFoundError(path)

        extent = self.path_table[lookup_path]
        self.fh.seek(extent * self.block_size)
        record = c_iso.iso_directory_record(self.fh)

        if lookup_filename is None:
            # The requested path is the record we have just looked up
            return self._make_entry(record)

        # The requested path is a file located in the directory we just looked up
        for entry in self._make_entry(record).iterdir():
            if entry.name == lookup_filename:
                return entry.get()

        raise FileNotFoundError(path)

    @cached_property
    def path_table(self) -> dict[str, int]:
        """Parse the path table and create a map of paths and the corresponding extent of their directory record."""
        table = {}

        self.fh.seek(self.primary_volume.type_l_path_table * self.block_size)
        buf = BytesIO(self.fh.read(self.primary_volume.path_table_size))

        index = 1
        entries: dict[int, str] = {}

        while buf.tell() < self.primary_volume.path_table_size:
            entry = c_iso.iso_path_table_entry(buf)

            if index == 1:
                entries[index] = ""
                table[""] = entry.extent_location
            else:
                entry_name = entry.name.decode(self.encoding)
                parent_path = entries[entry.parent_dir_no]
                entry_path = f"{parent_path}/{entry_name}"

                entries[index] = entry_path
                table[entry_path] = entry.extent_location

            if len(entry) % 2 != 0:
                # Align to even byte boundary
                buf.seek(1, io.SEEK_CUR)

            index += 1

        return table


class ISO9660DirEntry(BaseDirEntry):
    """A directory entry in a ISO9660 filesystem."""

    disc: ISO9660
    entry: c_iso.iso_directory_record

    def __init__(self, disc: ISO9660, entry: c_iso.iso_directory_record):
        if entry.name == b"\x00":
            name = "."
        elif entry.name == b"\x01":
            name = ".."
        else:
            name = entry.name.decode(disc.encoding, errors="ignore")

        if not entry.flags.Directory:
            name, _, _ = name.partition(";")

        super().__init__(disc, entry, name)

    def get(self) -> ISO9660Entry:
        """Get the file entry this directory entry points to."""
        return self.disc._make_entry(self.entry)


class ISO9660Entry(BaseEntry):
    """A file or directory entry in a ISO9660 filesystem."""

    disc: ISO9660
    entry: c_iso.iso_directory_record

    @property
    def inode(self) -> int:
        # Use the extent as a makeshift inode number
        return self.entry.extent

    @property
    def mode(self) -> int:
        if self.entry.ext_attr_length == 0:
            return 0o644
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def uid(self) -> int:
        if self.entry.ext_attr_length == 0:
            return 0
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def gid(self) -> int:
        if self.entry.ext_attr_length == 0:
            return 0
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def atime(self) -> datetime:
        # Plain ISO9660 have only one timestamp associated with them.
        return parse_iso9660_timestamp(self.entry.date_time)

    @property
    def mtime(self) -> datetime:
        # Plain ISO9660 have only one timestamp associated with them.
        return parse_iso9660_timestamp(self.entry.date_time)

    @property
    def ctime(self) -> datetime:
        # Plain ISO9660 have only one timestamp associated with them.
        return parse_iso9660_timestamp(self.entry.date_time)

    @property
    def size(self) -> int:
        """Size of the entry in bytes"""
        return self.entry.size

    def is_dir(self) -> bool:
        """Return whether this entry is a directory."""
        return bool(self.entry.flags.Directory)

    def iterdir(self) -> Iterator[ISO9660DirEntry]:
        """Iterate over the contents of this directory."""
        self.disc.fh.seek(self.entry.extent * self.disc.block_size)
        block = self.disc.fh.read(self.size)

        offset = 0
        while True:
            first_byte = block[offset : offset + 1]

            # The rest of this block is null bytes, so we're done
            if first_byte == b"\x00":
                break

            record = c_iso.iso_directory_record(block[offset:])
            yield self.disc._make_direntry(record)

            offset += len(record)
            if offset % 2 != 0:
                offset += 1

    def open(self) -> RangeStream:
        """Open the file for reading."""
        if self.is_dir():
            raise IsADirectoryError(self)

        # Haven't come across an ISO yet where the file was interleaved.
        if self.entry.interleave:
            raise NotImplementedError("Interleaved mode not supported for ISO files")

        return RangeStream(
            self.disc.fh,
            self.entry.extent * self.disc.block_size,
            self.size,
        )


def decode_identifier(identifier: bytes, encoding: str) -> str:
    if identifier := identifier.decode(encoding).split():
        return identifier[0]
    return ""


def parse_iso9660_timestamp(timestamp: type[c_iso.dec_datetime | c_iso.datetime_short]) -> datetime:
    """Parse the odd timestamp format of ISO9660. Works for both the LONG_FORM structure and the 7-byte structure."""
    tz = timezone(timedelta(minutes=timestamp.offset * 15))
    return datetime(
        timestamp.year + 1900,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
        tzinfo=tz,
    )


def read_descriptors(fh: BinaryIO) -> Iterator[tuple[bytes, c_iso.iso_volume_descriptor]]:
    """Read all volume descriptors from the ISO9660 disc image.

    Args:
        fh: The file-like object representing the disc image.
    """
    fh.seek(c_iso.SYSTEM_AREA_SIZE)
    while True:
        block = fh.read(c_iso.ISOFS_BLOCK_SIZE)
        volume_descriptor = c_iso.iso_volume_descriptor(block)

        if volume_descriptor.id != c_iso.ISO_STANDARD_ID:
            raise ValueError(f"Invalid volume descriptor ID for ISO9660 disc: {volume_descriptor.id!r}")

        yield block, volume_descriptor

        if volume_descriptor.type == c_iso.ISO_VD_END:
            break
