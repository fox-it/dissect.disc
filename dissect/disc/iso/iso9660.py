from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Iterator

from dissect.util.stream import RangeStream

from dissect.disc.base import DiscBase, DiscBaseEntry, DiscFormat
from dissect.disc.exceptions import FileNotFoundError, NotAFileError
from dissect.disc.iso.c_iso_9660 import c_iso

log = logging.getLogger(__name__)


class ISO9660Disc(DiscBase):
    """A Python class representing a ISO9660-compliant disc. As Joliet is basically ISO9660 with UTF-16-le encoding,
    this class also supports Joliet discs.

    References:
        - http://www.idea2ic.com/File_Formats/iso9660.pdf
        - https://wiki.osdev.org/ISO_9660
        - https://pismotec.com/cfs/iso9660-1999.html

    Joliet references:
        - https://github.com/torvalds/linux/blob/master/fs/isofs/joliet.c
        - http://littlesvr.ca/isomaster/resources/JolietSpecification.html
    """

    def __init__(
        self,
        fh: BinaryIO,
        primary_volume: c_iso.iso_primary_descriptor,
        volume_descriptor_end_pos: int,
        encoding: str = "utf-8",
    ) -> None:
        super().__init__(fh)
        self.primary_volume = primary_volume
        self.encoding = encoding

        self.volume_descriptors = []
        self._path_table: dict = None
        self.volume_descriptor_end_pos = volume_descriptor_end_pos

        self.root_record = self.make_record(c_iso.iso_directory_record(self.primary_volume.root_directory_record))

    def make_record(self, record: c_iso.iso_directory_record) -> ISO9660DirectoryRecord:
        return ISO9660DirectoryRecord(self, record)

    def get(self, path: str, use_path_table: bool = False) -> ISO9660DirectoryRecord:
        """Return an entry for a given path. For ISOs, this can be done in two ways: by using the path table, or by
        traversing the filesystem from the root record. Linux systems do not use the path table, Windows systems do."""
        requested_path = path

        # Remove trailing slash and left-pad with leading slash
        if not path.startswith("/"):
            path = "/" + path
        if path.endswith("/"):
            path = path[:-1]

        if not use_path_table:
            return self.root_record.get(path)
        filename = None
        if path not in self.path_table:
            # Only directories are in the path table, so if we can't find the initial path maybe we need to look up
            # its parent directory first.
            path, _, filename = path.rpartition("/")
            if not path:
                path = "/"

        # Either the parent or the requested path itself should be in the path table
        if path not in self.path_table:
            raise FileNotFoundError(requested_path)

        extent = self.path_table[path]
        self.fh.seek(extent * self.logical_block_size)
        record = c_iso.iso_directory_record(self.fh)
        if filename is None:
            # The requested path is the record we have just looked up
            return self.make_record(record)

        # The requested path is a file located in the directory we just looked up
        for entry in self.make_record(record).iterdir():
            if entry.name == filename:
                return entry
        raise FileNotFoundError(requested_path)

    @property
    def name(self) -> str:
        return self.primary_volume.volume_id.decode(self.encoding).split()[0]

    @property
    def logical_block_size(self) -> int:
        return self.primary_volume.logical_block_size

    @property
    def path_table(self) -> dict[str, int]:
        """Parse the path table and create a dict of paths and the corresponding extent of their directory record."""
        if self._path_table is not None:
            return self._path_table

        self._path_table = dict()

        self.fh.seek(self.primary_volume.type_l_path_table * self.logical_block_size)
        path_table_bytes = self.fh.read(self.primary_volume.path_table_size)

        offset = 0
        index = 1
        entries: dict[int, str] = dict()

        while offset < self.primary_volume.path_table_size:
            entry = c_iso.iso_path_table_entry(path_table_bytes[offset:])
            if index == 1:
                entries[1] = "/"
                self._path_table["/"] = entry.extent_location
            else:
                entry_name = entry.name.decode(self.encoding)
                parent_path = entries[entry.parent_dir_no]
                seperator = "/" if parent_path != "/" else ""
                entry_path = parent_path + seperator + entry_name

                entries[index] = entry_path
                self._path_table[entry_path] = entry.extent_location

            entry_size = len(entry)
            offset += entry_size
            if entry_size % 2 != 0:
                offset += 1

            index += 1

        return self._path_table


class ISO9660DirectoryRecord(DiscBaseEntry):
    """A Python class representing an iso_directory_record."""

    def __init__(
        self, fs: ISO9660Disc, record: c_iso.iso_directory_record, parent: ISO9660DirectoryRecord | None = None
    ):
        self.fs = fs
        self.record = record
        self.is_dir = bool(record.flags.Directory)
        self.parent = parent

        self.name = record.name.decode(self.fs.encoding, errors="ignore")
        if self.name == "\x00":
            self.name = "."
        elif self.name == "\x01":
            self.name = ".."

        if not self.is_dir:
            self.name, _, _ = self.name.partition(";")

    def iterdir(self) -> Iterator[ISO9660DirectoryRecord]:
        """Yield DirectoryRecords"""
        self.fs.fh.seek(self.fs.logical_block_size * self.record.extent)
        block = self.fs.fh.read(self.record.size)
        offset = 0

        while True:
            first_byte = block[offset : offset + 1]

            # The rest of this block is null bytes, so we're done
            if first_byte == b"\x00":
                break

            record = c_iso.iso_directory_record(block[offset:])

            # Instantiate a new instance of whatever class 'self' belongs to.
            yield type(self)(self.fs, record, self)

            offset += len(record)

            if offset % 2 != 0:
                offset += 1

    def get(self, path: str) -> ISO9660DirectoryRecord:
        """Get a directory record by path relative to this directory record"""
        if not self.is_dir:
            raise NotADirectoryError

        queue = path.split("/")
        current_entry = self
        while len(queue):
            elem = queue.pop(0)
            if not elem:
                continue

            found = False
            for entry in current_entry.iterdir():
                if entry.name == elem:
                    current_entry = entry
                    found = True

            if not found:
                # Could not find a matching entry
                raise FileNotFoundError(path)
        return current_entry

    def open(self) -> RangeStream:
        """Construct a file-like object for reading the contents of this file"""
        if self.is_dir:
            raise NotAFileError(self.name)

        # Haven't come across an ISO yet where the file was interleaved.
        if self.record.interleave:
            raise NotImplementedError("Interleaved mode not supported for ISO files.")

        return RangeStream(
            self.fs.fh,
            self.record.extent * self.fs.logical_block_size,
            self.record.size,
        )

    @property
    def ctime(self) -> datetime:
        # Plain ISO9660 have only one timestamp associated with them.
        return parse_iso9660_timestamp(self.record.date_time)

    @property
    def mtime(self) -> datetime:
        # Plain ISO9660 have only one timestamp associated with them.
        return parse_iso9660_timestamp(self.record.date_time)

    @property
    def atime(self) -> datetime:
        # Plain ISO9660 have only one timestamp associated with them.
        return parse_iso9660_timestamp(self.record.date_time)

    @property
    def mode(self) -> int:
        if self.record.ext_attr_length == 0:
            return 0o644
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def uid(self) -> int:
        if self.record.ext_attr_length == 0:
            return 0
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def gid(self) -> int:
        if self.record.ext_attr_length == 0:
            return 0
        raise NotImplementedError("Extended attribute record is available but not supported")


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


def load_iso9660_discs(fh: BinaryIO) -> Iterator[DiscFormat, ISO9660Disc]:
    """Try to parse a given file handle for available formats of ISO9660 discs. This includes 'plain' ISO9660 and
    Joliet."""
    fh.seek(c_iso.SYSTEM_AREA_SIZE)

    volume_descriptors = []

    volume_descriptor_end_pos = 0
    iso9660_primary_volume = None
    joliet_primary_volume = None

    while True:
        volume_descriptor_bytes = fh.read(c_iso.ISOFS_BLOCK_SIZE)
        volume_descriptor = c_iso.iso_volume_descriptor(volume_descriptor_bytes)

        if volume_descriptor.id != c_iso.ISO_STANDARD_ID:
            raise ValueError("Invalid volume descriptor ID")

        volume_descriptors.append(volume_descriptor)
        if volume_descriptor.type == c_iso.ISO_VD_END:
            volume_descriptor_end_pos = fh.tell()
            break

        if volume_descriptor.type == c_iso.ISO_VD_PRIMARY:
            iso9660_primary_volume = c_iso.iso_primary_descriptor(volume_descriptor_bytes)
            continue

        # Before the VD terminator volume, there is another one. This could possibly be a Joliet volume descriptor.
        # Re-parse as a primary volume
        primary_volume = c_iso.iso_primary_descriptor(volume_descriptor_bytes)

        # Check whether system id starts with a null byte, suggesting it is UTF-16-LE-encoded.
        if primary_volume.type == c_iso.ISO_VD_SUPPLEMENTARY and primary_volume.system_id[0] == 0x00:
            joliet_primary_volume = primary_volume

    if iso9660_primary_volume is None:
        raise ValueError("No primary volume descriptor found")

    yield DiscFormat.ISO9660, ISO9660Disc(fh, iso9660_primary_volume, volume_descriptor_end_pos)
    if joliet_primary_volume is not None:
        yield DiscFormat.JOLIET, ISO9660Disc(fh, joliet_primary_volume, volume_descriptor_end_pos, encoding="utf-16-be")
