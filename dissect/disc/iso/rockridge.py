from __future__ import annotations

from collections import defaultdict
from enum import Enum, IntEnum
from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream

from dissect.disc.exception import NotASymlinkError
from dissect.disc.iso.c_iso9660 import c_iso
from dissect.disc.iso.c_rockridge import (
    ROCKRIDGE_MAGICS,
    SUSP_MAGIC,
    c_rockridge,
)
from dissect.disc.iso.iso9660 import (
    ISO9660,
    ISO9660DirEntry,
    ISO9660Entry,
    parse_iso9660_timestamp,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime


class RockRidgeTimestampType(IntEnum):
    CREATION = 0
    MODIFY = 1
    ACCESS = 2
    ATTRIBUTES = 3
    BACKUP = 4
    EXPIRATION = 5
    EFFECTIVE = 6


class SystemUseSignature(Enum):
    EXTENSIONS_REFERENCE = b"ER"
    CONTINUATION_AREA = b"CE"


class RockRidgeSignature(Enum):
    POSIX = b"PX"
    SYMLINK = b"SL"
    ALTERNATIVE_NAME = b"NM"
    TIMESTAMPS = b"TF"
    CHILD_LINK = b"CL"
    RELOCATED = b"RE"


class RockRidge(ISO9660):
    """Disc implementation that is Rock Ridge compliant.

    References:
        - https://github.com/torvalds/linux/blob/master/fs/isofs/rock.h
        - https://studylib.net/doc/18849173/ieee-p1282-rock-ridge-interchange-protocol-draft
        - https://docplayer.net/29621206-Ieee-p1281-system-use-sharing-protocol-draft-standard-version-1-12-adopted.html
    """

    def __init__(self, fh: BinaryIO):
        # RockRidge is an extension of ISO9660, so we first have to parse the disc as ISO9660.
        # The verification here will do a little bit of redundant parsing of ISO9660
        base = ISO9660(fh)

        # RockRidge is an implementation of the System Use Sharing Protocol (SUSP). So we first check for SUSP
        # compatibility, then for a RockRidge identifier.

        # Skip past the root record
        fh.seek((base.block_size * base.root.entry.extent) + c_iso.ROOT_DIRECTORY_RECORD_LENGTH)
        if fh.read(6) != SUSP_MAGIC:
            raise ValueError("Not a RockRidge-compliant disc")

        # We have SUSP, but we need to check if it's RockRidge.
        # From System Use Sharing Protocol documentation per the Extensions Reference record location:
        # This System Use Entry shall appear in the System Use Area of the first ("." or (00))
        # Directory Record of the root directory of the Directory Hierarchy in which the extension
        # specification to which this "ER" System Use Entry refers is used.
        if (first_directory_record := next(base.root.iterdir(), None)) is None:
            raise ValueError("Empty root directory in SUSP-compliant disc")

        first_directory_entry = RockRidgeEntry(base, first_directory_record.entry)
        if first_directory_entry is None or not first_directory_entry.has_system_use_entry(
            SystemUseSignature.EXTENSIONS_REFERENCE
        ):
            raise ValueError("Encountered SUSP-compliant disc but could not detect RockRidge")

        # We can use this to determine what extension is being used that uses SUSP.
        buf = next(first_directory_entry.get_system_use_entries(SystemUseSignature.EXTENSIONS_REFERENCE))
        extensions_reference_entry = c_rockridge.SU_ER_s(buf)
        identifier = extensions_reference_entry.identifier
        if identifier not in ROCKRIDGE_MAGICS:
            raise ValueError(
                f"Encountered SUSP-compliant disc but could not detect RockRidge from extensions identifier {identifier!r}"  # noqa: E501
            )

        super().__init__(fh)

    def _make_entry(self, record: c_iso.iso_directory_record) -> RockRidgeEntry:
        return RockRidgeEntry(self, record)

    def _make_direntry(self, record: c_iso.iso_directory_record) -> RockRidgeDirEntry:
        return RockRidgeDirEntry(self, record)


class RockRidgeDirEntry(ISO9660DirEntry):
    """A directory entry in a Rock Ridge filesystem."""

    disc: RockRidge
    entry: c_iso.iso_directory_record

    def __init__(self, disc: RockRidge, entry: c_iso.iso_directory_record):
        super().__init__(disc, entry)

        # Pre-load the file entry for this directory entry, we need to check for alternative names.
        self._file_entry = self.disc._make_entry(entry)

        # Check for alternative name system use entries and if present, use them to determine the name of this record.
        if self._file_entry.has_system_use_entry(RockRidgeSignature.ALTERNATIVE_NAME):
            name = ""
            for buf in self._file_entry.get_system_use_entries(RockRidgeSignature.ALTERNATIVE_NAME):
                alternate_name_entry = c_rockridge.RR_NM_s(buf)
                name += alternate_name_entry.name.decode(self.disc.encoding)

            # Update the name
            self.name = name

    def get(self) -> RockRidgeEntry:
        """Get the file entry this directory entry points to."""
        return self._file_entry


class RockRidgeEntry(ISO9660Entry):
    """A file or directory entry in a Rock Ridge filesystem."""

    disc: RockRidge
    entry: c_iso.iso_directory_record

    def __init__(
        self,
        disc: RockRidge,
        record: c_iso.iso_directory_record,
    ):
        super().__init__(disc, record)

        # Check for a child link system use entry. If this is present, we have to traverse elsewhere to obtain accurate
        # information about this record, such as its actual extent and metadata."""
        if self.has_system_use_entry(RockRidgeSignature.CHILD_LINK):
            buf = next(self.get_system_use_entries(RockRidgeSignature.CHILD_LINK))
            entry = c_rockridge.RR_CL_s(buf)

            # Re-instantiate based on a new directory record, effectively overwriting the properties of 'self'.
            self.disc.fh.seek(entry.location * self.disc.block_size)
            record = c_iso.iso_directory_record(self.disc.fh)
            super().__init__(self.disc, record)

    @property
    def inode(self) -> int:
        # RockRidge Draft Version 1.12 suggests 4 bytes being dedicated to a 'serial' which would match with st_ino.
        # However, it's not there. Structure definitions in the kernel also don't have it. If someone knows where the
        # st_ino information for RockRidge is actually resided, feel free to add that functionality here. Thanks!
        return super().inode

    @property
    def nlinks(self) -> int:
        if self._posix_entry is not None:
            return self._posix_entry.links
        return super().nlinks

    @property
    def mode(self) -> int:
        if self._posix_entry is not None:
            return self._posix_entry.mode
        return super().mode

    @property
    def uid(self) -> int:
        if self._posix_entry is not None:
            return self._posix_entry.uid
        return super().uid

    @property
    def gid(self) -> int:
        if self._posix_entry is not None:
            return self._posix_entry.gid
        return super().gid

    @property
    def atime(self) -> datetime:
        if RockRidgeTimestampType.ACCESS in self.timestamps:
            return self.timestamps[RockRidgeTimestampType.ACCESS]
        return super().atime

    @property
    def mtime(self) -> datetime:
        if RockRidgeTimestampType.MODIFY in self.timestamps:
            return self.timestamps[RockRidgeTimestampType.MODIFY]
        return super().mtime

    @property
    def ctime(self) -> datetime:
        if RockRidgeTimestampType.ATTRIBUTES in self.timestamps:
            return self.timestamps[RockRidgeTimestampType.ATTRIBUTES]
        return super().ctime

    @cached_property
    def _system_use_entries(self) -> dict[bytes, list[c_rockridge.system_use_entry]]:
        """Traverse the System Use Area of this directory record and collect all System Use Entries.

        These entries are not parsed in their entirety: only signature, version, length and data properties are stored.
        """
        entries = defaultdict(list)

        initial_offset = len(SUSP_MAGIC) + 1 if self.entry.system_use.startswith(SUSP_MAGIC) else 0
        if self.entry.name_len % 2 == 0:
            # The system use has to begin at an even offset
            initial_offset += 1

        blocks = [BytesIO(self.entry.system_use[initial_offset:])]
        while blocks:
            block = blocks.pop(0)
            offset = 0

            buf = block.read()
            while offset < len(buf):
                # The remainder of the system use area is padded with null-bytes, so when we encounter a null byte we
                # should stop
                if buf[offset:] == b"\x00":
                    break

                # We now know the signature, version, length and data, allowing us to parse the data using the right
                # structure definition
                unparsed_entry = c_rockridge.system_use_entry(buf[offset:])
                entries[unparsed_entry.signature].append(unparsed_entry)

                if unparsed_entry.signature == SystemUseSignature.CONTINUATION_AREA.value:
                    # There are additional system use entries!
                    continuation_entry = c_rockridge.SU_CE_s(unparsed_entry.dumps())
                    new_block = RangeStream(
                        self.disc.fh, continuation_entry.extent * self.disc.block_size, continuation_entry.size
                    )

                    blocks.append(new_block)

                offset += len(unparsed_entry)

        return entries

    def get_system_use_entries(self, signature: RockRidgeSignature | SystemUseSignature) -> Iterator[bytes]:
        """Traverses system use entries for a given signature, and yields their byte-stream so they can be re-parsed."""
        if signature.value not in self._system_use_entries:
            raise KeyError(signature)

        for instance in self._system_use_entries[signature.value]:
            yield instance.dumps()

    def has_system_use_entry(self, signature: RockRidgeSignature | SystemUseSignature) -> bool:
        """Returns whether or not this directory record has one or more system use entries of the given signature."""
        return signature.value in self._system_use_entries

    @cached_property
    def _posix_entry(self) -> c_rockridge.RR_PX_s | None:
        """Return the POSIX system use entry for this record, if it exists."""
        if not self.has_system_use_entry(RockRidgeSignature.POSIX):
            return None

        buf = next(self.get_system_use_entries(RockRidgeSignature.POSIX))
        return c_rockridge.RR_PX_s(buf)

    @cached_property
    def timestamps(self) -> dict[RockRidgeTimestampType, datetime]:
        """Resolve timestamps from RockRidge timestamp system use entries."""
        result = {}

        if not self.has_system_use_entry(RockRidgeSignature.TIMESTAMPS):
            return result

        buf = next(self.get_system_use_entries(RockRidgeSignature.TIMESTAMPS))
        timestamps_metadata = c_rockridge.RR_TF_s(buf[: len(c_rockridge.RR_TF_s)])
        timestamps_values = buf[len(c_rockridge.RR_TF_s) :]

        # Timestamps will appear in this order, but only enabled timestamps will appear in the 'values' buffer.
        timestamp_flags = [
            timestamps_metadata.CREATION,
            timestamps_metadata.MODIFY,
            timestamps_metadata.ACCESS,
            timestamps_metadata.ATTRIBUTES,
            timestamps_metadata.BACKUP,
            timestamps_metadata.EXPIRATION,
            timestamps_metadata.EFFECTIVE,
        ]

        # When we start iterating through timestamp values, we have to know for each timestamp with which 'flag' it is
        # associated. To match the timestamp index to the right flag, we have to know where the 'gaps' (disabled flags)
        # are.
        gaps = {}
        gap_size = 0
        timestamp_index = 0
        for flag in timestamp_flags:
            if not flag:
                gap_size += 1
            elif gap_size > 0:
                gaps[timestamp_index] = gap_size
                gap_size = 0
                timestamp_index += 1

        # Now, when iterating through every timestamp value, we check if we have 'jumped' over a gap, and if so,
        # increment our 'effective' index accordingly so we know with which flag a given timestamp value is associated.
        offset = 0
        effective_index = 0
        timestamp_index = 0
        while offset < len(timestamps_values):
            if timestamp_index in gaps:
                effective_index += gaps[timestamp_index]

            if timestamps_metadata.LONG_FORM:
                timestamp = c_iso.dec_datetime(timestamps_values[offset:])
            else:
                timestamp = c_iso.datetime_short(timestamps_values[offset:])

            offset += len(timestamp)

            # TODO: This works because the timestamp structure of RockRidge and the timestamp structure of ISO9660 have
            # the same property names. This is not ideal, but it works for now.
            result[RockRidgeTimestampType(effective_index)] = parse_iso9660_timestamp(timestamp)

            effective_index += 1
            timestamp_index += 1

        return result

    def is_symlink(self) -> bool:
        """Returns whether this directory record represents a symlink."""
        return self.has_system_use_entry(RockRidgeSignature.SYMLINK)

    def iterdir(self) -> Iterator[RockRidgeDirEntry]:
        record: RockRidgeDirEntry
        for record in super().iterdir():
            if record._file_entry.has_system_use_entry(RockRidgeSignature.RELOCATED):
                # This is a relocated entry, and should instead be ignored as it doesn't 'really' live here.
                continue
            yield record

    def readlink(self) -> str:
        """Returns what this symlink points to. Raises NotASymlinkError if this is not a symlink."""
        if not self.is_symlink():
            raise NotASymlinkError(self)

        target = ""
        for buf in self.get_system_use_entries(RockRidgeSignature.SYMLINK):
            entry = c_rockridge.RR_SL_s(buf)

            offset = 0
            while offset < len(entry.components):
                component = c_rockridge.SL_component(entry.components[offset:])
                offset += len(component)

                if component.flags.parent:
                    target += "../"
                    continue

                if component.flags.root:
                    target = "/" + target
                    continue

                if component.flags.current:
                    target += "./"
                    continue

                target += component.content.decode()
                if offset < len(entry.components) and not component.flags._continue:
                    # A new component will follow after this one
                    target += "/"

        return target
