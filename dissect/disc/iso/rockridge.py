from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from typing import BinaryIO, Iterator

from dissect.cstruct import Instance
from dissect.util.stream import RangeStream

from dissect.disc.exceptions import NotASymlinkError, NotRockridgeError
from dissect.disc.iso.c_iso_9660 import c_iso
from dissect.disc.iso.c_rockridge import (
    ROCKRIDGE_MAGICS,
    SUSP_MAGIC,
    RockRidgeSignature,
    RockRidgeTimestampType,
    SystemUseSignature,
    c_rockridge,
)
from dissect.disc.iso.iso9660 import (
    ISO9660DirectoryRecord,
    ISO9660Disc,
    parse_iso9660_timestamp,
)

log = logging.getLogger(__name__)


class RockridgeDisc(ISO9660Disc):
    """A python class representing an ISO9660 disc that is Rockridge compliant.

    References:
        - https://github.com/torvalds/linux/blob/master/fs/isofs/rock.h
        - https://studylib.net/doc/18849173/ieee-p1282-rock-ridge-interchange-protocol-draft
        - https://docplayer.net/29621206-Ieee-p1281-system-use-sharing-protocol-draft-standard-version-1-12-adopted.html
    """

    def make_record(self, record: Instance) -> RockRidgeDirectoryRecord:
        return RockRidgeDirectoryRecord(self, record)


class SystemUseSharingProtocolDirectoryRecord(ISO9660DirectoryRecord):
    """A python class representing an iso_directory_record with System Use Entries in its System Use Area."""

    def __init__(
        self,
        fs: ISO9660Disc,
        record: Instance,
        parent: SystemUseSharingProtocolDirectoryRecord | None = None,
    ) -> None:
        super().__init__(fs, record, parent)
        self._system_use_entries: dict[RockRidgeSignature, list[Instance]] = defaultdict(list)
        self._process_system_use_area()

    def _process_system_use_area(self) -> None:
        """One-time function to traverse the System Use Area of this directory record and collect all System Usea
        Entries. These entries are not parsed in their entirety: only signature, version, length and data properties are
        inferred."""
        initial_offset = len(SUSP_MAGIC) + 1 if self.record.system_use.startswith(SUSP_MAGIC) else 0

        if self.record.name_len % 2 == 0:
            # The system use has to begin at an even offset
            initial_offset += 1

        blocks = [BytesIO(self.record.system_use[initial_offset:])]
        while len(blocks) > 0:
            block = blocks.pop(0)
            offset = 0
            byte_copy = block.read()
            while offset < len(byte_copy):
                # The remainder of the system area is padded with null-bytes, so when we encounter a null byte we
                # should stop
                if byte_copy[offset:] == b"\x00":
                    break
                # We now know the signature, version, length and data, allowing us to parse the data using the right
                # structure definition
                unparsed_entry = c_rockridge.rock_ridge_entry(byte_copy[offset:])
                self._system_use_entries[unparsed_entry.signature].append(unparsed_entry)

                if unparsed_entry.signature == SystemUseSignature.CONTINUATION_AREA.value:
                    # There are additional system use entries!
                    continuation_entry = c_rockridge.SU_CE_s(unparsed_entry.dumps())
                    new_block = RangeStream(
                        self.fs.fh, continuation_entry.extent * self.fs.logical_block_size, continuation_entry.size
                    )

                    blocks.append(new_block)

                offset += len(unparsed_entry)

    def get_system_use_entries(self, signature: RockRidgeSignature | SystemUseSignature) -> Iterator[bytes]:
        """Traverses system use entries for a given signature, and yields their byte-stream so they can be re-parsed"""
        if signature.value not in self._system_use_entries:
            raise KeyError(signature)
        for instance in self._system_use_entries[signature.value]:
            yield instance.dumps()

    def has_system_use_entry(
        self, signature: RockRidgeDirectoryRecord | SystemUseSharingProtocolDirectoryRecord
    ) -> bool:
        """Returns whether or not this directory record has one or more system use entries that have the given
        signature."""
        return signature.value in self._system_use_entries

    def iterdir(self) -> Iterator[SystemUseSharingProtocolDirectoryRecord]:
        """We know that iterdir() will instantiate the most specific type of DirectoryRecord (or subclass) possible, so
        we also know that this class will produce SystemUseSharingProtocolDirectoryRecord instances or a subclass of it.
        We type hint accordingly to make readability a little better."""
        return super().iterdir()


class RockRidgeDirectoryRecord(SystemUseSharingProtocolDirectoryRecord):
    """A python class representing an iso_directory_record of a disc that is RockRidge compliant."""

    def __init__(self, fs: RockridgeDisc, record: Instance, parent: RockRidgeDirectoryRecord | None = None):
        super().__init__(fs, record, parent)
        self._continued_name = False

        self._symlink: str | bool | None = None
        self._posix_entry: str | bool | None = None

        self._timestamps_initialized = False
        self.timestamps: dict[RockRidgeTimestampType, datetime] = dict()

        self._set_name()

        # Most occur after determining the name of this DirectoryRecord as relocated directory records have their name
        # recorded in the initially encountered directory record.
        self._resolve_relocation()

    def _set_name(self) -> None:
        """Check for alternative name system use entries and if present, use them to determine the name of this
        record."""
        if not self.has_system_use_entry(RockRidgeSignature.ALTERNATIVE_NAME):
            return

        self.name = ""
        for alternative_name_buf in self.get_system_use_entries(RockRidgeSignature.ALTERNATIVE_NAME):
            alternate_name_entry = c_rockridge.RR_NM_s(alternative_name_buf)
            self.name += alternate_name_entry.name.decode(self.fs.encoding)

    def _resolve_relocation(self) -> None:
        """Check for a child link system use entry. If this is present, we have to traverse elsewhere to obtain accurate
        information about this record, such as its actual extent and metadata."""
        if not self.has_system_use_entry(RockRidgeSignature.CHILD_LINK):
            return

        initial_name = self.name

        child_link_buf = next(self.get_system_use_entries(RockRidgeSignature.CHILD_LINK))
        child_location_entry = c_rockridge.RR_CL_s(child_link_buf)

        # Re-instantiate based on a new directory record, effectively overwriting the properties of 'this'.
        self.fs.fh.seek(self.fs.logical_block_size * child_location_entry.location)
        record = c_iso.iso_directory_record(self.fs.fh)
        super().__init__(self.fs, record)

        # Initializing the parent class causes the name property to be overwritten. However, the 'old' directory record
        # actually held the correct name. Thus we restore our name property to the old value
        self.name = initial_name

    def _resolve_timestamps(self) -> None:
        """Check for a timestamp system use entry. If present, we can use it to get more timestamp information about
        this record than we would have with base ISO 9660."""
        self._timestamps_initialized = True
        if not self.has_system_use_entry(RockRidgeSignature.TIMESTAMPS):
            return

        tf_buf = next(self.get_system_use_entries(RockRidgeSignature.TIMESTAMPS))
        timestamps_metadata = c_rockridge.RR_TF_s(tf_buf[: len(c_rockridge.RR_TF_s)])
        timestamps_values = tf_buf[len(c_rockridge.RR_TF_s) :]

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
        gaps = dict()
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

            # TODO: This works because the timestamp structure of Rockridge and the timestamp structure of ISO9660 have
            # the same property names. This is not ideal, but it works for now.
            timestamp = parse_iso9660_timestamp(timestamp)

            timestamp_type = RockRidgeTimestampType(effective_index)
            self.timestamps[timestamp_type] = timestamp

            effective_index += 1
            timestamp_index += 1

    def _resolve_symlink(self) -> None:
        """Check for a symlink system use entry. If so, this record represents a symlink, and we need to parse the
        symlink system use entries to determine where this symlink is pointing to."""
        if not self.has_system_use_entry(RockRidgeSignature.SYMLINK):
            self._symlink = False
            return

        self._symlink = ""
        for symlink_buf in self.get_system_use_entries(RockRidgeSignature.SYMLINK):
            entry = c_rockridge.RR_SL_s(symlink_buf)
            offset = 0
            while offset < len(entry.components):
                component = c_rockridge.SL_component(entry.components[offset:])
                offset += len(component)
                if component.flags.parent:
                    self._symlink += "../"
                    continue
                if component.flags.root:
                    self._symlink = "/" + self._symlink
                    continue
                if component.flags.current:
                    self._symlink += "./"
                    continue
                self._symlink += component.content.decode()
                if offset < len(entry.components) and not component.flags._continue:
                    # A new component will follow after this one
                    self._symlink += "/"

    def _resolve_posix(self) -> None:
        """Check for a posix system use entry. If present, we can get additional POSIX information about this record."""
        if not self.has_system_use_entry(RockRidgeSignature.POSIX):
            self._posix_entry = False
            return
        posix_buf = next(self.get_system_use_entries(RockRidgeSignature.POSIX))
        self._posix_entry = c_rockridge.RR_PX_s(posix_buf)

    def is_symlink(self) -> bool:
        """Returns whether this directory record represents a symlink."""
        if self._symlink is None:
            # We don't know yet whether we are a symlink or not
            self._resolve_symlink()
        return self._symlink is not False

    def readlink(self) -> str:
        """Returns what this symlink points to. Raises NotASymlinkError if this is not a symlink."""
        if not self.is_symlink():
            raise NotASymlinkError
        return self._symlink

    def iterdir(self) -> Iterator[RockRidgeDirectoryRecord]:
        for record in super().iterdir():
            if record.has_system_use_entry(RockRidgeSignature.RELOCATED):
                # This is a relocated entry, and should instead be ignored as it doesn't 'really' live here.
                continue
            yield record

    @property
    def mtime(self) -> datetime:
        if not self._timestamps_initialized:
            self._resolve_timestamps()

        if RockRidgeTimestampType.MODIFY in self.timestamps:
            return self.timestamps[RockRidgeTimestampType.MODIFY]
        return super().mtime

    @property
    def ctime(self) -> datetime:
        if not self._timestamps_initialized:
            self._resolve_timestamps()

        if RockRidgeTimestampType.ATTRIBUTES in self.timestamps:
            return self.timestamps[RockRidgeTimestampType.ATTRIBUTES]
        return super().ctime

    @property
    def atime(self) -> datetime:
        if not self._timestamps_initialized:
            self._resolve_timestamps()

        if RockRidgeTimestampType.ACCESS in self.timestamps:
            return self.timestamps[RockRidgeTimestampType.ACCESS]
        return super().atime

    @property
    def mode(self) -> int:
        if self._posix_entry is None:
            self._resolve_posix()
        if self._posix_entry is not False:
            return self._posix_entry.mode
        return super().mode

    @property
    def gid(self) -> int:
        if self._posix_entry is None:
            self._resolve_posix()
        if self._posix_entry is not False:
            return self._posix_entry.uid
        return super().gid

    @property
    def uid(self) -> int:
        if self._posix_entry is None:
            self._resolve_posix()
        if self._posix_entry is not False:
            return self._posix_entry.gid
        return super().uid

    @property
    def nlinks(self) -> int:
        if self._posix_entry is None:
            self._resolve_posix()
        if self._posix_entry is not False:
            return self._posix_entry.links
        return super().nlinks

    @property
    def inode(self) -> int:
        # Rockridge Draft Version 1.12 suggests 4 bytes being dedicated to a 'serial' which would match with st_ino.
        # However, it's not there. Structure definitions in the kernel also don't have it. If someone knows where the
        # st_ino information for Rockridge is actually resided, feel free to add that functionality here. Thanks!
        return super().inode


def load_rockridge(fh: BinaryIO, base_disc: ISO9660Disc) -> RockridgeDisc:
    """Check whether this disc is Rockridge compatible."""

    # Rockridge is an implementation of the System Use Sharing Protocol (SUSP). So we first check for SUSP
    # compatibility, then for a RockRidge identifier.

    # Skip past the root record

    fh.seek((base_disc.logical_block_size * base_disc.root_record.record.extent) + c_iso.ROOT_DIRECTORY_RECORD_LENGTH)

    if fh.read(6) != SUSP_MAGIC:
        raise NotRockridgeError

    # To determine whether or not the disc is compliant with Rockridge, we need to traverse the root record
    # while making use of the features of SUSP.

    # TODO: Merge SUSP and Rockridge into one class, considering we never use SUSP features other than for Rockridge
    rockridge_root_record = SystemUseSharingProtocolDirectoryRecord(base_disc, base_disc.root_record.record)

    # From System Use Sharing Protocol documentation per the Extensions Reference record location:
    # This System Use Entry shall appear in the System Use Area of the first ("." or (00))
    # Directory Record of the root directory of the Directory Hierarchy in which the extension
    # specification to which this "ER" System Use Entry refers is used.
    first_directory_record = next(rockridge_root_record.iterdir())

    if first_directory_record.has_system_use_entry(SystemUseSignature.EXTENSIONS_REFERENCE):
        # We can use this to determine what extension is being used that uses SUSP.
        extensions_reference_buf = next(
            first_directory_record.get_system_use_entries(SystemUseSignature.EXTENSIONS_REFERENCE)
        )
        extensions_reference_entry = c_rockridge.SU_ER_s(extensions_reference_buf)
        identifier = extensions_reference_entry.identifier
        if identifier in ROCKRIDGE_MAGICS:
            return RockridgeDisc(fh, base_disc.primary_volume, "utf-8")
        else:
            log.error("Encountered SUSP-compliant disc but could not detect Rockridge: %s", identifier)
            raise NotRockridgeError
    else:
        log.error("Encountered SUSP-compliant disc but could not detect Rockridge.")
        raise NotRockridgeError
