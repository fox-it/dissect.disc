from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from io import BytesIO
from typing import BinaryIO, Iterator

from dissect.cstruct import Instance
from dissect.util.stream import RangeStream

from dissect.disc.c_iso_9660 import c_iso
from dissect.disc.c_rockridge import (
    ROCKRIDGE_MAGICS,
    SUSP_MAGIC,
    RockRidgeSignature,
    RockRidgeTimestampType,
    SystemUseSignature,
    c_rockridge,
)
from dissect.disc.c_udf import UDF_MAGICS
from dissect.disc.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_DISC", "CRITICAL"))


class ISOFormat(Enum):
    PLAIN = "plain"
    ROCKRIDGE = "rockridge"
    JOLIET = "joliet"


DEFAULT_FORMAT_PREFERENCE_ORDER = [
    ISOFormat.ROCKRIDGE,
    ISOFormat.JOLIET,
    ISOFormat.PLAIN,
]


class DISC:
    """Filesystem implementation for filesystems commonly encountered on optical discs.

    Currently supports ISO9660 and its common extensions Joliet and Rockridge.
    Not supported: UDF, Apple extensions of ISO9660.

    References:

        ISO9660:
            - http://www.idea2ic.com/File_Formats/iso9660.pdf
            - https://wiki.osdev.org/ISO_9660
            - https://pismotec.com/cfs/iso9660-1999.html

        Rockridge:
            - https://github.com/torvalds/linux/blob/master/fs/isofs/rock.h
            - https://studylib.net/doc/18849173/ieee-p1282-rock-ridge-interchange-protocol-draft
            - https://docplayer.net/29621206-Ieee-p1281-system-use-sharing-protocol-draft-standard-version-1-12-adopted.html

        Joliet:
            - https://github.com/torvalds/linux/blob/master/fs/isofs/joliet.c
            - http://littlesvr.ca/isomaster/resources/JolietSpecification.html

        UDF:
            - https://docplayer.net/237090850-Ecma-tr-universal-disk-format-udf-specification-part-3-revision-2-50-1st-edition-december-reference-number-ecma-123-2009.html

    """  # noqa: E501

    def __init__(self, fh: BinaryIO, preference: ISOFormat | None = None):
        """Initialize a DISC filesystem object.

        Args:
            fh (BinaryIO): File-like object of the ISO file.
            preference (ISOFormat, optional): Preferred format to treat this disc as. When left None, the disc will be
                treated as the best available format. Defaults to None.
        """
        self.fh = fh
        self.iso_format = ISOFormat.PLAIN
        self.name_encoding = "utf-8"

        self.volume_descriptors = []
        self._path_table: dict = None

        self.primary_volumes = {
            ISOFormat.PLAIN: None,
            ISOFormat.JOLIET: None,
            ISOFormat.ROCKRIDGE: None,
        }

        self._load_volume_descriptors()

        if self.primary_volumes[ISOFormat.PLAIN] is None:
            raise ValueError("No primary volume descriptor found.")

        # To check for Rockridge, we need to start parsing the disc as a plain ISO9660 one and then look for extended
        # attributes.
        self.logical_block_size = self.primary_volume.logical_block_size
        self._check_rockridge()

        # At this point we know with which standards this disc is compatible. We can now choose to treat the DISC based
        # on the preference variable, and we will fall back to another format if the preference is not available.
        self._select_format(preference)

        # The volume name is padded with spaces, therefore we take everything before the first 'space' character.
        self.volume_name = self.primary_volume.volume_id.decode(self.name_encoding).split()[0]

    def _load_volume_descriptors(self) -> None:
        """Load volume descriptors from the ISO file."""
        self.fh.seek(c_iso.SYSTEM_AREA_SIZE)

        while True:
            volume_descriptor_bytes = self.fh.read(2048)
            volume_descriptor = c_iso.iso_volume_descriptor(volume_descriptor_bytes)

            if volume_descriptor.id != c_iso.ISO_STANDARD_ID
                raise ValueError("Invalid volume descriptor ID")

            self.volume_descriptors.append(volume_descriptor)
            if volume_descriptor.type == c_iso.ISO_VD_END:
                # This volume descriptor signifies the end of the volume descriptor set. To check whether a disc is
                # UDF, we need to look in the bytes directly following the volume descriptor set.
                self._check_udf(self.fh.tell())
                break
            if volume_descriptor.type == c_iso.ISO_VD_PRIMARY:
                plain_primary_descriptor = c_iso.iso_primary_descriptor(volume_descriptor_bytes)
                self.primary_volumes[ISOFormat.PLAIN] = plain_primary_descriptor
                continue

            # Before the VD terminator volume, there is another one. This could possibly be a Joliet volume descriptor.
            # Re-parse as a primary volume
            primary_volume = c_iso.iso_primary_descriptor(volume_descriptor_bytes)

            # Check whether system id starts with a null byte, suggesting it is UTF-16-LE-encoded.
            if primary_volume.type == c_iso.ISO_VD_SUPPLEMENTARY and primary_volume.system_id[0] == 0x00:
                self.primary_volumes[ISOFormat.JOLIET] = primary_volume

    def _check_udf(self, volume_descriptor_end_pos: int) -> None:
        """Currently, UDF is not yet supported. We do a small check to see whether we encounter an Extended Area
        Descriptor, so we can warn the user that they are likely to run into compatibility issues"""

        # Skip one byte, which for a Extended Area Descriptor would be the 'type'
        self.fh.seek(volume_descriptor_end_pos + 1)

        # Read 5 bytes, which would be the magic bytes if an Extended Area Descriptor is present.
        possible_identifier = self.fh.read(5)
        if possible_identifier in UDF_MAGICS:
            log.error(
                "dissect.disc does not (yet) support UDF or other ECMA-167 based filesystems."
                "Errors are likely to occur."
            )

    def _check_rockridge(self) -> None:
        """Check whether this disc is Rockridge compatible."""

        # Rockridge is an implementation of the System Use Sharing Protocol (SUSP). So we first check for SUSP
        # compatibility, then for a RockRidge identifier.

        # To be able to check for the SUSP magic bytes we first need to parse the root record so we can skip past its
        # extent.
        root_record = c_iso.iso_directory_record(self.primary_volumes[ISOFormat.PLAIN].root_directory_record)

        # Skip past the root record
        self.fh.seek((self.logical_block_size * root_record.extent) + c_iso.ROOT_DIRECTORY_RECORD_LENGTH)

        if self.fh.read(6) != SUSP_MAGIC:
            return

        # To determine whether or not the disc is compliant with Rockridge, we need to traverse the root record
        # while making use of the features of SUSP.
        rockridge_root_record = SystemUseSharingProtocolDirectoryRecord(self, root_record)

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
                self.primary_volumes[ISOFormat.ROCKRIDGE] = self.primary_volumes[ISOFormat.PLAIN]
                return

        log.error("Encountered SUSP-compliant disc but could not detect Rockridge: %s", identifier)

    def _select_format(self, preference: ISOFormat | None = None) -> None:
        """Given a preference, set the filesystem format with which a given disc should be handled if available. If
        not available, fall back on a format, trying preferred formats first.
        """
        self.iso_format = None

        # First try the user preference
        if preference is not None and self.primary_volumes[preference] is not None:
            if preference == ISOFormat.JOLIET and self.primary_volumes[ISOFormat.ROCKRIDGE] is not None:
                # Typically when both Joliet and Rockridge are available, Rockridge holds more information.
                log.warning("Treating disc as Joliet even though Rockridge is available.")

            self.iso_format = preference
        else:
            # Preference is not given or not available: fall back on the best available format (by iterating through
            # them in order of preference)
            for fmt in DEFAULT_FORMAT_PREFERENCE_ORDER:
                if self.primary_volumes[fmt] is not None:
                    if preference is not None:
                        log.warning(
                            "%s format is not available for this disc. Falling back to %s.", preference.value, fmt.value
                        )
                    self.iso_format = fmt
                    break

        if self.iso_format is None:
            raise ValueError("Could not select format for disc.")

        # Now that we know how we're going to treat the disc, we re-load the root record and the logical block size.
        root_record = c_iso.iso_directory_record(self.primary_volume.root_directory_record)
        self.logical_block_size = self.primary_volume.logical_block_size
        if self.iso_format == ISOFormat.JOLIET:
            self.name_encoding = "utf-16-be"

        # Wrap the root_record in the appropriate class for the selected file format.
        self.root_record = self.make_record(root_record)

    @property
    def primary_volume(self) -> Instance:
        """Return the primary volume corresponding with the selected format to treat this disc as."""
        return self.primary_volumes[self.iso_format]

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
                entry_name = entry.name.decode(self.name_encoding)
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

    def make_record(self, record: Instance) -> DirectoryRecord:
        """Wrap a iso_directory_record structure in the appropriate python representation based on the selected format
        of this disc."""
        if self.iso_format == ISOFormat.ROCKRIDGE:
            return RockRidgeDirectoryRecord(self, record)
        return DirectoryRecord(self, record)

    def get(self, path: str, use_path_table: bool = False) -> DirectoryRecord:
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


class DirectoryRecord:
    """A Python class representing an iso_directory_record."""

    def __init__(self, disc_fs: DISC, record: Instance, parent: DirectoryRecord | None = None):
        self.fs = disc_fs
        self.record = record
        self.is_dir = bool(record.flags.Directory)
        self.parent = parent

        self.name = record.name.decode(self.fs.name_encoding, errors="ignore")
        if self.name == "\x00":
            self.name = "."
        elif self.name == "\x01":
            self.name = ".."

        if not self.is_dir:
            self.name, _, _ = self.name.partition(";")

    def iterdir(self) -> Iterator[DirectoryRecord]:
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

    def listdir(self) -> dict[str, DirectoryRecord]:
        """Return a dictionary of DirectoryRecords by name."""
        return {record.name: record for record in self.iterdir()}

    def get(self, path: str) -> DirectoryRecord:
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
        """Creation time of this directory record."""

        # Plain ISO9660 have only one timestamp associated with them.
        return parse_directory_record_datetime(self.record.date_time)

    @property
    def mtime(self) -> datetime:
        """Modification time of this directory record."""

        # Plain ISO9660 have only one timestamp associated with them.
        return parse_directory_record_datetime(self.record.date_time)

    @property
    def atime(self) -> datetime:
        """Access time of this directory record."""

        # Plain ISO9660 have only one timestamp associated with them.
        return parse_directory_record_datetime(self.record.date_time)

    def is_symlink(self) -> bool:
        """Returns whether this directory record represents a symlink."""

        # Base ISO9660 does not support symlinks.
        return False

    def readlink(self) -> str:
        """Returns what this symlink points to. Raises NotASymlinkError if this is not a symlink."""

        # Base ISO9660 does not support symlinks.
        raise NotASymlinkError()

    @property
    def mode(self) -> int:
        """Return the mode of this directory record."""

        if self.record.ext_attr_length == 0:
            return 0o644
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def uid(self) -> int:
        """Return the user ID of this directory record."""

        if self.record.ext_attr_length == 0:
            return 0
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def gid(self) -> int:
        """Return the group ID of this directory record."""

        if self.record.ext_attr_length == 0:
            return 0
        raise NotImplementedError("Extended attribute record is available but not supported")

    @property
    def nlinks(self) -> int:
        """Return the number of links to this directory record."""

        # Not supported in base ISO9660
        return 1

    @property
    def inode(self) -> int:
        """Return the inode of this directory record."""

        # Not supported in base ISO9660
        return 0


class SystemUseSharingProtocolDirectoryRecord(DirectoryRecord):
    """A python class representing an iso_directory_record with System Use Entries in its System Use Area."""

    def __init__(
        self,
        disc_fs: DISC,
        record: Instance,
        parent: SystemUseSharingProtocolDirectoryRecord | None = None,
    ) -> None:
        super().__init__(disc_fs, record, parent)
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

    def __init__(self, disc_fs: DISC, record: Instance, parent: RockRidgeDirectoryRecord | None = None):
        super().__init__(disc_fs, record, parent)
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
            self.name += alternate_name_entry.name.decode(self.fs.name_encoding)

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

            timestamp = parse_directory_record_datetime(timestamp)

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


def parse_directory_record_datetime(dt: Instance) -> datetime:
    """Parse the odd timestamp format of ISO9660. Works for both the LONG_FORM structure and the 7-byte structure."""
    tz = timezone(timedelta(minutes=dt.offset * 15))
    return datetime(
        dt.year + 1900,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
        tzinfo=tz,
    )
