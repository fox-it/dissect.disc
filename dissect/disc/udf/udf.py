from __future__ import annotations

import logging
import stat
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import MappingStream, RangeStream

from dissect.disc.base import BaseDisc, BaseEntry
from dissect.disc.exception import (
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.disc.udf.c_udf import c_udf

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import NoReturn
log = logging.getLogger(__name__)

SECTOR_SIZES = [
    2048,  # Put 2048 first as this will most often be the case
    4096,
    1024,
    512,
]

AVDP_SECTOR = 256


class UDF(BaseDisc):
    """Disc implementation that is UDF compliant.

    Currently not implemented:
        - Multiple partition descriptors
        - Named streams
        - Sparable Partitions where bad sectors have been remapped
        - Metadata Partition
        - Virtual Partition

    For all of these, any ISOs containing such features would be greatly appreciated for testing.

    References:
        - https://docplayer.net/237090850-Ecma-tr-universal-disk-format-udf-specification-part-3-revision-2-50-1st-edition-december-reference-number-ecma-123-2009.html
        - https://ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
        - https://github.com/torvalds/linux/blob/master/fs/udf/ecma_167.h
        - http://web.archive.org/web/20060427084950/homepage.mac.com/wenguangwang/myhome/udf.html#udf-vol-struct
        - http://www.osta.org/specs/pdf/udf260.pdf

    Args:
        fh: File-like object of the UDF disc.
        sector_size: Sector size of the UDF disc.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.sector_size = find_udf_sector_size(fh)

        if self.sector_size is None:
            raise ValueError("Could not determine UDF sector size")

        self.logical_volume_descriptor = None
        self._physical_partition_map: dict[int, c_udf.udf_partition_descriptor] = {}
        self.partition_map: dict[int, UDFPartition] = {}

        self._load_volume_descriptors()
        self._parse_partition_map()

        self.warned_named_streams = False

        lvd_file_set_descriptor = c_udf.udf_long_allocation_descriptor(
            self.logical_volume_descriptor.logical_volume_contents_use
        )
        file_set_descriptor_buf = self._read_extent_from_long_ad(lvd_file_set_descriptor)
        root_file_descriptor = c_udf.udf_file_set_descriptor(file_set_descriptor_buf)

        self.root = self._file_entry_from_icb(root_file_descriptor.root_directory_icb, "/", "/")

    def get(self, path: str) -> UDFEntry:
        """Get a file entry by path."""
        if path == "/":
            return self.root
        return self.root.get(path)

    @property
    def name(self) -> str:
        return read_dstring(self.primary_volume_descriptor.volume_identifier)

    @property
    def application(self) -> str:
        return self.primary_volume_descriptor.implementation_identifier.identifier.decode().rstrip("\x00")

    @property
    def publisher(self) -> str:
        return self.primary_volume_descriptor.application_identifier.identifier.decode().rstrip("\x00")

    def _read_extent_from_long_ad(self, extent_ad: c_udf.udf_long_allocation_descriptor) -> bytes:
        """Read an extent from a long allocation descriptor."""
        partition = self.partition_map[extent_ad.extent_location.partition_reference_number]
        return partition.open(extent_ad.extent_location.logical_block_number, extent_ad.extent_length).read()

    def _load_volume_descriptors(self) -> None:
        """Starting from the anchor volume descriptor pointer, load all volume descriptors."""
        self.fh.seek(self.sector_size * AVDP_SECTOR)

        anchor_volume_descriptor_pointer = c_udf.udf_anchor_volume_descriptor_pointer(self.fh)
        tag_id = anchor_volume_descriptor_pointer.descriptor_tag.identifier
        if tag_id != c_udf.udf_tag_identifier.AVDP:
            raise ValueError(f"Expected AVDP, got {tag_id}")

        # Start at the Primary Volume Descriptor
        sector = anchor_volume_descriptor_pointer.main_volume_descriptor_sequence_extent.extent_location

        while True:
            # Move to the sector start
            self.fh.seek(sector * self.sector_size)
            tag = c_udf.udf_tag(self.fh)

            if tag.identifier == c_udf.udf_tag_identifier.PVD:
                self.primary_volume_descriptor = c_udf.udf_primary_volume_descriptor(self.fh)
            if tag.identifier == c_udf.udf_tag_identifier.LVD:
                self.logical_volume_descriptor = c_udf.udf_logical_volume_descriptor(self.fh)
            if tag.identifier == c_udf.udf_tag_identifier.PD:
                if len(self._physical_partition_map) > 1:
                    # Have not come across a disc with multiple partition descriptors yet.
                    raise NotImplementedError("Multiple partition descriptors are not yet supported")
                partition_descriptor = c_udf.udf_partition_descriptor(self.fh)
                self._physical_partition_map[partition_descriptor.partition_number] = partition_descriptor

            if tag.identifier == c_udf.udf_tag_identifier.TD:
                # End of volume descriptors
                break
            sector += 1

        if self.logical_volume_descriptor is None:
            raise ValueError("No Logical Volume Descriptor found")

        if not bool(self._physical_partition_map):
            raise ValueError("No Partition Descriptor found")

    def _parse_partition_map(self) -> None:
        """Parse the partition map into UDFPartition objects that provide an API to read extents from the disc."""

        partition_maps = BytesIO(self.logical_volume_descriptor.partition_maps)
        for partition_reference_number in range(self.logical_volume_descriptor.number_of_partition_maps):
            generic_partition_map = c_udf.udf_generic_partition_map(partition_maps)
            partition_map_dump = generic_partition_map.dumps()

            if generic_partition_map.partition_map_type == c_udf.GP_PARTITION_MAP_TYPE_1:
                # The most simple type of partition, which just maps a partition number to a physical partition.
                type_1_partition = c_udf.udf_partition_map_type_1(partition_map_dump)
                physical_partition = self._physical_partition_map[type_1_partition.partition_number]
                new_partition = UDFPartition(self, physical_partition)

            elif generic_partition_map.partition_map_type == c_udf.GP_PARTITION_MAP_TYPE_2:
                type_2_partition = c_udf.udf_partition_map_type_2(partition_map_dump)
                physical_partition = self._physical_partition_map[type_2_partition.partition_number]
                partition_type = type_2_partition.partition_type_identifier.identifier.decode()

                if partition_type == "*UDF Sparable Partition":
                    sparable_partition_map = c_udf.udf_sparable_partition_map(partition_map_dump)
                    new_partition = UDFSparablePartition(self, sparable_partition_map, physical_partition)
                elif partition_type == "*UDF Virtual Partition":
                    virtual_partition_map = c_udf.udf_virtual_partition_map(partition_map_dump)
                    new_partition = UDFVirtualPartition(self, virtual_partition_map, physical_partition)
                elif partition_type == "*UDF Metadata Partition":
                    new_partition = UDFMetadataPartition(self, physical_partition)
                else:
                    raise ValueError("Unknown partition type 2 identifier '%e'", partition_type)

            else:
                raise ValueError(f"Unknown partition map type {generic_partition_map.partition_map_type}")

            if partition_reference_number in self.partition_map:
                raise RuntimeError(f"Partition reference number already exists: {partition_reference_number}")

            self.partition_map[partition_reference_number] = new_partition

    def _file_entry_from_icb(
        self, icb_allocation_descriptor: c_udf.udf_long_allocation_descriptor, path: str, name: str
    ) -> UDFEntry:
        """Given an allocation descriptor for an Information Control Block, create a UDFEntry."""
        partition = self.partition_map[icb_allocation_descriptor.extent_location.partition_reference_number]
        icb_block = BytesIO(self._read_extent_from_long_ad(icb_allocation_descriptor))
        root_file_entry_tag = c_udf.udf_tag(icb_block)
        if root_file_entry_tag.identifier == c_udf.udf_tag_identifier.FE:
            root_entry = c_udf.udf_file_entry(icb_block)
        elif root_file_entry_tag.identifier == c_udf.udf_tag_identifier.EFE:
            root_entry = c_udf.udf_extended_file_entry(icb_block)

        return UDFEntry(self, partition, path, name, root_entry)


class UDFEntry(BaseEntry):
    fs: UDF
    entry: type[c_udf.udf_file_entry | c_udf.udf_extended_file_entry]

    def __init__(
        self,
        disc: UDF,
        partition: UDFPartition,
        path: str,
        name: str,
        entry: type[c_udf.udf_file_entry | c_udf.udf_extended_file_entry],
    ):
        super().__init__(disc, entry)

        self.disc = disc
        self.partition = partition
        self.path = path
        self.name = name
        self.entry = entry

        self.allocation_type = c_udf.udf_icb_tag_allocation_type(self.entry.icb_tag.flags.allocation_type)
        self.extents = None

    @property
    def inode(self) -> int:
        return self.entry.unique_id

    @property
    def nlinks(self) -> int:
        return self.entry.file_link_count

    @property
    def mode(self) -> int:
        # UDF stores permissions slightly differently. The special bits are stored in the ICBTag.
        # User, group and other permissions are ordered differently than in stat, so we shift & mask them.
        # Based on: https://github.com/torvalds/linux/blob/cb273eb7c8390c70a484db6c79a797e377db09b5/fs/udf/inode.c#L1639

        isuid = stat.S_ISUID if self.entry.icb_tag.flags.S_ISUID else 0
        isgid = stat.S_ISGID if self.entry.icb_tag.flags.S_ISGID else 0
        isvt = stat.S_ISVTX if self.entry.icb_tag.flags.C_ISVTX else 0

        return (
            ((self.entry.permissions) & 0o007)  # User read,write,execute
            | ((self.entry.permissions >> 2) & 0o0070)  # Group read,write,execute
            | ((self.entry.permissions >> 4) & 0o0700)  # Other read,write,execute
            | isuid
            | isgid
            | isvt
        )

    @property
    def uid(self) -> int:
        return self.entry.uid

    @property
    def gid(self) -> int:
        return self.entry.gid

    @property
    def atime(self) -> datetime:
        return parse_udf_timestamp(self.entry.access_time)

    @property
    def mtime(self) -> datetime:
        return parse_udf_timestamp(self.entry.modification_time)

    @property
    def ctime(self) -> datetime:
        return parse_udf_timestamp(self.entry.attribute_time)

    @property
    def btime(self) -> datetime:
        return parse_udf_timestamp(self.entry.creation_time)

    @property
    def size(self) -> int:
        # For extended file entries, the object size holds the sum of all information lengths of all streams of a file.
        # Currently we haven't come across ISOs with streams, so we warn if these values are not the same, indicating
        # streams are in fact available.
        if (
            isinstance(self.entry, c_udf.udf_extended_file_entry)
            and self.entry.object_size != self.entry.information_length
        ):
            if not self.disc.warned_named_streams:
                log.critical("This UDF disc contains named streams, which are not yet supported")
                self.disc.warned_named_streams = True
            return self.entry.object_size

        return self.entry.information_length

    def _load_extents(self) -> Iterator[tuple[UDFPartition, int, int]]:
        """A file entry can have multiple extents which can be found by parsing its associated allocation descriptors.
        For every extent, the partition, logical block number and length are yielded.
        """
        buf = BytesIO(self.entry.allocation_descriptors)

        if self.allocation_type == c_udf.udf_icb_tag_allocation_type.short_descriptors:
            while True:
                short_ad = c_udf.udf_short_allocation_descriptor(buf)

                # Unlike long ad's, the partition is not referenced, so we assume it's the same as this entry's.
                yield self.partition, short_ad.extent_position, short_ad.extent_length

                if buf.tell() >= self.entry.length_of_allocation_descriptors:
                    break
        elif self.allocation_type == c_udf.udf_icb_tag_allocation_type.long_descriptors:
            while True:
                long_ad = c_udf.udf_long_allocation_descriptor(buf)

                partition = self.disc.partition_map[long_ad.extent_location.partition_reference_number]
                logical_block_num = long_ad.extent_location.logical_block_number
                length = long_ad.extent_length

                yield partition, logical_block_num, length

                if buf.tell() >= self.entry.length_of_allocation_descriptors:
                    break
        else:
            raise ValueError(f"Unsupported allocation type {self.allocation_type}")

    def is_dir(self) -> bool:
        return self.entry.icb_tag.file_type == c_udf.udf_icb_file_type.DIRECTORY

    def is_symlink(self) -> bool:
        return self.entry.icb_tag.file_type == c_udf.udf_icb_file_type.SYMLINK

    def iterdir(self) -> Iterator[UDFEntry]:
        if not self.is_dir():
            raise NotADirectoryError

        # To iterate a directory, we open the stream associated with this entry and parse the file identifiers
        stream = self.open()
        first = True
        while True:
            if stream.tell() >= self.size:
                break

            descriptor = c_udf.udf_file_identifier_descriptor(stream)

            if (align := (-stream.tell() % 4)) != 0:
                stream.read(align)

            if first:
                # "First is first, last is last" - Luigi
                # First entry is the parent directory
                first = False
                continue

            identifier = read_dchars(descriptor.file_identifier)
            seperator = "/" if self.path != "/" else ""
            path = self.path + seperator + identifier

            yield self.disc._file_entry_from_icb(descriptor.icb, path, identifier)

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(self.name)

        stream = self.open()
        target = ""
        first = True
        while True:
            try:
                component = c_udf.udf_path_component(stream)
            except EOFError:
                break

            if not first:
                target += "/"
            else:
                first = False

            component_type = c_udf.udf_component_type(component.component_type)
            if component_type == c_udf.udf_component_type.PARENT:
                target += ".."
            elif component_type == c_udf.udf_component_type.CURDIR:
                target += "."
            elif component_type == c_udf.udf_component_type.IDENTIFIER:
                target += read_dchars(component.component_identifier)
            elif component_type == c_udf.udf_component_type.ROOT:
                target = "/"
                first = True
            else:
                raise NotImplementedError(f"Unsupported path component type {component_type}")

        return target

    def open(self) -> BinaryIO:
        # Contents of file is contained within the allocation descriptor.
        if self.allocation_type == c_udf.udf_icb_tag_allocation_type.embedded:
            return BytesIO(self.entry.allocation_descriptors)

        if self.extents is None:
            self.extents = list(self._load_extents())

        stream = MappingStream(size=self.size)
        offset = 0
        for partition, extent_position, extent_length in self.extents:
            stream.add(offset, extent_length, partition.open(extent_position, extent_length))
            offset += extent_length

        return stream


class UDFPartition:
    """A partition on a UDF disc that starts at a certain offset into the file handle."""

    def __init__(self, disc: UDF, physical_partition_descriptor: c_udf.udf_partition_descriptor) -> None:
        self.disc = disc
        self.physical_partition_descriptor = physical_partition_descriptor

    def open(self, logical_block_num: int, length: int) -> RangeStream:
        offset_into_fh = self.physical_partition_descriptor.partition_starting_location * self.disc.sector_size
        offset_into_partition = logical_block_num * self.disc.sector_size
        return RangeStream(self.disc.fh, offset_into_fh + offset_into_partition, length)


class UDFSparablePartition(UDFPartition):
    """On RW media, a sparable partition is used to store a sparing table to remap bad sectors."""

    # While Sparable Partitions are made when creating ISOs, remappings only occur once sectors have been written to too
    # much. An ISO in such a condition has to be ripped off a physical RW-disc that has seen a lot of use. Therefore,
    # this is untested. We parse the remapping, but as soon as a location is requested that should have been remapped,
    # we raise an error.

    def __init__(
        self,
        disc: UDF,
        sparable_partition_map: c_udf.udf_sparable_partition_map,
        physical_partition_descriptor: c_udf.udf_partition_descriptor,
    ) -> None:
        super().__init__(disc, physical_partition_descriptor)

        self.packet_length = sparable_partition_map.packet_length
        self.remappings: dict[int, int] = {}

        sparing_tables = BytesIO(sparable_partition_map.sparing_tables)
        for i in range(sparable_partition_map.number_of_sparing_tables):
            table_location = c_udf.uint32(sparing_tables)
            self.disc.fh.seek(table_location * self.disc.sector_size)
            table_buf = self.disc.fh.read(sparable_partition_map.sparing_table_size)
            sparing_table = c_udf.udf_sparing_table(table_buf)
            mappings_buf = sparing_table.map_entry_buf
            for i in range(0, len(mappings_buf), 8):
                mapping = c_udf.udf_map_entry(mappings_buf[i : i + 8])
                self.remappings[mapping.original_location] = mapping.mapped_location

    def open(self, logical_block_num: int, length: int) -> RangeStream:
        if logical_block_num in self.remappings or logical_block_num in self.remappings.values():
            logical_block_num = self.remappings[logical_block_num]
            raise NotImplementedError("Sparable Partition not yet tested: remapped position requested")
        return super().open(logical_block_num, length)


class UDFVirtualPartition(UDFPartition):
    """A virtual partition is used on write-once media and is layered on top of a physical partition. It is written to
    the disc last, and holds a virtual allocation table to re-map file entry locations."""

    def __init__(
        self,
        disc: UDF,
        virtual_partition_map: c_udf.udf_virtual_partition_map,
        physical_partition_descriptor: c_udf.udf_partition_descriptor,
    ) -> None:
        super().__init__(disc, physical_partition_descriptor)

    def open(self, logical_block_num: int, length: int) -> NoReturn:
        raise NotImplementedError("Virtual Partition not yet supported")


class UDFMetadataPartition(UDFPartition):
    """A Metadata Partition is used to store metadata such as file entries, allocation descriptors and directories. As
    they are clustered together, they are more efficient to read than from the main partition when seeks are expensive.
    """

    def __init__(self, disc: UDF, physical_partition_descriptor: c_udf.udf_partition_descriptor) -> None:
        super().__init__(disc, physical_partition_descriptor)

    def open(self, logical_block_num: int, length: int) -> NoReturn:
        raise NotImplementedError("Metadata Partition not yet supported")


def osta_compression_to_encoding(compression: int) -> str:
    """Determine the encoding of a string based on the OSTA compression algorithm byte."""
    if compression == 8:
        return "utf-8"
    if compression == 16:
        return "utf-16-be"
    raise ValueError(f"Unknown compression algorithm {compression}")


def read_dstring(dstring: bytes) -> str:
    """Parse a dstring structure into a string."""
    # A dstring has one byte for the compression algorithm, followed by the characters, and ending with a length byte.
    encoding = osta_compression_to_encoding(dstring[0])
    length = dstring[-1]
    chars = dstring[1:length]
    return chars.decode(encoding)


def read_dchars(dchars: bytes) -> str:
    """Parse a dchar structure into a string."""
    # Unlike dstrings, dchars do not have a length byte at the end
    encoding = osta_compression_to_encoding(dchars[0])
    return dchars[1:].decode(encoding)


def parse_udf_timestamp(timestamp: c_udf.udf_timestamp) -> datetime:
    """Parse the timestamp format from UDF."""
    # TODO: Microseconds
    tz = timezone(timedelta(minutes=timestamp.timezone))
    return datetime(
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
        tzinfo=tz,
    )


def find_udf_sector_size(fh: BinaryIO) -> int | None:
    """Try to find the sector size of the UDF disc by looking for the AVDP tag at various sector sizes."""
    for sector_size in SECTOR_SIZES:
        try:
            fh.seek(sector_size * AVDP_SECTOR)
            tag_buf = fh.read(16)
            if len(tag_buf) != 16:
                continue
        except EOFError:
            continue

        tag_id = c_udf.uint16(tag_buf[0:2])
        tag_location = c_udf.uint32(tag_buf[12:16])

        if tag_id == c_udf.udf_tag_identifier.AVDP and tag_location == AVDP_SECTOR:
            return sector_size

    return None


def load_udf(fh: BinaryIO) -> UDF | None:
    """Load a UDF disc if it is compatible.

    Args:
        fh: The file-like object representing the disc image.
    """
    try:
        return UDF(fh)
    except ValueError:
        return None
