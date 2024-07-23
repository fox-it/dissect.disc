from dissect.cstruct import cstruct

udf_def = """
/* ======== ECMA-167 Constants ======== */

/* Standard Identifiers (ECMA 167 2/9.1.2) */
#define     NSR_DESCRIPTOR_MAGIC    b"NSR02"
#define     TEA_DESCRIPTOR_MAGIC    b"TEA01"
#define     BOOT_DESCRIPTOR_MAGIC   b"BOOT2"
#define     BEA_DESCRIPTOR_MAGIC    b"BEA01"

/* ======== ECMA-167 Part 1: General ======== */

/* OSTA CS0 Character Set Information (ECMA 167 1/7.2.1) */
struct udf_charspec {
    uint8   charset_type;
    char    charset_info[63];
}

/* Entity Identifier (ECMA 167 1/7.4) */
struct udf_entity_id {
    uint8   flags;
    char    identifier[23];
    char    identifier_suffix[8];
}

/* Timestamp (ECMA 167 1/7.3) */
struct udf_timestamp {
    int16 type:4;
    int16 timezone:12; // Minutes from UTC, signed
    int16 year;
    uint8 month;
    uint8 day;
    uint8 hour;
    uint8 minute;
    uint8 second;
    uint8 centiseconds;
    uint8 hundreds_of_microseconds;
    uint8 microseconds;
}

/* ======== ECMA-167 Part 3: Volume Structure ======== */

/* Extent Descriptor (ECMA 167 3/7.1) */
struct udf_extent_ad {
    uint32 extent_length;
    uint32 extent_location;
}

/* Tag Identifier (ECMA 167 3/7.2.1) */
enum udf_tag_identifier : uint16 {
    PVD = 0x0001, AVDP, VDP, IUVD, PD, LVD, USD, TD, LVID,
    FSD = 0x0100, FID, AED, IE, TE, FE, EAHD, USE, SBD, PIE, EFE
};

/* Tag (ECMA 167 3/7.2) */
struct udf_tag {
    udf_tag_identifier  identifier;
    uint16              descriptor_version;
    uint8               tag_checksum;
    char                reserved;
    uint16              tag_serial_number;
    uint16              descriptor_crc;
    uint16              descriptor_crc_length;
    uint32              tag_location;
}

/* Primary Volume Descriptor (ECMA 167 3/10.1) */
struct udf_primary_volume_descriptor {
    uint32          volume_descriptor_sequence_number;
    uint32          primary_volume_descriptor_number;
    char            volume_identifier[32];
    uint16          volume_sequence_number;
    uint16          maximum_volume_sequence_number;
    uint16          interchange_level;
    uint16          maximum_interchange_level;
    uint32          character_set_list;
    uint32          maximum_character_set_list;
    char            volume_set_identifier[128];
    udf_charspec    descriptor_character_set;
    udf_charspec    explanatory_character_set;
    udf_extent_ad   volume_abstract;
    udf_extent_ad   volume_copyright_notice;
    udf_entity_id   application_identifier;
    udf_timestamp   recording_date_and_time;
    udf_entity_id   implementation_identifier;
    char            implementation_use[64];
    uint32          predecessor_volume_descriptor_sequence_location;
    uint16          flags;
    char            reserved[22];
}

/* Anchor Volume Descriptor Pointer (ECMA 167 3/10.2) */
struct udf_anchor_volume_descriptor_pointer {
    udf_tag         descriptor_tag;
    udf_extent_ad   main_volume_descriptor_sequence_extent;
    udf_extent_ad   reserve_volume_descriptor_sequence_extent;
    char            reserved[480];
}

/* Partition Descriptor (ECMA 167 3/10.5) */
struct udf_partition_descriptor {
    uint32          volume_descriptor_sequence_number;
    uint16          partition_flags;
    uint16          partition_number;
    udf_entity_id   partition_contents;
    char            partition_contents_use[128];
    uint32          access_type;
    uint32          partition_starting_location;
    uint32          partition_length;
    udf_entity_id   implementation_identifier;
    char            implementation_use[128];
    char            reserved[156];
}

/* Logical Volume Descriptor (ECMA 167 3/10.6) */
struct udf_logical_volume_descriptor {
    uint32          volume_descriptor_sequence_number;
    udf_charspec    descriptor_character_set;
    char            logical_volume_identifier[128];
    uint32          logical_block_size;
    udf_entity_id   domain_identifier;
    char            logical_volume_contents_use[16];
    uint32          map_table_length;
    uint32          number_of_partition_maps;
    udf_entity_id   implementation_identifier;
    char            implementation_use[128];
    udf_extent_ad   integrity_sequence_extent;
    char            partition_maps[512 - 424]; // 512 bytes minutes length of the other fields
}

/* Generic Partition Map (ECMA 167 3/10.7.1) */
struct udf_generic_partition_map {
    uint8  partition_map_type;
    uint8  partition_map_length;
    char  partition_mapping[partition_map_length - 2];
};

/* Partition Map Type (ECMA 167 3/10.7.1.1) */
#define GP_PARTITION_MAP_TYPE_UNDEF 0x00
#define GP_PARTITION_MAP_TYPE_1  0x01
#define GP_PARTITION_MAP_TYPE_2  0x02

/* Type 1 Partition Map (ECMA 167 3/10.7.2) */
struct udf_partition_map_type_1 {
    uint8  partition_map_type;
    uint8  partition_map_length;
    uint16 volume_sequence_number;
    uint16 partition_number;
}

/* Type 2 Partition Map (ECMA 167 3/10.7.3) */
struct udf_partition_map_type_2 {
    uint8           partition_map_type;
    uint8           partition_map_length;
    char            reserved[2];
    udf_entity_id   partition_type_identifier;
    uint16          volume_sequence_number;
    uint16          partition_number;
    char            data[partition_map_length - 40];
}

/* ======== ECMA-167 Part 4: File Structure ======== */

/* Recorded Address (ECMA 167 4/7.1) */
struct udf_lb_addr {
    uint32  logical_block_number;
    uint16  partition_reference_number;
}

/* Short Allocation Descriptor (ECMA 167 4/14.14.1) */
struct udf_short_allocation_descriptor {
        uint32  extent_length;
        uint32  extent_position; // Note inconsistency between 'position' and 'location', this is copied from the spec.
};

 /* Long Allocation Descriptor (ECMA 167 4/14.14.2) */
struct udf_long_allocation_descriptor {
    uint32      extent_length;
    udf_lb_addr extent_location;
    char        implementation_use[6];
}

/* File Set Descriptor (ECMA 167 4/14.1) */
struct udf_file_set_descriptor {
    udf_tag                         descriptor_tag;
    udf_timestamp                   recording_date_and_time;
    uint16                          interchange_level;
    uint16                          maximum_interchange_level;
    uint32                          character_set_list;
    uint32                          maximum_character_set_list;
    uint32                          file_set_number;
    uint32                          file_set_descriptor_number;
    udf_charspec                    logical_volume_identifier_character_set;
    char                            logical_volume_identifier[128];
    udf_charspec                    file_set_character_set;
    char                            file_set_identifier[32];
    char                            copyright_file_identifier[32];
    char                            abstract_file_identifier[32];
    udf_long_allocation_descriptor  root_directory_icb;
    udf_entity_id                   domain_identifier;
    udf_long_allocation_descriptor  next_extent;
    udf_long_allocation_descriptor  system_stream_directory_icb;
    char                            reserved[32];
}

/* File Identifier Descriptor (ECMA 167 4/14.4) */
struct udf_file_identifier_descriptor {
    udf_tag                         descriptor_tag;
    uint16                          file_version_number;
    uint8                           file_characteristics;
    uint8                           length_of_file_identifier;
    udf_long_allocation_descriptor  icb;
    uint16                          length_of_implementation_use;
    char                            implementation_use[length_of_implementation_use];
    char                            file_identifier[length_of_file_identifier];
}

/* Strategy Type (ECMA 167 4/14.6.2) */
enum udf_icb_strategy_type: uint16 {
    UNDEF = 0x0000, STRATEGY_1, STRATEGY_2, STRATEGY_3, STRATEGY_4
};

/* File Type (ECMA 167 4/14.6.6) */
enum udf_icb_file_type: uint8 {
    UNDEF = 0x00, USE, PIE, IE, DIRECTORY, REGULAR, BLOCK, CHAR, EA, FIFO, SOCKET, TE, SYMLINK, STREAMDIR
};

/* ICB Tag Allocation Type (ECMA 167 4/14.6.8) */
enum udf_icb_tag_allocation_type: uint16 {
    short_descriptors = 0x0000, long_descriptors, extended_descriptors, embedded  // TODO: Consider implementing the bit fields within the icb_tag_flags struct
};

/* ICB Tag Flags (ECMA 167 4/14.6.8) */
struct udf_icb_tag_flags {
    uint16  allocation_type:3;
    uint16  sort_directory:1;
    uint16  non_relocatable:1;
    uint16  archive:1;
    uint16  S_ISUID:1;
    uint16  S_ISGID:1;
    uint16  C_ISVTX:1;
    uint16  contiguous:1;
    uint16  system:1;
    uint16  transformed:1;
    uint16  multi_versions:1;
    uint16  stream:1;
    uint16  reserved:2;
};

/* ICB Tag (ECMA 167 4/14.6) */
struct udf_icb_tag {
    uint32                  prior_recorded_number_of_direct_entries;
    udf_icb_strategy_type   strategy_type;
    char                    strategy_parameter[2];
    uint16                  maximum_number_of_entries;
    char                    reserved;
    udf_icb_file_type       file_type;
    udf_lb_addr             parent_icb_location;
    udf_icb_tag_flags       flags;
}

/* File Entry (ECMA 167 4/14.9) */
struct udf_file_entry {
    udf_icb_tag                     icb_tag;
    uint32                          uid;
    uint32                          gid;
    uint32                          permissions;
    uint16                          file_link_count;
    uint8                           record_format;
    uint8                           record_display_attributes;
    uint32                          record_length;
    uint64                          information_length;
    uint64                          logical_blocks_recorded;
    udf_timestamp                   access_time;
    udf_timestamp                   modification_time;
    udf_timestamp                   attribute_time;
    uint32                          checkpoint;
    udf_long_allocation_descriptor  extended_attribute_icb;
    udf_entity_id                   implementation_identifier;
    uint64                          unique_id;
    uint32                          length_of_extended_attributes;
    uint32                          length_of_allocation_descriptors;
    char                            extended_attributes[length_of_extended_attributes];
    char                            allocation_descriptors[length_of_allocation_descriptors];
}

/* Component Type (ECMA 167 4/14.16.1.1) */
enum udf_component_type: uint8 {
    RESERVED = 0x00, ROOT, PATH_ROOT, PARENT, CURDIR, IDENTIFIER
};

/* Path Component (ECMA 167 4/14.16.1) */
struct udf_path_component {
    uint8   component_type;
    uint8   length_of_component_identifier;
    uint16  component_file_version_number;
    char    component_identifier[length_of_component_identifier];
}

/* Extended File Entry (ECMA 167 4/14.17) */
struct udf_extended_file_entry {
    udf_icb_tag                     icb_tag;
    uint32                          uid;
    uint32                          gid;
    uint32                          permissions;
    uint16                          file_link_count;
    uint8                           record_format;
    uint8                           record_display_attributes;
    uint32                          record_length;
    uint64                          information_length;
    uint64                          object_size;
    uint64                          logical_blocks_recorded;
    udf_timestamp                   access_time;
    udf_timestamp                   modification_time;
    udf_timestamp                   creation_time;
    udf_timestamp                   attribute_time;
    uint32                          checkpoint;
    char                            reserved[4];
    udf_long_allocation_descriptor  extended_attribute_icb;
    udf_long_allocation_descriptor  stream_directory_icb;
    udf_entity_id                   implementation_identifier;
    uint64                          unique_id;
    uint32                          length_of_extended_attributes;
    uint32                          length_of_allocation_descriptors;
    char                            extended_attributes[length_of_extended_attributes];
    char                            allocation_descriptors[length_of_allocation_descriptors];
}

/* ======== UDF ======== */

/* Virtual Partition Map (UDF 2.60 2.2.8) */
struct udf_virtual_partition_map {
    uint8       partition_map_type;
    uint8       partition_map_length;
    char        reserved[2];
    char        partition_type_identifier[32];
    uint16      volume_sequence_number;
    uint16      partition_number;
    char        reserved2[24];
}

/* Sparable Partition Map (UDF 2.60 2.2.9) */
struct udf_sparable_partition_map {
    uint8       partition_map_type;
    uint8       partition_map_length;
    char        reserved[2];
    char        partition_type_identifier[32];
    uint16      volume_sequence_number;
    uint16      partition_number;
    uint16      packet_length;
    uint8       number_of_sparing_tables;
    char        reserved2[1];
    uint32      sparing_table_size;
    char        sparing_tables[number_of_sparing_tables * 4];
}

/* Sparing Table (UDF 2.60 2.2.12) */
struct udf_sparing_table {
    udf_tag         descriptor_tag;
    udf_entity_id   sparing_table_identifier;
    uint16          reallocation_table_length;
    char            reserved[2];
    char            map_entry_buf[8 * reallocation_table_length];
}

/* Map Entry (UDF 2.60 2.2.12) */
struct udf_map_entry {
    uint32 original_location;
    uint32 mapped_location;
}
"""  # noqa: E501
c_udf = cstruct().load(udf_def)


UDF_MAGICS = [
    c_udf.NSR_DESCRIPTOR_MAGIC,
    c_udf.BEA_DESCRIPTOR_MAGIC,
    c_udf.TEA_DESCRIPTOR_MAGIC,
    c_udf.BOOT_DESCRIPTOR_MAGIC,
]
