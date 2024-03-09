from dissect.cstruct import cstruct

ISO_DEF = """

/* volume descriptor types */
#define ISO_VD_PRIMARY 1
#define ISO_VD_SUPPLEMENTARY 2
#define ISO_VD_END 255

#define ISO_STANDARD_ID "CD001"

#define ISOFS_BLOCK_SIZE 0x800

#define SYSTEM_AREA_SIZE ISOFS_BLOCK_SIZE * 16

#define ROOT_DIRECTORY_RECORD_LENGTH 0x22

struct iso_volume_descriptor {
    uint8_t type;
    char    id[5];
    uint8_t version;
    char    data[2041];
};

struct dec_datetime {
	char year[4];
	char month[2];
	char day[2];
	char hour[2];
	char minute[2];
	char second[2];
	char centiseconds[2];
	int8_t offset;
}

struct datetime_short {
	uint8_t	year;
    uint8_t	month;
    uint8_t	day;
    uint8_t	hour;
    uint8_t	minute;
    uint8_t	second;
    int8_t	offset;
}

struct iso_primary_descriptor {
	uint8_t         type;
    char            id[5];
    uint8_t         version;
    char            unused1;
    char            system_id[32];
    char            volume_id[32];
    char            unused2[8];
    uint32_t        volume_space_size;
    char			volume_space_size_be[4];
    char            unused3[32];
	uint16_t        volume_set_size;
	char	        volume_set_size_be[2];
	uint16_t        volume_sequence_number;
	char	        volume_sequence_number_be[2];
	uint16_t        logical_block_size;
	char	        logical_block_size_be[2];
	uint32_t        path_table_size;
	char	        path_table_size_be[4];
	uint32_t        type_l_path_table;
	uint32_t		opt_type_l_path_table;
	char	        type_m_path_table_be[4];
    char			opt_type_m_path_table_be[4];
    char			root_directory_record[ROOT_DIRECTORY_RECORD_LENGTH];
	char			volume_set_id[128];
    char			publisher_id[128];
	char			preparer_id[128];
    char			application_id[128];
	char			copy_right_file_id[37];
	char			abstract_file_id[37];
	char			bibliographic_file_id[37];
	dec_datetime	creation_date;
    dec_datetime	modification_date;
	dec_datetime	expiration_date;
    dec_datetime	effective_date;
	uint8_t			file_structure_version;
	char			unused4;
	char			application_data[512];
	char			unused5[653];
}

struct iso_directory_record_datetime {
	uint8_t			year;
	uint8_t			month;
	uint8_t			day;
	uint8_t			hour;
	uint8_t			minute;
	uint8_t			second;
	int8_t			offset;
}

struct iso_directory_record_flags {
	uint8_t           Hidden:1;
	uint8_t           Directory:1;
	uint8_t           AssociatedFile:1;
	uint8_t           ExtendedAttributeRecordContainsInformation:1;
	uint8_t           OwnerAndGroupPermissionsAreSet:1;
	uint8_t           Reserved:2;
	uint8_t           SpansMultipleExtents:1;
}

struct iso_directory_record {
	uint8_t			length;
	uint8_t			ext_attr_length;
	uint32_t		extent;
	char			extent_be[4];
	uint32_t		size;
	char			size_be[4];
    iso_directory_record_datetime			date_time;
	iso_directory_record_flags				flags;
	uint8_t			file_unit_size;
	uint8_t			interleave;
	uint16_t		volume_sequence_number;
	char			volume_sequence_number_be[2];
	uint8_t			name_len;
	char			name[name_len];
    char			system_use[length - name_len - 33];
}

struct iso_path_table_entry {
	uint8_t			directory_id_len;
	uint8_t			ext_attr_rec_len;
	uint32_t		extent_location;
    uint16_t		parent_dir_no;
    char			name[directory_id_len];
}
"""  # noqa

c_iso = cstruct()
c_iso.load(ISO_DEF)
