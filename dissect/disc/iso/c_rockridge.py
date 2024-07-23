from enum import Enum, IntEnum

from dissect.cstruct import cstruct

rockridge_def = """
struct SU_SP_s {
    char    signature[2];
    uint8_t length;
    uint8_t version;
    char    check_bytes[2];
    uint8_t len_skp;
}

struct SU_CE_s {
    char        signature[2];
    uint8_t     length;
    uint8_t     version;
    uint32_t    extent;
    char        extent_be[4];
    uint32_t    offset;
    char        offset_be[4];
    uint32_t    size;
    char        size_be[4];
};

struct SU_ER_s {
    char    signature[2];
    uint8_t length;
    uint8_t version;
    uint8_t len_id;
    uint8_t len_des;
    uint8_t len_src;
    uint8_t ext_ver;
    char    identifier[len_id];
    char    description[len_des];
    char    source[len_src];
}

struct RR_PX_s {
    char        signature[2];
    uint8_t     length;
    uint8_t     version;
    uint32_t    mode;
    char        mode_be[4];
    uint32_t    links;
    char        links_be[4];
    uint32_t    uid;
    char        uid_be[4];
    uint32_t    gid;
    char        gid_be[4];
};

struct RR_NM_s {
    char    signature[2];
    uint8_t len;
    uint8_t version;
    uint8_t _continue:1;
    uint8_t current:1;
    uint8_t parent:1;
    uint8_t reserved_one:2;
    uint8_t reserved_two:1; /* Historically, this component has contained the network node name of the current system as defined in the uname structure of POSIX:4.4.1.2. */
    uint8_t reserved_three:2;
    char    name[len - 5];
}

struct SL_component_flags {
    uint8_t _continue:1;
    uint8_t current:1;
    uint8_t parent:1;
    uint8_t root:1;
    uint8_t reserved_one:1; /* Historically, this component has referred to the directory on which the current CD-ROM volume is mounted. */
    uint8_t reserved_two:1; /* Historically, this component has contained the network node name of the current system as defined in the uname structure of POSIX:4.4.1.2. */
    uint8_t reserved:2;
}

struct SL_component {
    SL_component_flags  flags;
    uint8_t             len;
    char                content[len];
}

struct RR_SL_s {
    char    signature[2];
    uint8_t len;
    uint8_t version;
    uint8_t continue_flag:1;
    uint8_t reserved_flag_bits:7;
    char    components[len - 5];
}

struct RR_TF_s {
    char    signature[2];
    uint8_t len;
    uint8_t version;
    uint8_t CREATION:1;
    uint8_t MODIFY:1;
    uint8_t ACCESS:1;
    uint8_t ATTRIBUTES:1;
    uint8_t BACKUP:1;
    uint8_t EXPIRATION:1;
    uint8_t EFFECTIVE:1;
    uint8_t LONG_FORM:1;
}

struct RR_CL_s {
    char        signature[2];
    uint8_t     len;
    uint8_t     version;
    uint32_t    location;
    char        location_be[4];
}

struct RR_PL_s {
    char        signature[2];
    uint8_t     len;
    uint8_t     version;
    uint32_t    location;
    char        location_be[4];
}

struct rock_ridge_entry {
    char    signature[2];
    uint8_t len;
    uint8_t version;
    char    data[len - 4];
};
"""  # noqa: E501

c_rockridge = cstruct().load(rockridge_def)

SUSP_MAGIC = b"SP\x07\x01\xbe\xef"
ROCKRIDGE_MAGICS = [b"RRIP_1991A", b"IEEE_P1282", b"IEEE_1282"]


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
