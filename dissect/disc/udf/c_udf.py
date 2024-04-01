from dissect.cstruct import cstruct

udf_def = """
#define     NSR_DESCRIPTOR_MAGIC    b"NSR02"
#define     TEA_DESCRIPTOR_MAGIC    b"TEA01"
#define     BOOT_DESCRIPTOR_MAGIC   b"BOOT2"
#define     BEA_DESCRIPTOR_MAGIC    b"BEA01"
"""

c_udf = cstruct()
c_udf.load(udf_def)

UDF_MAGICS = [
    c_udf.NSR_DESCRIPTOR_MAGIC,
    c_udf.BEA_DESCRIPTOR_MAGIC,
    c_udf.TEA_DESCRIPTOR_MAGIC,
    c_udf.BOOT_DESCRIPTOR_MAGIC,
]
