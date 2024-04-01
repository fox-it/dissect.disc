import logging
from typing import BinaryIO

from dissect.disc.base import DiscBase
from dissect.disc.exceptions import NotUDFError
from dissect.disc.iso.iso9660 import ISO9660Disc
from dissect.disc.udf.c_udf import UDF_MAGICS


class UDFDisc(DiscBase):
    """A python class representing a UDF-formatted disc.

    References:
        - https://docplayer.net/237090850-Ecma-tr-universal-disk-format-udf-specification-part-3-revision-2-50-1st-edition-december-reference-number-ecma-123-2009.html
        - https://www.ecma-international.org/wp-content/uploads/ECMA-167_2nd_edition_december_1994.pdf
        - https://github.com/torvalds/linux/blob/master/fs/udf/ecma_167.h
        - http://web.archive.org/web/20060427084950/homepage.mac.com/wenguangwang/myhome/udf.html#udf-vol-struct
    """  # noqa: E501


log = logging.getLogger(__name__)


def load_udf(fh: BinaryIO, base_disc: ISO9660Disc) -> UDFDisc:
    """Currently, UDF is not yet supported. We do a small check to see whether we encounter an Extended Area
    Descriptor, so we can warn the user that they are likely to run into compatibility issues"""

    # Skip one byte, which for a Extended Area Descriptor would be the 'type'
    # TODO: Based on ECMA-167, it might be possible to recognize the Extended Area Descriptor even without the disc
    # being ISO9660 compliant.
    fh.seek(base_disc.volume_descriptor_end_pos + 1)

    # Read 5 bytes, which would be the magic bytes if an Extended Area Descriptor is present.
    possible_identifier = fh.read(5)

    if possible_identifier in UDF_MAGICS:
        log.warning(
            "dissect.disc does not (yet) support UDF or other ECMA-167 based filesystems. Errors are likely to occur."
        )

    raise NotUDFError
