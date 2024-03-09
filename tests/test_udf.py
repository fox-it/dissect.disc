import logging
from typing import BinaryIO

from dissect.disc.disc import DISC, ISOFormats

logger = logging.getLogger(__name__)


def test_udf(udf_iso: BinaryIO, caplog) -> None:
    udf_fs = DISC(udf_iso)
    assert (
        "dissect.disc does not (yet) support UDF or other ECMA-167 based filesystems.Errors are likely to occur."
        in caplog.text
    )
    assert udf_fs.iso_format == ISOFormats.PLAIN
