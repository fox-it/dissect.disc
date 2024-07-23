import logging
from typing import BinaryIO

from dissect.disc.disc import DISC, DiscFormat, log

log.setLevel(logging.DEBUG)


def test_udf(hybrid_iso: BinaryIO, caplog) -> None:
    udf_fs = DISC(hybrid_iso)
    assert (
        "dissect.disc does not (yet) support UDF or other ECMA-167 based filesystems. Errors are likely to occur."
        in caplog.text
    )
    assert udf_fs.selected_format == DiscFormat.ROCKRIDGE
