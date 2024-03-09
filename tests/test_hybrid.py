import logging
from datetime import datetime, timedelta, timezone
from typing import BinaryIO

import pytest

from dissect.disc.disc import DISC, ISOFormats
from dissect.disc.exceptions import FileNotFoundError

LONG_FILENAME = "100_character_long_filename_" + ("a" * 68) + ".txt"


logger = logging.getLogger(__name__)


@pytest.mark.parametrize("use_path_table", [False, True])
def test_hybrid(hybrid_iso: BinaryIO, use_path_table: bool, caplog) -> None:
    rockridge_fs = DISC(hybrid_iso)
    # Assert defaulting to rockridge
    assert rockridge_fs.iso_format == ISOFormats.ROCKRIDGE

    joliet_fs = DISC(hybrid_iso, preference=ISOFormats.JOLIET)

    # Assert warning raised when selecting Joliet
    assert "Treating disc as Joliet even though Rockridge is available" in caplog.text
    assert joliet_fs.iso_format == ISOFormats.JOLIET

    plain_fs = DISC(hybrid_iso, preference=ISOFormats.PLAIN)
    assert plain_fs.iso_format == ISOFormats.PLAIN

    contents = b"My full filename should be supported on Joliet"

    assert joliet_fs.get_entry(LONG_FILENAME, use_path_table).open().read() == contents
    assert joliet_fs.get_entry(LONG_FILENAME, use_path_table).open().read() == contents
    assert plain_fs.get_entry("100_CHAR.TXT", use_path_table).open().read() == contents


@pytest.mark.parametrize(
    "fs_format,expected",
    [
        (
            ISOFormats.JOLIET,
            dict(
                {
                    "/": 33,
                    "/a": 34,
                    "/a/aa": 35,
                    "/b": 36,
                }
            ),
        ),
        (
            ISOFormats.ROCKRIDGE,
            dict(
                {
                    "/": 28,
                    "/A": 30,
                    "/A/AA": 31,
                    "/B": 32,
                }
            ),
        ),
        (
            ISOFormats.PLAIN,
            dict(
                {
                    "/": 28,
                    "/A": 30,
                    "/A/AA": 31,
                    "/B": 32,
                }
            ),
        ),
    ],
)
def test_path_table(hybrid_iso: BinaryIO, fs_format: ISOFormats, expected: dict) -> None:
    fs = DISC(hybrid_iso, preference=fs_format)
    assert fs.path_table == expected


@pytest.mark.parametrize("fs_format", [ISOFormats.JOLIET, ISOFormats.ROCKRIDGE, ISOFormats.PLAIN])
def test_primary_volume_descriptor(hybrid_iso: BinaryIO, fs_format: ISOFormats):
    fs = DISC(hybrid_iso, preference=fs_format)
    assert fs.volume_name == "CDROM"
    assert fs.primary_volume.application_id.decode(fs.name_encoding).startswith("GENISOIMAGE ISO 9660")
    assert fs.primary_volume.system_id.decode(fs.name_encoding).startswith("LINUX")


@pytest.mark.parametrize("fs_format", [ISOFormats.JOLIET, ISOFormats.ROCKRIDGE, ISOFormats.PLAIN])
@pytest.mark.parametrize("use_path_table", [False, True])
def test_notfound(hybrid_iso: BinaryIO, fs_format: ISOFormats, use_path_table: bool):
    fs = DISC(hybrid_iso, preference=fs_format)
    with pytest.raises(FileNotFoundError):
        fs.get_entry("a/does_not_exists.txt", use_path_table)


@pytest.mark.parametrize(
    "fs_format,filename",
    [
        (ISOFormats.JOLIET, LONG_FILENAME),
        (ISOFormats.ROCKRIDGE, LONG_FILENAME),
        (ISOFormats.PLAIN, "100_CHAR.TXT"),
    ],
)
@pytest.mark.parametrize("use_path_table", [False, True])
def test_metadata(hybrid_iso: BinaryIO, fs_format: ISOFormats, filename: str, use_path_table: bool):
    fs = DISC(hybrid_iso, preference=fs_format)
    entry = fs.get_entry(filename, use_path_table)

    # All three properties are the same for this file, which makes it easy to test :)
    assert entry.mtime == datetime(2024, 3, 9, 12, 40, 4, tzinfo=timezone(timedelta(seconds=3600)))
    assert entry.ctime == datetime(2024, 3, 9, 12, 40, 4, tzinfo=timezone(timedelta(seconds=3600)))
    assert entry.atime == datetime(2024, 3, 9, 12, 40, 4, tzinfo=timezone(timedelta(seconds=3600)))
