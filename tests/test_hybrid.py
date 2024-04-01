import logging
from datetime import datetime, timedelta, timezone
from typing import BinaryIO

import pytest

from dissect.disc.base import DiscFormat
from dissect.disc.disc import DISC, log
from dissect.disc.exceptions import FileNotFoundError
from dissect.disc.iso.iso9660 import ISO9660Disc
from dissect.disc.iso.rockridge import RockridgeDisc

LONG_FILENAME = "100_character_long_filename_" + ("a" * 68) + ".txt"


log.setLevel(logging.DEBUG)


@pytest.mark.parametrize("use_path_table", [False, True])
def test_hybrid(hybrid_iso: BinaryIO, use_path_table: bool, caplog) -> None:
    rockridge_disc = DISC(hybrid_iso)
    rockridge_fs = rockridge_disc.fs
    # Assert defaulting to rockridge
    assert rockridge_disc.selected_format == DiscFormat.ROCKRIDGE
    assert isinstance(rockridge_fs, RockridgeDisc)

    joliet_disc = DISC(hybrid_iso, preference=DiscFormat.JOLIET)
    joliet_fs = joliet_disc.fs

    # Assert warning raised when selecting Joliet
    assert joliet_disc.selected_format == DiscFormat.JOLIET
    assert isinstance(joliet_fs, ISO9660Disc)
    assert "Treating disc as Joliet even though Rockridge is available" in caplog.text

    iso9660_disc = DISC(hybrid_iso, preference=DiscFormat.ISO9660)
    iso9660_fs = iso9660_disc.fs

    assert iso9660_disc.selected_format == DiscFormat.ISO9660
    assert isinstance(iso9660_fs, ISO9660Disc)

    contents = b"My full filename should be supported on Joliet"

    assert joliet_fs.get(LONG_FILENAME, use_path_table).open().read() == contents
    assert joliet_fs.get(LONG_FILENAME, use_path_table).open().read() == contents
    assert iso9660_fs.get("100_CHAR.TXT", use_path_table).open().read() == contents


@pytest.mark.parametrize(
    "fs_format,expected",
    [
        (
            DiscFormat.JOLIET,
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
            DiscFormat.ROCKRIDGE,
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
            DiscFormat.ISO9660,
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
def test_path_table(hybrid_iso: BinaryIO, fs_format: DiscFormat, expected: dict) -> None:
    disc = DISC(hybrid_iso, preference=fs_format)

    assert isinstance(disc.fs, ISO9660Disc)
    assert disc.fs.path_table == expected


@pytest.mark.parametrize("fs_format", [DiscFormat.JOLIET, DiscFormat.ROCKRIDGE, DiscFormat.ISO9660])
def test_primary_volume_descriptor(hybrid_iso: BinaryIO, fs_format: DiscFormat):
    disc = DISC(hybrid_iso, preference=fs_format)
    assert disc.fs.name == "CDROM"
    assert disc.fs.primary_volume.application_id.decode(disc.fs.encoding).startswith("GENISOIMAGE ISO 9660")
    assert disc.fs.primary_volume.system_id.decode(disc.fs.encoding).startswith("LINUX")


@pytest.mark.parametrize("fs_format", [DiscFormat.JOLIET, DiscFormat.ROCKRIDGE, DiscFormat.ISO9660])
@pytest.mark.parametrize("use_path_table", [False, True])
def test_notfound(hybrid_iso: BinaryIO, fs_format: DiscFormat, use_path_table: bool):
    disc = DISC(hybrid_iso, preference=fs_format)
    with pytest.raises(FileNotFoundError):
        disc.fs.get("a/does_not_exists.txt", use_path_table)


@pytest.mark.parametrize(
    "fs_format,filename",
    [
        (DiscFormat.JOLIET, LONG_FILENAME),
        (DiscFormat.ROCKRIDGE, LONG_FILENAME),
        (DiscFormat.ISO9660, "100_CHAR.TXT"),
    ],
)
@pytest.mark.parametrize("use_path_table", [False, True])
def test_metadata(hybrid_iso: BinaryIO, fs_format: DiscFormat, filename: str, use_path_table: bool):
    disc = DISC(hybrid_iso, preference=fs_format)
    entry = disc.fs.get(filename, use_path_table)

    # All three properties are the same for this file, which makes it easy to test :)
    assert entry.mtime == datetime(2024, 3, 9, 12, 40, 4, tzinfo=timezone(timedelta(seconds=3600)))
    assert entry.ctime == datetime(2024, 3, 9, 12, 40, 4, tzinfo=timezone(timedelta(seconds=3600)))
    assert entry.atime == datetime(2024, 3, 9, 12, 40, 4, tzinfo=timezone(timedelta(seconds=3600)))
