import logging
from datetime import datetime, timedelta, timezone
from typing import BinaryIO

import pytest

from dissect.disc.base import DiscFormat
from dissect.disc.disc import DISC, log
from dissect.disc.exceptions import FileNotFoundError
from dissect.disc.iso.iso9660 import ISO9660Disc
from dissect.disc.iso.rockridge import RockridgeDisc

LONG_FILENAME = "long_filename_" + ("a" * 236) + ".txt"
LONG_FILENAME_ISO9660 = "LONG_FIL.TXT"


log.setLevel(logging.DEBUG)


def genisoimage_joliet_filename(original: str, limit: int = 128) -> str:
    # Genisoimage encodes the Joliet filenames in UTF-16 for hybrid disks, causing length limitations to be halved
    return original[: (limit // 2)]


@pytest.mark.parametrize("use_path_table", [False, True])
def test_rockridge_joliet(rockridge_joliet_iso: BinaryIO, use_path_table: bool, caplog) -> None:
    rockridge_disc = DISC(rockridge_joliet_iso)
    rockridge_fs = rockridge_disc.fs
    # Assert defaulting to rockridge
    assert rockridge_disc.selected_format == DiscFormat.ROCKRIDGE
    assert isinstance(rockridge_fs, RockridgeDisc)

    joliet_disc = DISC(rockridge_joliet_iso, preference=DiscFormat.JOLIET)
    joliet_fs = joliet_disc.fs

    # Assert warning raised when selecting Joliet
    assert joliet_disc.selected_format == DiscFormat.JOLIET
    assert isinstance(joliet_fs, ISO9660Disc)
    assert "Treating disc as Joliet even though Rockridge is available" in caplog.text

    iso9660_disc = DISC(rockridge_joliet_iso, preference=DiscFormat.ISO9660)
    iso9660_fs = iso9660_disc.fs

    assert iso9660_disc.selected_format == DiscFormat.ISO9660
    assert isinstance(iso9660_fs, ISO9660Disc)

    contents = b"My filename is really long!"

    assert rockridge_fs.get(LONG_FILENAME, use_path_table).open().read() == contents
    assert joliet_fs.get(genisoimage_joliet_filename(LONG_FILENAME), use_path_table).open().read() == contents
    assert iso9660_fs.get(LONG_FILENAME_ISO9660, use_path_table).open().read() == contents

    # Joliet and plain iso9660 do not support symlinks.
    assert rockridge_fs.get("/test.txt.symlink", use_path_table).is_symlink()
    assert not joliet_fs.get("/test.txt.symlink", use_path_table).is_symlink()
    assert not iso9660_fs.get("/TEST_TXT.SYM", use_path_table).is_symlink()

    assert sorted(rockridge_disc.fs.get("/").listdir().keys()) == [
        ".",
        "..",
        "1",
        LONG_FILENAME,
        "rr_moved",
        "test.txt.symlink",
    ]

    assert sorted(joliet_disc.fs.get("/").listdir().keys()) == [
        ".",
        "..",
        "1",
        genisoimage_joliet_filename(LONG_FILENAME),
        "test.txt.symlink",
    ]

    assert sorted(iso9660_disc.fs.get("/").listdir().keys()) == [
        ".",
        "..",
        "1",
        LONG_FILENAME_ISO9660,
        "RR_MOVED",
        "TEST_TXT.SYM",
    ]


@pytest.mark.parametrize("fs_format", [DiscFormat.JOLIET, DiscFormat.ROCKRIDGE, DiscFormat.ISO9660])
def test_primary_volume_descriptor(hybrid_iso: BinaryIO, fs_format: DiscFormat):
    disc = DISC(hybrid_iso, preference=fs_format)

    fs_name = "DISSECTGREATESTHITS"
    if fs_format == DiscFormat.JOLIET:
        fs_name = genisoimage_joliet_filename(fs_name, 32)
    assert disc.name == fs_name
    assert disc.application == "DISSECT.DISC"
    assert disc.publisher == "HACKSY"


@pytest.mark.parametrize("fs_format", [DiscFormat.JOLIET, DiscFormat.ROCKRIDGE, DiscFormat.ISO9660])
@pytest.mark.parametrize("use_path_table", [False, True])
def test_notfound_iso(hybrid_iso: BinaryIO, fs_format: DiscFormat, use_path_table: bool):
    disc = DISC(hybrid_iso, preference=fs_format)
    with pytest.raises(FileNotFoundError):
        disc.fs.get("1/does_not_exists.txt", use_path_table)


@pytest.mark.parametrize(
    "fs_format,filename",
    [
        (DiscFormat.JOLIET, genisoimage_joliet_filename(LONG_FILENAME)),
        (DiscFormat.ROCKRIDGE, LONG_FILENAME),
        (DiscFormat.ISO9660, LONG_FILENAME_ISO9660),
    ],
)
@pytest.mark.parametrize("use_path_table", [False, True])
def test_entry_attributes(hybrid_iso: BinaryIO, fs_format: DiscFormat, filename: str, use_path_table: bool):
    disc = DISC(hybrid_iso, preference=fs_format)

    assert disc.selected_format == fs_format
    entry = disc.fs.get(filename, use_path_table)

    mtime = datetime(2024, 3, 9, 12, 25, 25, tzinfo=timezone(timedelta(seconds=3600)))
    ctime = datetime(2024, 5, 21, 20, 29, 5, tzinfo=timezone(timedelta(seconds=7200)))
    atime = datetime(2024, 7, 22, 8, 32, 25, tzinfo=timezone(timedelta(seconds=7200)))
    if fs_format != DiscFormat.ROCKRIDGE:
        # Joliet and ISO9660 do not store ctime and atime
        ctime = mtime
        atime = mtime

    # Joliet and plain iso9660 do not support file permissions and will default to 0o644.
    mode = 0o444 if fs_format == DiscFormat.ROCKRIDGE else 0o644

    assert entry.mtime == mtime
    assert entry.ctime == ctime
    assert entry.atime == atime

    assert entry.size == 27
    assert entry.gid == 0
    assert entry.uid == 0
    assert entry.nlinks == 1
    assert entry.mode & 0o777 == mode


def test_rockridge_specific_features(rockridge_joliet_iso: BinaryIO) -> None:
    disc = DISC(rockridge_joliet_iso)

    # Rockridge should be preferred over Joliet
    assert disc.selected_format == DiscFormat.ROCKRIDGE

    # Test deep directory hierarchy
    entry = disc.get("/1/2/3/4/5/6/7/8/9/10/test.txt")
    contents = entry.open().read()
    assert entry.name == "test.txt"
    assert contents == b"Hello World!\n"
    assert entry.mode & 0o777 == 0o444

    # Test long filenames
    long_filename_entry = disc.get(LONG_FILENAME)
    assert long_filename_entry.open().read() == b"My filename is really long!"

    # Test downwards symlinks
    symlink_downwards = disc.get("test.txt.symlink")
    assert symlink_downwards.is_symlink()
    assert symlink_downwards.readlink() == "1/2/3/4/5/6/7/8/9/10/test.txt"
    assert symlink_downwards.parent.get(symlink_downwards.readlink()).open().read() == b"Hello World!\n"

    # Test upwards symlinks
    symlink_upwards = disc.get("/1/2/3/4/5/6/7/8/9/10/symlink_upwards.txt")
    assert symlink_upwards.is_symlink()
    assert symlink_upwards.readlink() == f"../../../../../../../../../../{LONG_FILENAME}"
    assert symlink_upwards.parent.get(symlink_upwards.readlink()).open().read() == b"My filename is really long!"


def test_fallback_to_rockridge(rockridge_joliet_iso: BinaryIO, caplog):
    disc = DISC(rockridge_joliet_iso, preference=DiscFormat.UDF)

    assert "udf format is not available for this disc. Falling back to rockridge" in caplog.text
    assert disc.selected_format == DiscFormat.ROCKRIDGE
