from datetime import datetime, timedelta, timezone
from typing import BinaryIO

from dissect.disc.disc import DISC, ISOFormat

LONG_FILENAME = "long_filename_" + ("a" * 236) + ".txt"


def test_rockridge(rockridge_iso: BinaryIO) -> None:
    fs = DISC(rockridge_iso)

    assert fs.iso_format == ISOFormat.ROCKRIDGE

    # Test deep directory hierarchy
    entry = fs.get("/1/2/3/4/5/6/7/8/9/10/test.txt")
    contents = entry.open().read()
    assert entry.name == "test.txt"
    assert contents == b"Hello World!\n"

    # Test posix attributes
    assert entry.mode & 0o777 == 0o444
    assert entry.mtime == datetime(2024, 3, 8, 17, 44, 8, tzinfo=timezone(timedelta(seconds=3600)))
    assert entry.ctime == datetime(2024, 3, 8, 17, 44, 8, tzinfo=timezone(timedelta(seconds=3600)))
    assert entry.atime == datetime(2024, 3, 8, 17, 44, 54, tzinfo=timezone(timedelta(seconds=3600)))

    assert entry.gid == 0
    assert entry.uid == 0
    assert entry.nlinks == 1

    # Test long filenames
    long_filename_entry = fs.get(LONG_FILENAME)
    assert long_filename_entry.open().read() == b"My filename is really long!"

    # Test downwards symlinks
    symlink_downwards = fs.get("test.txt.symlink")
    assert symlink_downwards.is_symlink()
    assert symlink_downwards.readlink() == "1/2/3/4/5/6/7/8/9/10/test.txt"
    assert symlink_downwards.parent.get(symlink_downwards.readlink()).open().read() == b"Hello World!\n"

    # Test upwards symlinks
    symlink_upwards = fs.get("/1/2/3/4/5/6/7/8/9/10/symlink_upwards.txt")
    assert symlink_upwards.is_symlink()
    assert symlink_upwards.readlink() == f"../../../../../../../../../../{LONG_FILENAME}"
    assert symlink_upwards.parent.get(symlink_upwards.readlink()).open().read() == b"My filename is really long!"


def test_fallback(rockridge_iso: BinaryIO, caplog):
    fs = DISC(rockridge_iso, preference=ISOFormat.JOLIET)

    assert "joliet format is not available for this disc. Falling back to rockridge" in caplog.text
    assert fs.iso_format == ISOFormat.ROCKRIDGE
