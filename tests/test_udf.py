import logging
from datetime import datetime, timedelta, timezone
from typing import BinaryIO

from dissect.disc.disc import DISC, DiscFormat, log
from tests.test_iso import genisoimage_joliet_filename

log.setLevel(logging.DEBUG)
LONG_FILENAME = "long_filename_" + ("a" * 236) + ".txt"


def test_udf_only_iso(udf_only_iso: BinaryIO) -> None:
    disc = DISC(udf_only_iso)

    assert disc.selected_format == DiscFormat.UDF
    assert disc.name == "LinuxUDF"
    assert disc.application == "*Linux UDFFS"
    assert disc.publisher == "*Linux mkudffs 2.3"

    # Test deep directory hierarchy
    entry = disc.get("/1/2/3/4/5/6/7/8/9/10/test.txt")

    contents = entry.open().read()
    assert entry.name == "test.txt"
    assert contents == b"Hello World!\n"
    assert entry.mode & 0o777 == 0o644

    assert entry.mtime == datetime(2024, 7, 23, 10, 5, 41, tzinfo=timezone(timedelta(seconds=15360)))
    assert entry.atime == datetime(2024, 7, 23, 10, 5, 41, tzinfo=timezone(timedelta(seconds=15360)))
    assert entry.ctime == datetime(2024, 7, 23, 10, 5, 41, tzinfo=timezone(timedelta(seconds=15360)))
    assert entry.btime == datetime(2024, 7, 23, 10, 5, 41, tzinfo=timezone(timedelta(seconds=15360)))

    assert entry.size == 13
    assert entry.gid == 0
    assert entry.uid == 0
    assert entry.nlinks == 1

    directory = disc.get("/1/2/3/4/5/6/7/8/9/10")
    assert directory.mode & 0o777 == 0o755

    larger_file = disc.get("/dummy_larger_file.bin").open()
    bytes_read = 0
    while True:
        chunk = larger_file.read(1024)
        if not chunk:
            break
        bytes_read += len(chunk)
        assert chunk == b"\x69" * len(chunk)

    assert bytes_read == 1024 * 1024 * 10

    # Test long filenames
    long_filename_entry = disc.get(LONG_FILENAME)
    assert long_filename_entry.open().read() == b"My filename is really long!"

    # Test downwards symlinks
    symlink_downwards = disc.get("test.txt.symlink")
    assert symlink_downwards.is_symlink()
    assert symlink_downwards.readlink() == "1/2/3/4/5/6/7/8/9/10/test.txt"

    # Test upwards symlinks
    symlink_upwards = disc.get("/1/2/3/4/5/6/7/8/9/10/symlink_upwards.txt")
    assert symlink_upwards.is_symlink()
    assert symlink_upwards.readlink() == f"../../../../../../../../../../{LONG_FILENAME}"

    # Test absolute symlink
    absolute_symlink = disc.get("/absolute_symlink")
    assert absolute_symlink.is_symlink()
    assert absolute_symlink.readlink() == "/tmp/passwords.txt"


def test_hybrid_iso_udf(hybrid_iso: BinaryIO) -> None:
    disc = DISC(hybrid_iso)

    assert disc.selected_format == DiscFormat.UDF
    assert disc.name == "DISSECTGREATESTHITS"
    assert disc.application == "*genisoimage"
    assert disc.publisher == ""

    # Test deep directory hierarchy
    entry = disc.get("/1/2/3/4/5/6/7/8/9/10/test.txt")

    contents = entry.open().read()
    assert entry.name == "test.txt"
    assert contents == b"Hello World!\n"
    assert entry.mode & 0o777 == 0o444

    directory = disc.get("/1/2/3/4/5/6/7/8/9/10")
    assert directory.mode & 0o777 == 0o555

    long_filename_entry = disc.get(genisoimage_joliet_filename(LONG_FILENAME))
    assert long_filename_entry.open().read() == b"My filename is really long!"
