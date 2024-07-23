import gzip
import os

from typing import Iterator
import pytest


def absolute_path(filename) -> str:
    return os.path.join(os.path.dirname(__file__), filename)


def gzip_file(filename) -> Iterator[gzip.GzipFile]:
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


@pytest.fixture
def udf_only_iso() -> Iterator[gzip.GzipFile]:
    # Made using https://askubuntu.com/questions/1152527/creating-a-pure-udf-iso
    yield from gzip_file("data/udf.iso.gz")


@pytest.fixture
def rockridge_joliet_iso() -> Iterator[gzip.GzipFile]:
    yield from gzip_file("data/rockridge_joliet.iso.gz")


@pytest.fixture
def hybrid_iso() -> Iterator[gzip.GzipFile]:
    yield from gzip_file("data/hybrid.iso.gz")
