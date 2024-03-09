import gzip
import os

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def gzip_file(filename):
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


@pytest.fixture
def rockridge_iso():
    yield from gzip_file("data/rockridge.iso.gz")


@pytest.fixture
def hybrid_iso():
    yield from gzip_file("data/hybrid.iso.gz")


@pytest.fixture
def udf_iso():
    yield from gzip_file("data/udf.iso.gz")
