from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.resolve() / filename


def open_file_gz(name: str) -> Iterator[gzip.GzipFile]:
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        yield fh


@pytest.fixture
def udf_only_iso() -> Iterator[gzip.GzipFile]:
    # Made using https://askubuntu.com/questions/1152527/creating-a-pure-udf-iso
    yield from open_file_gz("_data/udf.iso.gz")


@pytest.fixture
def rockridge_joliet_iso() -> Iterator[gzip.GzipFile]:
    yield from open_file_gz("_data/rockridge_joliet.iso.gz")


@pytest.fixture
def hybrid_iso() -> Iterator[gzip.GzipFile]:
    yield from open_file_gz("_data/hybrid.iso.gz")
