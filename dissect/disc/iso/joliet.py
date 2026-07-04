from __future__ import annotations

from typing import BinaryIO

from dissect.disc.iso.c_iso9660 import c_iso
from dissect.disc.iso.iso9660 import ISO9660, read_descriptors


class Joliet(ISO9660):
    """Joliet is basically ISO9660 with UTF-16-BE encoding. This class exists for clarity."""

    def __init__(self, fh: BinaryIO) -> None:
        super().__init__(fh, encoding="utf-16-be")

    def _find_primary_volume_descriptor(self) -> c_iso.iso_primary_descriptor:
        for block, descriptor in read_descriptors(self.fh):
            if descriptor.type == c_iso.ISO_VD_SUPPLEMENTARY:
                primary_volume = c_iso.iso_primary_descriptor(block)
                # Check whether system id starts with a null byte, suggesting it is UTF-16-BE encoded.
                if primary_volume.system_id[0] == 0x00:
                    return primary_volume
        else:
            raise ValueError("No Joliet primary volume descriptor found")
