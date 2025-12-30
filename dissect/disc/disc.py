from __future__ import annotations

import logging
import os
from typing import BinaryIO

from dissect.disc.base import BaseDisc, BaseEntry, Format
from dissect.disc.iso.iso9660 import load_iso9660
from dissect.disc.iso.joliet import load_joliet
from dissect.disc.iso.rockridge import load_rockridge
from dissect.disc.udf.udf import load_udf

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_DISC", "CRITICAL"))

DEFAULT_FORMAT_PREFERENCE_ORDER = [
    Format.UDF,
    Format.ROCKRIDGE,
    Format.JOLIET,
    Format.ISO9660,
]


class Disc:
    """Implementation for commonly encountered file systems on optical discs.

    Currently supports ISO9660 and its common extensions Joliet and RockRidge.
    Not supported: Apple extensions of ISO9660.

    Args:
        fh: File-like object of the ISO file.
        preference: Optional preferred format to treat this disc as.
                    By default, the disc will be treated with the best available format.
    """

    def __init__(self, fh: BinaryIO, preference: Format | None = None):
        self.fh = fh

        self.available: dict[Format, BaseDisc] = {}
        self.selected: Format = None

        # Try to load all supported filesystems
        # This will do some redundant parsing, but it keeps the code simple.
        for format, loader in [
            (Format.ISO9660, load_iso9660),
            (Format.JOLIET, load_joliet),
            (Format.ROCKRIDGE, load_rockridge),
            (Format.UDF, load_udf),
        ]:
            if disc := loader(fh):
                self.available[format] = disc

        if not self.available:
            raise ValueError("No compatible filesystem found on disc")

        # At this point we know with which standards this disc is compatible. We can now choose to treat the DISC based
        # on the preference variable, and we will fall back to another format if the preference is not available.
        self.select(preference)

    @property
    def fs(self) -> BaseDisc:
        """Selects the underlying filesystem object based on the selected format."""
        return self.available[self.selected]

    @property
    def name(self) -> str:
        return self.fs.name

    @property
    def publisher(self) -> str:
        return self.fs.publisher

    @property
    def application(self) -> str:
        return self.fs.application

    def select(self, preference: Format | None = None) -> None:
        """Set the filesystem format with which a given disc should be handled if available.

        Attempt a supplied preference first, and if not available, try preferred formats in order.
        """

        # First try the user preference
        if preference is not None and preference in self.available:
            if preference == Format.JOLIET and Format.ROCKRIDGE in self.available:
                # Typically when both Joliet and RockRidge are available, RockRidge holds more information.
                log.warning("Treating disc as Joliet even though RockRidge is available.")
            elif preference != Format.UDF and Format.UDF in self.available:
                # UDF is the most modern standard and should be preferred over others
                log.warning("Treating disc as %s even though UDF is available.", preference.value)

            self.selected = preference
        else:
            # Preference is not given or not available: fall back on the best available format (by iterating through
            # them in order of preference)
            for fmt in DEFAULT_FORMAT_PREFERENCE_ORDER:
                if fmt in self.available:
                    if preference is not None:
                        log.warning(
                            "%s format is not available for this disc. Falling back to %s.", preference.value, fmt.value
                        )
                    self.selected = fmt
                    break

        if self.selected is None:
            raise ValueError("Could not select format for disc")

    def get(self, path: str) -> BaseEntry:
        """Get an entry from an absolute path."""
        return self.fs.get(path)
