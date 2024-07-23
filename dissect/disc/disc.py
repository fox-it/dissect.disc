from __future__ import annotations

import logging
import os
from typing import BinaryIO

from dissect.disc.base import DiscBase, DiscBaseEntry, DiscFormat
from dissect.disc.exceptions import NotRockridgeError, NotUDFError
from dissect.disc.iso.iso9660 import load_iso9660_discs
from dissect.disc.iso.rockridge import load_rockridge
from dissect.disc.udf.udf import load_udf

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_DISC", "CRITICAL"))

DEFAULT_FORMAT_PREFERENCE_ORDER = [
    DiscFormat.UDF,
    DiscFormat.ROCKRIDGE,
    DiscFormat.JOLIET,
    DiscFormat.ISO9660,
]


class DISC:
    """Filesystem implementation for filesystems commonly encountered on optical discs.

    Currently supports ISO9660 and its common extensions Joliet and Rockridge.
    Not supported: UDF, Apple extensions of ISO9660.

    """

    def __init__(self, fh: BinaryIO, preference: DiscFormat | None = None):
        """Initialize a DISC filesystem object.

        Args:
            fh (BinaryIO): File-like object of the ISO file.
            preference (DiscFormat, optional): Preferred format to treat this disc as. When left None, the disc will be
                treated as the best available format. Defaults to None.
        """
        self.fh = fh
        self.available_formats: dict[DiscFormat, DiscBase] = dict()
        self.selected_format: DiscFormat = None

        for disc_format, disc in load_iso9660_discs(self.fh):
            self.available_formats[disc_format] = disc

        if DiscFormat.ISO9660 in self.available_formats:
            try:
                self.available_formats[DiscFormat.ROCKRIDGE] = load_rockridge(
                    fh, self.available_formats[DiscFormat.ISO9660]
                )
            except NotRockridgeError:
                pass

        try:
            self.available_formats[DiscFormat.UDF] = load_udf(fh)
        except NotUDFError:
            pass

        if bool(self.available_formats) is False:
            raise ValueError("No compatible filesystem found on disc.")

        # At this point we know with which standards this disc is compatible. We can now choose to treat the DISC based
        # on the preference variable, and we will fall back to another format if the preference is not available.
        self.select_format(preference)

        self.disc_name = self.fs.name

    @property
    def fs(self) -> DiscBase:
        """Selects the underlying filesystem object based on the selected format."""
        return self.available_formats[self.selected_format]

    def select_format(self, preference: DiscFormat | None = None) -> None:
        """Given a preference, set the filesystem format with which a given disc should be handled if available. If
        not available, fall back on a format, trying preferred formats first.
        """

        # First try the user preference
        if preference is not None and preference in self.available_formats:
            if preference == DiscFormat.JOLIET and DiscFormat.ROCKRIDGE in self.available_formats:
                # Typically when both Joliet and Rockridge are available, Rockridge holds more information.
                log.warning("Treating disc as Joliet even though Rockridge is available.")
            elif preference != DiscFormat.UDF and DiscFormat.UDF in self.available_formats:
                # UDF is the most modern standard and should be preferred over others
                log.warning("Treating disc as %s even though UDF is available.", preference.value)

            self.selected_format = preference
        else:
            # Preference is not given or not available: fall back on the best available format (by iterating through
            # them in order of preference)
            for fmt in DEFAULT_FORMAT_PREFERENCE_ORDER:
                if fmt in self.available_formats:
                    if preference is not None:
                        log.warning(
                            "%s format is not available for this disc. Falling back to %s.", preference.value, fmt.value
                        )
                    self.selected_format = fmt
                    break

        if self.selected_format is None:
            raise RuntimeError("Could not select format for disc.")

    def get(self, path: str) -> DiscBaseEntry:
        """Get a DiscBaseEntry from an absolute path."""
        return self.fs.get(path)

    @property
    def name(self) -> str:
        return self.fs.name

    @property
    def publisher(self) -> str:
        return self.fs.publisher

    @property
    def application(self) -> str:
        return self.fs.application
