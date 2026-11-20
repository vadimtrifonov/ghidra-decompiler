"""What a file is: its contents' hash, its version, the name of its tree's folder, and whether its code can be read."""

import hashlib
import math
import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .windows import version_resource

# Bits per byte. x64 code measures about 6, and encrypted or compressed bytes close to 8.
ENCRYPTED_ENTROPY = 7.0
_ENTROPY_SAMPLE = (64, 4096)
_EXECUTABLE_SECTION = 0x20000000


@dataclass(frozen=True)
class Identity:
    source: Path
    sha256: str
    version: str | None

    @property
    def key(self):
        """The part of the folder name that decides which tree belongs to the file."""
        return self.sha256[:12]

    @property
    def name(self):
        return "-".join(part for part in (self.source.name, self.version, self.key) if part)


def version_label(text, numeric):
    """Reduce a FileVersion string to its leading dotted number; fall back to the numeric version."""
    if match := re.match(r"\d+(?:\s*[.,]\s*\d+)*", (text or "").strip()):
        return re.sub(r"\s*[.,]\s*", ".", match[0])
    return numeric


def _is_x64_pe(file):
    head = file.read(0x40)
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    file.seek(struct.unpack_from("<I", head, 0x3C)[0])
    nt = file.read(26)
    if len(nt) < 26 or nt[:4] != b"PE\0\0":
        return False
    machine, optional_magic = struct.unpack_from("<H", nt, 4)[0], struct.unpack_from("<H", nt, 24)[0]
    return machine == 0x8664 and optional_magic == 0x20B


def _sample(file, offset, size):
    """Read a small range whole, and evenly spaced blocks of a large one."""
    blocks, block = _ENTROPY_SAMPLE
    if size <= blocks * block:
        starts, block = [0], size
    else:
        step = (size - block) // (blocks - 1)
        starts = [index * step for index in range(blocks)]
    parts = []
    for start in starts:
        file.seek(offset + start)
        parts.append(file.read(block))
    return b"".join(parts)


def encrypted_code(source):
    """Say that the code of an x64 PE file looks encrypted or compressed, or return None when it looks plain.

    The measure is the byte entropy of the largest executable section.
    """
    with Path(source).open("rb") as file:
        file.seek(0x3C)
        nt = struct.unpack("<I", file.read(4))[0]
        file.seek(nt)
        header = file.read(24)
        count, optional_size = struct.unpack_from("<H", header, 6)[0], struct.unpack_from("<H", header, 20)[0]
        file.seek(nt + 24 + optional_size)
        code = [
            (size, offset, name)
            for name, size, offset, flags in struct.iter_unpack("<8s8xII12xI", file.read(40 * count))
            if flags & _EXECUTABLE_SECTION and size
        ]
        if not code:
            return None
        size, offset, name = max(code)
        sample = _sample(file, offset, size)
    entropy = -sum(n / len(sample) * math.log2(n / len(sample)) for n in Counter(sample).values())
    if entropy <= ENCRYPTED_ENTROPY:
        return None
    section = name.rstrip(b"\0").decode("latin-1")
    return f"the code in {section} looks encrypted or compressed (entropy {entropy:.2f} bits per byte)"


def identify(path):
    source = Path(path).resolve(strict=True)
    with source.open("rb") as file:
        if not _is_x64_pe(file):
            raise ValueError(f"not an x64 Windows executable or DLL: {source}")
        file.seek(0)
        sha256 = hashlib.file_digest(file, "sha256").hexdigest()
    return Identity(source, sha256, version_label(*version_resource(source)))
