"""Check that every installed renode core library matches the target platform."""

import os
import struct
import sys
from pathlib import Path

PLATFORM = os.environ["EXPECTED_PLATFORM"]
PREFIX = Path(os.environ.get("PREFIX") or os.environ["CONDA_PREFIX"])

ELF_MACHINE = {"linux-64": 62, "linux-aarch64": 183, "linux-ppc64le": 21}
MACHO_CPU = {"osx-64": 0x01000007, "osx-arm64": 0x0100000C}
PE_MACHINE = {"win-64": 0x8664, "win-arm64": 0xAA64}


def check(path: Path) -> str | None:
    with path.open("rb") as handle:
        head = handle.read(4096)
        if PLATFORM in ELF_MACHINE:
            if head[:4] != b"\x7fELF":
                return "not an ELF file"
            (found,) = struct.unpack_from("<H", head, 18)
            expected = ELF_MACHINE[PLATFORM]
        elif PLATFORM in MACHO_CPU:
            (magic,) = struct.unpack_from("<I", head, 0)
            if magic != 0xFEEDFACF:
                return f"not a 64-bit Mach-O file (magic {magic:#x})"
            (found,) = struct.unpack_from("<I", head, 4)
            expected = MACHO_CPU[PLATFORM]
        elif PLATFORM in PE_MACHINE:
            if head[:2] != b"MZ":
                return "not a PE file"
            (pe_offset,) = struct.unpack_from("<I", head, 0x3C)
            handle.seek(pe_offset)
            pe_head = handle.read(6)
            if pe_head[:4] != b"PE\0\0":
                return "missing PE signature"
            (found,) = struct.unpack_from("<H", pe_head, 4)
            expected = PE_MACHINE[PLATFORM]
        else:
            return f"unsupported target platform {PLATFORM}"
    if found != expected:
        return f"machine type {found:#x}, expected {expected:#x} for {PLATFORM}"
    return None


def main() -> int:
    subdir = Path("Library/bin") if PLATFORM.startswith("win") else Path("lib")
    cores = sorted((PREFIX / subdir / "renode-cores").glob("translate-*.so"))
    if len(cores) != 16:
        print(f"expected 16 core libraries, found {len(cores)}")
        return 1
    errors = [f"{core}: {err}" for core in cores if (err := check(core))]
    for error in errors:
        print(f"ARCH MISMATCH: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
