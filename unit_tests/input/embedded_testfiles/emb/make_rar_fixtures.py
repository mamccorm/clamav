#!/usr/bin/env python3
# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
"""
Generate the embedded-RAR test fixtures used by unit_tests/clamscan/embedded_files_test.py.

No `rar` binary is needed: RAR 1.5-4.x "stored" archives are simple enough to
write by hand (marker block, main header, one file header + data per member,
end-of-archive block; every header carries a CRC16 = low 16 bits of CRC32).

Produces, next to the other test.png.emb-* files:

  test.png.emb-rars
      test.png followed by two valid stored RAR archives containing the
      same four test files as the ZIP/ARJ/CAB fixtures.

  test.png.emb-rar-false-positive
      test.png followed by the 7-byte RAR marker and then bytes that merely
      *look* like a main header and a file header (right block types, plausible
      sizes, but wrong CRCs) claiming a 3 GiB member. This is the shape found
      inside Go binaries, which embed the marker in their MIME-sniffing table.
      It must scan clean, even with --alert-exceeds-max.

Run from the repository root:
    python3 unit_tests/input/embedded_testfiles/emb/make_rar_fixtures.py
"""

import struct
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTFILES = HERE.parent

MARKER = b"Rar!\x1a\x07\x00"
HEAD_MAIN, HEAD_FILE, HEAD_ENDARC = 0x73, 0x74, 0x7B


def block(head_type, flags, body, good_crc=True):
    """RAR 1.5-4.x block: CRC16, type, flags, size, body."""
    head_size = 7 + len(body)
    raw = bytes([head_type]) + struct.pack("<HH", flags, head_size) + body
    crc = zlib.crc32(raw) & 0xFFFF
    if not good_crc:
        crc ^= 0x5A5A
    return struct.pack("<H", crc) + raw


def file_header(name, data, pack_size=None, unp_size=None, good_crc=True):
    pack_size = len(data) if pack_size is None else pack_size
    unp_size = len(data) if unp_size is None else unp_size
    body = struct.pack(
        "<IIBIIBBHI",
        pack_size,                    # PACK_SIZE
        unp_size,                     # UNP_SIZE
        0,                            # HOST_OS (MS-DOS)
        zlib.crc32(data) & 0xFFFFFFFF,  # FILE_CRC
        0,                            # FTIME
        29,                           # UNP_VER (2.9)
        0x30,                         # METHOD (stored)
        len(name),                    # NAME_SIZE
        0x20,                         # ATTR
    ) + name
    return block(HEAD_FILE, 0x8000, body, good_crc)  # LONG_BLOCK is always set on file headers


def stored_rar(members):
    out = MARKER + block(HEAD_MAIN, 0, struct.pack("<HI", 0, 0))
    for name, data in members:
        out += file_header(name, data) + data
    out += block(HEAD_ENDARC, 0, b"")
    return out


def main():
    png = (TESTFILES / "test.png.emb-zips").read_bytes()
    png = png[: png.index(b"PK\x03\x04")]
    assert png.endswith(b"IEND\xaeB`\x82")

    ref = lambda p: (TESTFILES / "emb" / p).read_bytes()
    rar1 = stored_rar([(b"test-file-1-1.txt", ref("1/test-file.ref")),
                       (b"test-file-1-2.txt", ref("1/test-file-2.ref"))])
    rar2 = stored_rar([(b"test-file-2-1.txt", ref("2/test-file.ref")),
                       (b"test-file-2-2.txt", ref("2/test-file-2.ref"))])
    (TESTFILES / "test.png.emb-rars").write_bytes(png + rar1 + rar2)

    bogus = (MARKER
             + block(HEAD_MAIN, 0, struct.pack("<HI", 0, 0), good_crc=False)
             + file_header(b"x", b"", pack_size=1 << 30, unp_size=3 << 30, good_crc=False)
             + b"B" * 4096)
    (TESTFILES / "test.png.emb-rar-false-positive").write_bytes(png + bogus)


if __name__ == "__main__":
    main()
