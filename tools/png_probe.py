#!/usr/bin/env python3
"""Scan a column of a PNG screenshot for colour boundaries.

The reference Android screenshots are 1200x2670 (density 480 => 3px per dp),
so a device-side layout question ("how tall did that panel end up?") can be
answered exactly instead of eyeballed off a downscaled preview. ``screencap``
without ``-p`` gives raw RGBA, but an already-saved ``.png`` only needs a
decoder, and the standard library has ``zlib`` -- so this stays dependency-free
(no Pillow on this machine).

Usage::

    python tools/png_probe.py shot.png --x 1150 --y0 2100 --y1 2620
    python tools/png_probe.py shot.png --x 600 --y0 300 --y1 700 --threshold 3

Coordinates are device pixels, matching ``screencap``. Convert a measured span
to density-independent units with ``px / 3``.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib


class Png:
    """A minimal non-interlaced 8-bit truecolour PNG."""

    def __init__(self, path: str) -> None:
        data = open(path, "rb").read()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError(f"{path}: not a PNG")
        pos = 8
        idat = bytearray()
        self.width = self.height = 0
        self.channels = 0
        while pos < len(data):
            (length,) = struct.unpack(">I", data[pos : pos + 4])
            ctype = data[pos + 4 : pos + 8]
            body = data[pos + 8 : pos + 8 + length]
            pos += 12 + length
            if ctype == b"IHDR":
                (
                    self.width,
                    self.height,
                    depth,
                    colour,
                    _compression,
                    _filter,
                    interlace,
                ) = struct.unpack(">IIBBBBB", body)
                if depth != 8 or interlace != 0:
                    raise ValueError("only 8-bit, non-interlaced PNGs are supported")
                self.channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(colour)
                if self.channels is None:
                    raise ValueError(f"unsupported colour type {colour}")
            elif ctype == b"IDAT":
                idat += body
            elif ctype == b"IEND":
                break
        self.pixels = self._unfilter(zlib.decompress(bytes(idat)))

    def _unfilter(self, raw: bytes) -> bytes:
        stride = self.width * self.channels
        out = bytearray(self.height * stride)
        prev = bytearray(stride)
        pos = 0
        for row in range(self.height):
            ftype = raw[pos]
            pos += 1
            line = bytearray(raw[pos : pos + stride])
            pos += stride
            if ftype == 1:  # Sub
                for i in range(self.channels, stride):
                    line[i] = (line[i] + line[i - self.channels]) & 0xFF
            elif ftype == 2:  # Up
                for i in range(stride):
                    line[i] = (line[i] + prev[i]) & 0xFF
            elif ftype == 3:  # Average
                for i in range(stride):
                    left = line[i - self.channels] if i >= self.channels else 0
                    line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
            elif ftype == 4:  # Paeth
                for i in range(stride):
                    a = line[i - self.channels] if i >= self.channels else 0
                    b = prev[i]
                    c = prev[i - self.channels] if i >= self.channels else 0
                    p = a + b - c
                    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                    pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                    line[i] = (line[i] + pred) & 0xFF
            out[row * stride : (row + 1) * stride] = line
            prev = line
        return bytes(out)

    def rgb(self, x: int, y: int) -> tuple[int, int, int]:
        o = (y * self.width + x) * self.channels
        return self.pixels[o], self.pixels[o + 1], self.pixels[o + 2]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("png")
    ap.add_argument("--x", type=int, required=True)
    ap.add_argument("--y0", type=int, default=0)
    ap.add_argument("--y1", type=int, default=None)
    ap.add_argument("--threshold", type=int, default=4)
    args = ap.parse_args(argv)

    img = Png(args.png)
    y1 = img.height - 1 if args.y1 is None else args.y1
    print(f"{args.png}: {img.width}x{img.height}, x={args.x}, y={args.y0}..{y1}")
    prev = None
    for y in range(args.y0, min(y1, img.height - 1) + 1):
        v = img.rgb(args.x, y)
        if prev is not None and max(abs(a - b) for a, b in zip(v, prev)) > args.threshold:
            print(f"  y={y:5d}  rgb={v}  ({y / 3:.1f}dp)")
        prev = v
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
