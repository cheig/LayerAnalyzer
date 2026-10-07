#!/usr/bin/env python3
"""Downscale a PNG screenshot by an integer factor, dependency-free.

The docs comparison pages embed screenshots as base64, and a full 1200x2670
device capture is ~300KB each -- four of them make a page nobody wants to open.
``png_probe`` already carries a small PNG decoder; this reuses it, box-filters
each ``factor x factor`` block, and writes a PNG back out with a fresh zlib
stream (filter type 0, one IDAT).

Usage::

    python tools/png_resize.py shot.png -o small.png -f 3
    python tools/png_resize.py shot.png --factor 3 --base64 > shot.b64
"""

from __future__ import annotations

import argparse
import base64
import sys
import zlib

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("\\", 1)[0])

from png_probe import Png  # noqa: E402  (path set above)


def downsample(img: Png, factor: int) -> tuple[int, int, bytes]:
    """Box-filter into a new RGB raster, returning (width, height, rgb bytes)."""
    out_w = max(1, img.width // factor)
    out_h = max(1, img.height // factor)
    src = img.pixels
    channels = img.channels
    stride = img.width * channels
    out = bytearray(out_w * out_h * 3)
    area = factor * factor
    for oy in range(out_h):
        y0 = oy * factor
        for ox in range(out_w):
            x0 = ox * factor
            r = g = b = 0
            for dy in range(factor):
                row = (y0 + dy) * stride
                for dx in range(factor):
                    o = row + (x0 + dx) * channels
                    r += src[o]
                    g += src[o + 1]
                    b += src[o + 2]
            o = (oy * out_w + ox) * 3
            out[o] = r // area
            out[o + 1] = g // area
            out[o + 2] = b // area
    return out_w, out_h, bytes(out)


def encode_png(width: int, height: int, rgb: bytes) -> bytes:
    """Write an 8-bit truecolour PNG with every scanline using filter 0."""
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        raw += rgb[y * stride : (y + 1) * stride]

    def chunk(ctype: bytes, body: bytes) -> bytes:
        return (
            len(body).to_bytes(4, "big")
            + ctype
            + body
            + zlib.crc32(ctype + body).to_bytes(4, "big")
        )

    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("png")
    ap.add_argument("-o", "--out")
    ap.add_argument("-f", "--factor", type=int, default=3)
    ap.add_argument("--base64", action="store_true")
    args = ap.parse_args(argv)

    img = Png(args.png)
    w, h, rgb = downsample(img, args.factor)
    data = encode_png(w, h, rgb)
    if args.base64:
        sys.stdout.write(base64.b64encode(data).decode())
    elif args.out:
        open(args.out, "wb").write(data)
        print(f"{args.png} -> {args.out}  {img.width}x{img.height} -> {w}x{h}  "
              f"{len(data) // 1024}KB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
