#!/usr/bin/env python3
"""Export launcher artwork from the Android vectors. Requires resvg-py==0.5.0."""

from pathlib import Path
from xml.etree import ElementTree as ET

import resvg_py


ROOT = Path(__file__).resolve().parents[1]
DRAWABLE = ROOT / "app/src/main/res/drawable"
OUTPUT = ROOT / "artwork"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def vector(name: str, prefix: str, tint: str | None = None) -> tuple[str, str]:
    """Translate the paths and linear gradients used by these launcher vectors."""
    definitions, paths = [], []
    mapping = {
        "pathData": "d", "fillColor": "fill", "fillType": "fill-rule",
        "strokeColor": "stroke", "strokeWidth": "stroke-width",
        "strokeLineCap": "stroke-linecap", "strokeLineJoin": "stroke-linejoin",
    }
    for index, path in enumerate(ET.parse(DRAWABLE / name).getroot()):
        if path.tag != "path":
            raise ValueError(f"Unsupported vector element: {path.tag}")
        attrs = {}
        for key, value in path.attrib.items():
            key = key.removeprefix(ANDROID)
            if key not in mapping:
                raise ValueError(f"Unsupported path attribute: {key}")
            attrs[mapping[key]] = {
                "@android:color/transparent": "none", "evenOdd": "evenodd",
            }.get(value, value)
        gradient = path.find(".//gradient")
        if gradient is not None:
            values = {key.removeprefix(ANDROID): value for key, value in gradient.attrib.items()}
            if values["type"] != "linear":
                raise ValueError("Only linear gradients are supported")
            gradient_id = f"{prefix}-{index}"
            stops = [(0, values["startColor"]), (1, values["endColor"])]
            if "centerColor" in values:
                stops.insert(1, (0.5, values["centerColor"]))
            definitions.append(
                f'<linearGradient id="{gradient_id}" gradientUnits="userSpaceOnUse" '
                f'x1="{values["startX"]}" y1="{values["startY"]}" '
                f'x2="{values["endX"]}" y2="{values["endY"]}">'
                + "".join(f'<stop offset="{offset}" stop-color="{color}"/>' for offset, color in stops)
                + '</linearGradient>'
            )
            attrs["fill"] = f"url(#{gradient_id})"
        if tint:
            attrs["fill"] = tint
        paths.append(ET.tostring(ET.Element("path", attrs), encoding="unicode"))
    return "\n".join(definitions), "\n".join(paths)


def export() -> None:
    OUTPUT.mkdir(exist_ok=True)
    bg_defs, background = vector("ic_launcher_background.xml", "background")
    fg_defs, foreground = vector("ic_launcher_foreground.xml", "foreground")
    _, mono_light = vector("ic_launcher_monochrome.xml", "mono-light", "#174F46")
    _, mono_dark = vector("ic_launcher_monochrome.xml", "mono-dark", "#B0EBD5")
    definitions = bg_defs + "\n" + fg_defs
    artwork = background + "\n" + foreground
    # Android's resting adaptive mask displays the central 72 of 108 units.
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="18 18 72 72">\n'
        '<title>LayerAnalyzer</title>\n'
        '<desc>Three mint protocol layers with a routed packet trace on a deep teal field.</desc>\n'
        f'<defs>{definitions}</defs>\n{artwork}\n</svg>\n'
    )
    (OUTPUT / "launcher-icon.svg").write_text(svg, encoding="utf-8")
    (OUTPUT / "launcher-icon.png").write_bytes(resvg_py.svg_to_bytes(svg_string=svg))

    masks = {
        "rounded": '<rect x="18" y="18" width="72" height="72" rx="17"/>',
        "circle": '<circle cx="54" cy="54" r="36"/>',
        "squircle": '<path d="M54,18 C84,18 90,24 90,54 C90,84 84,90 54,90 C24,90 18,84 18,54 C18,24 24,18 54,18 Z"/>',
    }
    symbols = []
    for name, shape in masks.items():
        symbols.append(
            f'<clipPath id="mask-{name}">{shape}</clipPath>'
            f'<symbol id="{name}" viewBox="18 18 72 72">'
            f'<g clip-path="url(#mask-{name})">{artwork}</g></symbol>'
        )
    for name, color, mark in [("light", "#DAEEE2", mono_light), ("dark", "#204C43", mono_dark)]:
        symbols.append(
            f'<symbol id="{name}" viewBox="18 18 72 72"><g clip-path="url(#mask-circle)">'
            f'<path fill="{color}" d="M0,0h108v108h-108z"/>{mark}</g></symbol>'
        )

    def icon(name: str, x: int, y: int, size: int) -> str:
        return f'<use href="#{name}" x="{x}" y="{y}" width="{size}" height="{size}"/>'

    def label(text: str, x: int, y: int, size: int = 14, color: str = "#65766E", weight: int = 400) -> str:
        return f'<text x="{x}" y="{y}" font-family="Segoe UI, sans-serif" font-size="{size}" font-weight="{weight}" fill="{color}">{text}</text>'

    board = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="680" viewBox="0 0 1120 680">'
        f'<defs>{definitions}{"".join(symbols)}</defs>'
        '<rect width="1120" height="680" fill="#F5F7F2"/>'
        + label("LayerAnalyzer", 64, 88, 42, "#153C34", 600)
        + label("PROTOCOL LAYERS / CONNECTED DATA", 66, 119, 12)
        + '<path d="M64,148H1056 M454,186V574 M64,608H1056" stroke="#DCE4DC"/>'
        + icon("rounded", 64, 204, 320)
        + label("Deep teal. Clear connections.", 64, 559, 17, "#315A4C")
        + icon("circle", 510, 202, 112) + label("Circle", 544, 345)
        + icon("rounded", 700, 202, 112) + label("Rounded", 729, 345)
        + icon("squircle", 890, 202, 112) + label("Squircle", 921, 345)
        + icon("light", 510, 417, 112) + label("Themed / light", 523, 560)
        + icon("dark", 700, 417, 112) + label("Themed / dark", 713, 560)
        + icon("rounded", 890, 445, 48) + icon("circle", 966, 453, 32)
        + label("48 px / 32 px", 907, 560)
        + label("LAYERANALYZER / LAUNCHER ICON", 64, 644, 11)
        + label("ANDROID ADAPTIVE + MONOCHROME", 815, 644, 11)
        + '</svg>'
    )
    (OUTPUT / "launcher-icon-preview.png").write_bytes(resvg_py.svg_to_bytes(svg_string=board))
    print(f"Exported SVG, 512 px PNG and preview to {OUTPUT}")


if __name__ == "__main__":
    export()
