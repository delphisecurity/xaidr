#!/usr/bin/env python3
"""Generate TA-xaidr/static/appIcon.png and appIcon_2x.png from the source logo.

    python3 integrations/splunk/make_icons.py ~/Documents/"official logo delphi.png"

Not part of the build. The icons are committed artifacts; this script exists so
the recipe that produced them is recorded and rerunnable rather than being a
sequence of shell commands someone ran once. Requires Pillow, which is why it is
kept out of build_ta.py -- the build itself has no third-party dependencies.

Splunk wants exactly 36x36 and 72x72. It does not resize: an icon whose
dimensions are off is silently ignored rather than reported, and AppInspect has
no check for it either (it only constrains static/ to flat .png/.md/.txt), so
nothing downstream will catch a mistake here.

Two things this does that a plain resize does not:

1. **Squares the artwork, not the canvas.** The source file is already square,
   but the artwork inside it is not, and is not centred -- there is more empty
   space on the left than the right. Scaling the file as-is inherits that
   offset, and at 36px an off-centre mark is visible. The alpha bounding box is
   cropped out, then re-centred on a fresh square of transparency. Padding, not
   stretching: the aspect ratio of the artwork is preserved exactly.

2. **Resamples on premultiplied alpha.** The source's transparent pixels are
   transparent *black*, which is the setup for a dark fringe: a resampler that
   averages RGB without weighting by alpha pulls those hidden zeros into every
   edge pixel. Converting to RGBa before the resize and back after makes the
   transparent regions contribute nothing, by construction.

   Measured, so as not to overclaim: on Pillow 12.3.0 this changes nothing --
   the premultiplied and naive results for this logo are byte-identical, so
   Pillow is already handling it. The conversion is kept because it is free and
   does not depend on that remaining true across Pillow versions, not because it
   was observed to fix a fringe here. If you are comparing output against an
   older Pillow, this is the line that explains a difference.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image

#: Splunk's required in-product icon sizes. appIcon_2x is the retina variant.
SIZES = {"appIcon.png": 36, "appIcon_2x.png": 72}

#: Fraction of the artwork's long edge added as breathing room on each side, so
#: the mark does not sit flush against the tile edge.
MARGIN = 0.04


def build_square(source: Path) -> Image.Image:
    """Crop to the artwork, centre it on a square of transparency."""
    im = Image.open(source)
    if im.mode != "RGBA":
        im = im.convert("RGBA")

    bbox = im.getchannel("A").getbbox()
    if bbox is None:
        raise SystemExit(f"error: {source} is fully transparent")

    art = im.crop(bbox)
    side = round(max(art.size) * (1 + 2 * MARGIN))
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(art, ((side - art.width) // 2, (side - art.height) // 2))
    return canvas


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="source logo (PNG with alpha)")
    parser.add_argument(
        "--static-dir",
        type=Path,
        default=here / "TA-xaidr" / "static",
        help="output directory (default: TA-xaidr/static/)",
    )
    args = parser.parse_args(argv)

    square = build_square(args.source.expanduser().resolve())
    args.static_dir.mkdir(parents=True, exist_ok=True)

    for name, size in SIZES.items():
        # RGBa is Pillow's premultiplied mode; see note 2 in the module docstring.
        icon = square.convert("RGBa").resize((size, size), Image.LANCZOS)
        icon = icon.convert("RGBA")
        out = args.static_dir / name
        icon.save(out, "PNG", optimize=True)
        print(f"{out}  {icon.width}x{icon.height}  {out.stat().st_size} bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
