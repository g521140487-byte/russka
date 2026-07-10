#!/usr/bin/env python3

import base64
import io
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "res" / "ruibo-logo.b64"


def resized(source: Image.Image, size: int) -> Image.Image:
    return source.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    source = Image.open(io.BytesIO(base64.b64decode(SOURCE.read_text()))).convert("RGBA")

    png_targets = {
        ROOT / "res" / "icon.png": 512,
        ROOT / "res" / "32x32.png": 32,
        ROOT / "res" / "128x128.png": 128,
        ROOT / "res" / "128x128@2x.png": 256,
        ROOT / "flutter" / "assets" / "icon.png": 512,
    }
    for path, size in png_targets.items():
        resized(source, size).save(path, format="PNG", optimize=True)

    icon_sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40),
                  (48, 48), (64, 64), (128, 128), (256, 256)]
    for path in (
        ROOT / "res" / "icon.ico",
        ROOT / "flutter" / "windows" / "runner" / "resources" / "app_icon.ico",
    ):
        source.save(path, format="ICO", sizes=icon_sizes, bitmap_format="png")

    tray_sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48)]
    source.save(ROOT / "res" / "tray-icon.ico", format="ICO",
                sizes=tray_sizes, bitmap_format="png")


if __name__ == "__main__":
    main()
