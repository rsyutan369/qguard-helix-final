"""Prepare derived image assets for the QGuard Messaging promo.

Run from the project root:  python tools/prep-images.py

Nothing here redraws or recolours the brand mark. The only change made to the
logo is an alpha feather on its outer edge, so its own pale ground can melt
into the video's canvas instead of ending in a visible square.
"""
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
IMG = ROOT / "assets" / "img"


def smoothstep(x: np.ndarray) -> np.ndarray:
    x = np.clip(x, 0.0, 1.0)
    return x * x * (3.0 - 2.0 * x)


def feather_logo() -> None:
    src = Image.open(IMG / "logo.png").convert("RGB")
    rgb = np.asarray(src).astype(np.uint8)
    h, w, _ = rgb.shape

    # Superellipse falloff: fully opaque through the artwork, fading to zero at
    # the frame edge. Exponent 4 keeps the corners generous so the hexagon
    # field around the emblem survives.
    ys = (np.arange(h) - (h - 1) / 2.0) / ((h - 1) / 2.0)
    xs = (np.arange(w) - (w - 1) / 2.0) / ((w - 1) / 2.0)
    xx, yy = np.meshgrid(xs, ys)
    r = (np.abs(xx) ** 4 + np.abs(yy) ** 4) ** 0.25
    inner, outer = 0.80, 0.995
    alpha = 1.0 - smoothstep((r - inner) / (outer - inner))

    out = np.dstack([rgb, (alpha * 255.0 + 0.5).astype(np.uint8)])
    Image.fromarray(out, "RGBA").save(IMG / "logo-feather.png", optimize=True)

    # Report the mean ground tone inside the feather band so the stage plate
    # behind the logo can be matched to it.
    band = (r > 0.70) & (r < 0.80)
    tone = rgb[band].reshape(-1, 3).mean(0)
    print("logo-feather.png written; ground tone ~", [int(round(v)) for v in tone])


def grain() -> None:
    # Deterministic film grain tile. Seeded so every render is identical.
    rng = np.random.default_rng(20261007)
    size = 512
    n = rng.normal(0.0, 1.0, (size, size))
    # Slight low-pass so the grain reads as film, not as sensor static.
    k = np.array([[1, 2, 1], [2, 4, 2], [1, 2, 1]], dtype=np.float64)
    k /= k.sum()
    padded = np.pad(n, 1, mode="wrap")
    soft = sum(
        k[dy, dx] * padded[dy : dy + size, dx : dx + size]
        for dy in range(3)
        for dx in range(3)
    )
    mix = 0.55 * n + 0.45 * soft * 2.0
    mix = (mix - mix.mean()) / mix.std()
    alpha = np.clip(np.abs(mix) * 46.0, 0, 255).astype(np.uint8)
    # Two tiles: light specks for dark scenes, dark specks for light scenes.
    for name, value in (("grain-light.png", 255), ("grain-dark.png", 12)):
        tile = np.zeros((size, size, 4), dtype=np.uint8)
        tile[..., :3] = value
        tile[..., 3] = alpha
        Image.fromarray(tile, "RGBA").save(IMG / name, optimize=True)
    print("grain tiles written")


if __name__ == "__main__":
    feather_logo()
    grain()
