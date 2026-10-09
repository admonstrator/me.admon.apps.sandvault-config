#!/usr/bin/env python3
# Draws the app icon (a vault door) and writes App/SandvaultConfig/Assets.xcassets/AppIcon.appiconset.
# Usage: python3 scripts/make-app-icon.py App/SandvaultConfig/Assets.xcassets/AppIcon.appiconset (needs Pillow).
import math, json, os, sys
from PIL import Image, ImageDraw, ImageFilter

S = 4096  # supersampled canvas, downscaled to 1024
k = S / 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

# Shadow under the body (macOS icon grid: body 824 px with ~100 px margin).
body = [int(100 * k), int(100 * k), int(924 * k), int(924 * k)]
radius = int(185 * k)
shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(shadow).rounded_rectangle([body[0], body[1] + int(12 * k), body[2], body[3] + int(12 * k)], radius, fill=(0, 0, 0, 110))
shadow = shadow.filter(ImageFilter.GaussianBlur(int(18 * k)))
img.alpha_composite(shadow)

# Body: vertical gradient, deep teal to navy.
top, bottom = (38, 110, 128), (14, 32, 52)
grad = Image.new("RGBA", (S, S))
gd = ImageDraw.Draw(grad)
for y in range(S):
    t = min(max((y - body[1]) / (body[3] - body[1]), 0), 1)
    gd.line([(0, y), (S, y)], fill=tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle(body, radius, fill=255)
img.paste(grad, (0, 0), mask)

d = ImageDraw.Draw(img)
cx, cy = S / 2, S / 2 + 6 * k

def circle(r, **kw):
    d.ellipse([cx - r, cy - r, cx + r, cy + r], **kw)

# Vault door: outer rim, door face, bolts, wheel.
circle(318 * k, fill=(222, 232, 236, 255))
circle(286 * k, fill=(176, 196, 204, 255))
circle(262 * k, fill=(206, 220, 226, 255))
for i in range(12):
    a = 2 * math.pi * i / 12
    bx, by = cx + 300 * k * math.cos(a), cy + 300 * k * math.sin(a)
    r = 11 * k
    d.ellipse([bx - r, by - r, bx + r, by + r], fill=(120, 146, 158, 255))

# Wheel: three spokes through the hub, with knobs.
spoke = (44, 84, 102, 255)
for i in range(3):
    a = math.pi / 2 + math.pi * i / 3
    dx, dy = 190 * k * math.cos(a), 190 * k * math.sin(a)
    d.line([cx - dx, cy - dy, cx + dx, cy + dy], fill=spoke, width=int(34 * k))
    for sx, sy in ((cx - dx, cy - dy), (cx + dx, cy + dy)):
        r = 34 * k
        d.ellipse([sx - r, sy - r, sx + r, sy + r], fill=spoke)
circle(112 * k, outline=spoke, width=int(30 * k))
circle(62 * k, fill=spoke)
# Small accent: the hub glints in the brand teal.
circle(26 * k, fill=(92, 196, 204, 255))

icon = img.resize((1024, 1024), Image.LANCZOS)
out = sys.argv[1]
images = []
for size in (16, 32, 128, 256, 512):
    for scale in (1, 2):
        px = size * scale
        name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
        icon.resize((px, px), Image.LANCZOS).save(os.path.join(out, name), optimize=True)
        images.append({"filename": name, "idiom": "mac", "scale": f"{scale}x", "size": f"{size}x{size}"})
with open(os.path.join(out, "Contents.json"), "w") as f:
    json.dump({"images": images, "info": {"author": "xcode", "version": 1}}, f, indent=2)
    f.write("\n")
