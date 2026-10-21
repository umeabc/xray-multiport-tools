# -*- coding: utf-8 -*-
"""Generate a simple app icon (app.ico) using Pillow."""
from PIL import Image, ImageDraw

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# rounded dark background
d.rounded_rectangle([8, 8, S - 8, S - 8], radius=52, fill=(24, 32, 48, 255),
                    outline=(70, 90, 120, 255), width=6)

def thick_line(p1, p2, w, fill):
    d.line([p1, p2], fill=fill, width=w)
    r = w // 2
    for (cx, cy) in (p1, p2):
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)

# big X (two diagonals), teal gradient-ish colors
c1, c2 = (46, 204, 183, 255), (52, 152, 219, 255)
thick_line((58, 52), (198, 204), 44, c2)
thick_line((198, 52), (58, 204), 44, c1)

# three "port" dots at the bottom
for i, x in enumerate((78, 128, 178)):
    d.ellipse([x - 13, 214 - 13, x + 13, 214 + 13],
              fill=(255, 255, 255, 255) if i == 1 else (142, 168, 196, 255))

img.save(r"D:\harness\xray-multi-port-lite\app.ico",
         sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print("icon saved")
