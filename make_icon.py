from PIL import Image, ImageDraw

SIZE = 1024
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# Rounded-square background matching the app's dark theme
pad = 40
d.rounded_rectangle(
    [pad, pad, SIZE - pad, SIZE - pad],
    radius=220,
    fill=(26, 26, 30, 255),
    outline=(60, 90, 60, 255),
    width=10,
)

# Broom handle
hx0, hy0 = 430, 160
hx1, hy1 = 620, 560
d.line([hx0, hy0, hx1, hy1], fill=(140, 110, 80, 255), width=46)
d.ellipse([hx0 - 23, hy0 - 23, hx0 + 23, hy0 + 23], fill=(140, 110, 80, 255))

# Broom head (bristles) — fan of lines from a neck point
neck = (640, 580)
bristle_color = (136, 221, 136, 255)
import math
base_angle = 60
spread = 70
n = 13
for i in range(n):
    ang = math.radians(base_angle - spread / 2 + spread * i / (n - 1))
    length = 280
    ex = neck[0] + length * math.cos(ang)
    ey = neck[1] + length * math.sin(ang)
    d.line([neck, (ex, ey)], fill=bristle_color, width=14)

# Neck band
d.rounded_rectangle([neck[0] - 34, neck[1] - 34, neck[0] + 34, neck[1] + 34],
                    radius=16, fill=(90, 150, 90, 255))

# A few sparkle marks for "clean"
def sparkle(cx, cy, s, color):
    d.line([cx - s, cy, cx + s, cy], fill=color, width=10)
    d.line([cx, cy - s, cx, cy + s], fill=color, width=10)

sparkle(330, 330, 46, (255, 255, 255, 230))
sparkle(760, 270, 30, (255, 255, 255, 180))
sparkle(820, 470, 24, (255, 255, 255, 140))

img.save("icon_source.png")
print("wrote icon_source.png")
