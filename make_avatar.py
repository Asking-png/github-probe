# -*- coding: utf-8 -*-
"""生成 GitHub 头像：分层探测（同心弧 = DNS/TCP/TLS/HTTP 逐层推进）+ 探针节点。

纯几何、无文字，缩到 40px 仍可辨识。
"""
from PIL import Image, ImageDraw
import math

S = 1024
img = Image.new("RGB", (S, S), "#0B1220")
d = ImageDraw.Draw(img, "RGBA")

# --- 背景：径向渐变，中心略亮 ---
cx = cy = S / 2
for r in range(int(S * 0.78), 0, -3):
    t = r / (S * 0.78)
    col = (int(11 + 16 * (1 - t)), int(18 + 26 * (1 - t)), int(32 + 40 * (1 - t)))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=col)

# --- 同心探测弧：从中心向右上方逐层张开 ---
arcs = [
    (135, "#2B6CB0", 24),
    (232, "#3182CE", 22),
    (329, "#3FA9F5", 20),
    (426, "#63D2FF", 18),
]
for rad, col, w in arcs:
    d.arc([cx - rad, cy - rad, cx + rad, cy + rad], start=-72, end=18, fill=col, width=w)

# --- 轴向辅助线（投影/坐标感）---
d.line([(cx - 430, cy), (cx + 430, cy)], fill=(255, 255, 255, 34), width=6)
d.line([(cx, cy - 430), (cx, cy + 430)], fill=(255, 255, 255, 34), width=6)

# --- 中心探针：实心圆 + 外环 ---
d.ellipse([cx - 62, cy - 62, cx + 62, cy + 62], fill="#FF5A5F")
d.ellipse([cx - 62, cy - 62, cx + 62, cy + 62], outline="#FFD1D2", width=8)
d.ellipse([cx - 24, cy - 24, cx + 24, cy + 24], fill="#FFF3F3")

# --- 沿 45° 方向三个端点（代表 5 个探测端点中的节点）---
for ang, rad, col in [(-58, 285, "#8BE9FD"), (-34, 395, "#63D2FF"), (-8, 470, "#F0F6FF")]:
    x = cx + rad * math.cos(math.radians(ang))
    y = cy + rad * math.sin(math.radians(ang))
    if 0 < x < S and 0 < y < S:
        d.ellipse([x - 15, y - 15, x + 15, y + 15], fill=col)

img.save(r"C:\Users\ASKING\WorkBuddy\2026-10-21-15-34-32\github-probe\assets\avatar.png")
img.resize((160, 160), Image.LANCZOS).save(
    r"C:\Users\ASKING\WorkBuddy\2026-10-21-15-34-32\github-probe\assets\avatar-160.png")
print("已生成 assets/avatar.png (1024) 与 avatar-160.png")
