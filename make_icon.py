# -*- coding: utf-8 -*-
"""生成 icon.ico（32x32，纯标准库写 ICO，不依赖 Pillow）。

图案：蓝色圆形 + 白色经纬线，读作「网络/连通性」。
"""
import struct
from pathlib import Path

SIZE = 32
BG = (43, 108, 176, 255)     # BGRA
FG = (255, 255, 255, 255)
CLEAR = (0, 0, 0, 0)

px = [[CLEAR for _ in range(SIZE)] for _ in range(SIZE)]

cx = cy = (SIZE - 1) / 2
r = SIZE / 2 - 1.2
for y in range(SIZE):
    for x in range(SIZE):
        d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
        if d <= r:
            px[y][x] = BG

# 经纬线：两条横线 + 一条竖线 + 一条斜线
def hline(yy, x0, x1, color=FG):
    for xx in range(x0, x1 + 1):
        if 0 <= xx < SIZE:
            px[yy][xx] = color

def vline(xx, y0, y1, color=FG):
    for yy in range(y0, y1 + 1):
        if 0 <= yy < SIZE:
            px[yy][xx] = color

hline(14, 9, 22)
hline(17, 7, 24)
vline(16, 5, 26)
for i in range(9):                       # 斜线（纬线感）
    vline(9 + i, 11 + i // 3, 21 - i // 3)

# ICO：ICONDIR + ICONDIRENTRY + BMP(BITMAPINFOHEADER + XOR + AND)
xor = b""
for y in range(SIZE - 1, -1, -1):        # BMP 自下而上
    for x in range(SIZE):
        b, g, rr, a = px[y][x]
        xor += struct.pack("4B", b, g, rr, a)

row_bytes = ((SIZE + 31) // 32) * 4      # AND 掩码每行按 4 字节对齐
and_mask = b"".join(b"\x00" * row_bytes for _ in range(SIZE))

dib = struct.pack("<IiiHHIIiiII", 40, SIZE, SIZE * 2, 1, 32, 0, len(xor) + len(and_mask),
                  0, 0, 0, 0)
image = dib + xor + and_mask
header = struct.pack("<HHH", 0, 1, 1)
entry = struct.pack("<BBBBHHII", SIZE, SIZE, 0, 0, 1, 32, len(image), 22)

out = Path(__file__).with_name("icon.ico")
out.write_bytes(header + entry + image)
print(f"已生成 {out} ({out.stat().st_size} 字节)")
