# -*- coding: utf-8 -*-
"""GUI 冒烟测试：打开窗口 -> 探一轮 -> 渲染 -> 自动关闭。"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import probe_gui

app = probe_gui.ProbeApp()
state = {"done": False}


def finish():
    app.var_mode.set("direct")     # 直连模式更快出结果
    app.probe_now()


def check():
    if app.rows["网页 github.com"]["state"].cget("text") not in ("-", ""):
        print("渲染完成，判定：", app.var_verdict.get())
        for name, row in app.rows.items():
            print(f"  {name:<22} 状态={row['state'].cget('text')} 耗时={row['ms'].cget('text')} "
                  f"断在={row['stage'].cget('text')} 成功率={row['rate'].cget('text')}")
        app.root.destroy()
    else:
        app.root.after(1500, check)


app.root.after(500, finish)
app.root.after(3000, check)
app.root.after(40000, app.root.destroy)   # 兜底，别卡住
app.run()
print("GUI 冒烟测试结束")
