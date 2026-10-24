#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub 实时探测 —— 图形面板。

用法：
    python probe_gui.py
    pythonw probe_gui.py      # 无控制台窗口
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from urllib.parse import urlsplit

from gh_probe import (DEFAULT_CONTROL, DEFAULT_TARGETS, PUBLIC_DNS, ProbeResult,
                      ProbeRunner, env_report)

BG = "#f7f7f9"
OK = "#2e7d32"
FAIL = "#c62828"
WARN = "#ef6c00"
IDLE = "#9e9e9e"


def data_dir() -> Path:
    """日志/CSV 的存放目录。

    打包成 exe 后，工作目录可能是桌面或临时目录，不能往那儿写；
    固定写到 %LOCALAPPDATA%\\GitHubProbe（脚本模式则写到脚本所在目录）。
    """
    if getattr(sys, "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        p = Path(base) / "GitHubProbe"
    else:
        p = Path(__file__).resolve().parent
    p.mkdir(parents=True, exist_ok=True)
    return p


class ProbeApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("GitHub 实时探测")
        self.root.geometry("820x560")
        self.root.configure(bg=BG)

        self.results_q: "queue.Queue[list[ProbeResult]]" = queue.Queue()
        self.stop = threading.Event()
        self.worker: threading.Thread | None = None
        self.rows: dict[str, dict] = {}
        self.runner: ProbeRunner | None = None
        self._shown: list[str] = []

        self.var_mode = tk.StringVar(value="auto")
        self.var_interval = tk.StringVar(value="10")
        self.var_beep = tk.BooleanVar(value=False)
        self.var_csv = tk.BooleanVar(value=True)
        self.var_verdict = tk.StringVar(value="未开始探测")

        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._pump()

    # ---------------- UI ----------------
    def _build(self) -> None:
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=12, pady=(10, 6))

        tk.Label(top, text="总体判定：", bg=BG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        self.lbl_verdict = tk.Label(top, textvariable=self.var_verdict, bg=BG, fg=IDLE,
                                    font=("Microsoft YaHei UI", 10, "bold"))
        self.lbl_verdict.pack(side="left")

        ctrl = tk.Frame(self.root, bg=BG)
        ctrl.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(ctrl, text="模式：", bg=BG).pack(side="left")
        for text, val in (("自动(跟随系统代理)", "auto"), ("强制直连", "direct")):
            tk.Radiobutton(ctrl, text=text, variable=self.var_mode, value=val, bg=BG,
                           command=self._on_mode_change).pack(side="left")
        tk.Label(ctrl, text="  间隔(秒)：", bg=BG).pack(side="left")
        tk.Spinbox(ctrl, from_=2, to=600, width=5, textvariable=self.var_interval).pack(side="left")
        tk.Checkbutton(ctrl, text="状态翻转时响一声", variable=self.var_beep, bg=BG).pack(side="left", padx=(10, 0))
        tk.Checkbutton(ctrl, text="记录 CSV", variable=self.var_csv, bg=BG).pack(side="left")

        btns = tk.Frame(ctrl, bg=BG)
        btns.pack(side="right")
        self.btn_start = ttk.Button(btns, text="开始探测", command=self.start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(btns, text="停止", command=self.stop_probe, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))
        ttk.Button(btns, text="立即探测一轮", command=self.probe_now).pack(side="left", padx=(6, 0))

        # 表格
        head = tk.Frame(self.root, bg="#e9e9ef")
        head.pack(fill="x", padx=12)
        for text, w in (("目标", 24), ("状态", 8), ("耗时", 10), ("断在", 10),
                        ("成功率", 10), ("连续失败", 9), ("最近成功", 14)):
            tk.Label(head, text=text, width=w, anchor="w", bg="#e9e9ef",
                     font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")

        self.table = tk.Frame(self.root, bg=BG)
        self.table.pack(fill="both", padx=12, pady=(2, 6))
        for name, _ in DEFAULT_TARGETS + DEFAULT_CONTROL:
            row = tk.Frame(self.table, bg=BG)
            row.pack(fill="x", pady=1)
            vals = {}
            for key, w in (("name", 24), ("state", 8), ("ms", 10), ("stage", 10),
                           ("rate", 10), ("streak", 9), ("last", 14)):
                vals[key] = tk.Label(row, text=("-" if key != "name" else name), width=w, anchor="w",
                                     bg=BG, font=("Consolas" if key != "name" else "Microsoft YaHei UI", 9))
                vals[key].pack(side="left")
            self.rows[name] = vals

        # 日志
        tk.Label(self.root, text="事件 / 日志", bg=BG, anchor="w",
                 font=("Microsoft YaHei UI", 9, "bold")).pack(fill="x", padx=12)
        self.log = tk.Text(self.root, height=12, wrap="none", bg="white", relief="solid", bd=1)
        self.log.pack(fill="both", expand=True, padx=12, pady=(2, 10))
        self.log.tag_config("ok", foreground=OK)
        self.log.tag_config("fail", foreground=FAIL)
        self.log.tag_config("dim", foreground="#666666")

        for line in env_report() or ["本机未检测到代理环境变量 / HOSTS 中的 GitHub 条目"]:
            self._log(line.strip(), "dim")

    # ---------------- 控制 ----------------
    def _resolve_proxy(self) -> str:
        mode = self.var_mode.get()
        if mode == "direct":
            return ""
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            v = (os.environ.get(k) or "").strip()
            if v:
                return v
        return ""

    def _on_mode_change(self) -> None:
        if self.worker and self.worker.is_alive():
            self.stop_probe()
            self.start()

    def _new_runner(self) -> ProbeRunner:
        proxy = self._resolve_proxy()
        csv_path = data_dir() / "probe.csv" if self.var_csv.get() else None
        return ProbeRunner(interval=float(self.var_interval.get() or 10),
                           timeout=8.0, csv_path=csv_path, proxy=proxy,
                           dns_servers=[ip for _, ip in PUBLIC_DNS])

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        self.runner = self._new_runner()
        self.stop.clear()
        self.worker = threading.Thread(target=self._loop, daemon=True)
        self.worker.start()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        proxy = self._resolve_proxy()
        self._log(f"开始探测，间隔 {self.var_interval.get()}s，模式={'代理 ' + (urlsplit(proxy if '://' in proxy else 'http://' + proxy).netloc if proxy else '直连')}", "dim")
        if self.var_csv.get():
            self._log(f"CSV 记录：{data_dir() / 'probe.csv'}", "dim")

    def _loop(self) -> None:
        r = self.runner
        if not r:
            return
        while not self.stop.is_set():
            try:
                results = r.one_round()
                self.results_q.put(results)
            except Exception as e:  # noqa: BLE001
                self.results_q.put([])
            self.stop.wait(max(1.0, float(self.var_interval.get() or 10)))

    def stop_probe(self) -> None:
        self.stop.set()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._log("已停止。", "dim")

    def probe_now(self) -> None:
        if self.runner is None:
            self.runner = self._new_runner()
        r = self.runner

        def once():
            self.results_q.put(r.one_round())
        threading.Thread(target=once, daemon=True).start()

    # ---------------- 刷新 ----------------
    def _pump(self) -> None:
        try:
            while True:
                results = self.results_q.get_nowait()
                self._render(results)
        except queue.Empty:
            pass
        self.root.after(300, self._pump)

    def _render(self, results: list[ProbeResult]) -> None:
        if not results:
            return
        runner = self.runner
        verdict = getattr(runner, "last_verdict", "")
        color = OK if verdict.startswith("GitHub 全部") else (
            FAIL if "不可达" in verdict or "整体网络异常" in verdict else WARN)
        self.var_verdict.set(verdict)
        self.lbl_verdict.config(fg=color)

        for r in results:
            row = self.rows.get(r.name)
            if not row:
                continue
            st = runner.stats[r.name]
            if r.ok:
                row["state"].config(text="通", fg=OK)
                row["ms"].config(text=f"{int(r.total_ms)} ms")
                row["stage"].config(text="-")
            elif r.reachable:
                row["state"].config(text="异常", fg=WARN)
                row["ms"].config(text=f"{int(r.total_ms)} ms")
                row["stage"].config(text=r.stage or "-")
            else:
                row["state"].config(text="断", fg=FAIL)
                row["ms"].config(text=f"{int(r.total_ms)} ms")
                row["stage"].config(text=r.stage or "-")
            row["rate"].config(text=f"{st.rate:.0f}%")
            row["streak"].config(text=str(st.streak_fail))
            row["last"].config(text=st.last_ok[11:] if st.last_ok else "-")
            if not r.ok and r.error:
                self._log(f"{r.ts[11:]} {r.name}: [{r.stage}] {r.error}"
                          + (f"  ! {r.note}" if r.note else ""), "fail")

        # 翻转事件（带提示音）
        if runner and runner.events:
            while len(self._shown) < len(runner.events):
                ev = runner.events[len(self._shown)]
                self._shown.append(ev)
                self._log(ev, "ok" if "恢复" in ev else "fail")
                if self.var_beep.get():
                    self._beep("恢复" in ev)

    def _beep(self, ok: bool) -> None:
        try:
            import winsound
            winsound.Beep(880 if ok else 330, 200)
        except Exception:  # noqa: BLE001
            pass

    def _log(self, text: str, tag: str = "dim") -> None:
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")

    def _on_close(self) -> None:
        self.stop.set()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def selftest() -> int:
    """打包后自检：探一轮并把结果写入文件（无控制台也能验证 exe 是否真的能工作）。"""
    r = ProbeRunner(interval=10, timeout=8, proxy="", dns_servers=[ip for _, ip in PUBLIC_DNS])
    results = r.one_round()
    lines = [f"自检时间 {datetime.now():%Y-%m-%d %H:%M:%S}",
             f"总体判定：{getattr(r, 'last_verdict', '')}"]
    for x in results:
        lines.append(("  OK   " if x.ok else "  FAIL ") + f"{x.name:<22} {int(x.total_ms)} ms "
                     + (f"HTTP {x.status}" if x.ok else f"[{x.stage}] {x.error}"
                        + (f" ! {x.note}" if x.note else "")))
    out = data_dir() / "selftest.txt"
    out.write_text("\n".join(lines), encoding="utf-8")
    return 0 if any(x.ok for x in results) else 1


def main() -> None:
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    ProbeApp().run()


if __name__ == "__main__":
    main()
