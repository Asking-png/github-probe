#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub 实时可达性探测。

逐层定位「到底是哪一步断了」：
    DNS 解析 -> TCP 连接 -> TLS 握手 -> HTTP 响应
再配一条国内对照站点，用来区分「GitHub 被墙/被干扰」和「我这边根本没网」。

用法：
    python gh_probe.py --once                  # 只探一轮
    python gh_probe.py --interval 10           # 每 10 秒一轮，持续探测
    python gh_probe.py -i 15 --csv probe.csv   # 同时写 CSV
    python gh_probe.py -i 10 --beep            # 状态翻转时响一声

GUI：pythonw probe_gui.py
"""
from __future__ import annotations

import argparse
import csv
import os
import queue
import random
import socket
import ssl
import statistics
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

# 公共 DNS（用来判定「系统 DNS 被污染」还是「真的不通」）
PUBLIC_DNS = [("阿里 223.5.5.5", "223.5.5.5"), ("腾讯 119.29.29.29", "119.29.29.29")]

# GitHub 各条关键路径：网页 / API / raw / 归档下载 / release 资源，
# 只探 github.com 一个域名是不够的——很多网络环境是「网页能开、git clone 不通」。
DEFAULT_TARGETS: list[tuple[str, str]] = [
    ("网页 github.com", "https://github.com/"),
    ("API api.github.com", "https://api.github.com/zen"),
    ("raw.githubusercontent", "https://raw.githubusercontent.com/github/gitignore/HEAD/Python.gitignore"),
    ("codeload(归档)", "https://codeload.github.com/github/gitignore/tar.gz/refs/heads/main"),
    ("objects(资源)", "https://objects.githubusercontent.com/"),
]
# 国内对照站：它通而 GitHub 全挂，说明是"GitHub 侧不通"，不是你断网
DEFAULT_CONTROL: list[tuple[str, str]] = [
    ("对照 baidu", "https://www.baidu.com/"),
]

UA = "gh-probe/1.0 (+local network diagnostic)"


def dns_query_a(hostname: str, server: str, timeout: float = 3.0) -> list[str]:
    """向指定 DNS 服务器发一次 A 记录查询（自己组包，绕开系统解析器）。

    用途：系统 DNS 解析失败时，用公共 DNS 再试一次。
    公共 DNS 能解析而系统 DNS 不能 = 典型的 DNS 污染/劫持。
    """
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in hostname.split(".")) + b"\x00"
    pkt = header + qname + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(2048)
    finally:
        s.close()
    # 跳过 12 字节头部 + 问题区
    i = 12
    while data[i] != 0:
        i += data[i] + 1
    i += 5                                   # 结尾 0x00 + QTYPE + QCLASS
    ips: list[str] = []
    ancount = struct.unpack(">H", data[6:8])[0]
    for _ in range(ancount):
        if i >= len(data):
            break
        if data[i] & 0xC0 == 0xC0:           # 压缩指针
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += data[i] + 1
            i += 1
        if i + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        rdata = data[i:i + rdlen]
        i += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
    return ips


def _resolve(host: str, port: int, dns_servers: list[str]):
    """先用系统解析器；失败则逐个试公共 DNS。返回 (addr, ip, 说明)。"""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        return infos[0][4], infos[0][4][0], ""
    except Exception as e:  # noqa: BLE001
        base = f"{e.__class__.__name__}"
    for srv in dns_servers:
        try:
            ips = dns_query_a(host, srv)
            if ips:
                return (ips[0], port), ips[0], f"系统DNS失败({base})，改用公共DNS {srv} 成功→疑似DNS污染"
        except Exception:  # noqa: BLE001
            continue
    raise socket.gaierror(base)


def _connect_through_proxy(proxy: str, host: str, port: int, timeout: float):
    """通过 HTTP 代理建立 CONNECT 隧道。返回 (socket, 耗时ms)。"""
    p = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    t0 = time.perf_counter()
    s = socket.create_connection((p.hostname, p.port or 80), timeout=timeout)
    req = (f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"User-Agent: {UA}\r\nProxy-Connection: keep-alive\r\n\r\n").encode()
    s.sendall(req)
    s.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    code = int(head.split("\r\n", 1)[0].split(" ")[1]) if " " in head else 0
    if code != 200:
        s.close()
        raise OSError(f"代理拒绝连接（HTTP {code}）：{head.splitlines()[0] if head else ''}")
    return s, (time.perf_counter() - t0) * 1000


@dataclass
class ProbeResult:
    name: str
    url: str
    ts: str
    ok: bool = False
    reachable: bool = False          # 拿到了 HTTP 响应就算通
    status: int = 0                  # HTTP 状态码，0=没拿到
    dns_ms: float = -1.0
    conn_ms: float = -1.0
    tls_ms: float = -1.0
    ttfb_ms: float = -1.0
    total_ms: float = -1.0
    ip: str = ""
    cert_cn: str = ""
    cert_ok: bool | None = None      # 证书 SAN 是否覆盖该域名（False 多半是中间人/拦截页）
    error: str = ""                  # 失败原因（DNS / TCP / TLS / HTTP / TIMEOUT ...）
    stage: str = ""                  # 断在哪一层
    via: str = "直连"                # 直连 / 代理 host:port
    note: str = ""                   # 附加说明（如 DNS 污染提示）

    def as_row(self) -> dict:
        d = self.__dict__.copy()
        d["ok"] = int(self.ok)
        d["reachable"] = int(self.reachable)
        return d


def _san_matches(cert: dict, host: str) -> bool:
    """检查证书 SAN 是否覆盖 host（覆盖不到 = 很可能被中间人替换）。"""
    try:
        sans = [v for _, v in cert.get("subjectAltName", [])]
    except Exception:  # noqa: BLE001
        return False
    for san in sans:
        if san == host:
            return True
        if san.startswith("*.") and host.split(".", 1)[-1] == san[2:]:
            return True
    return False


def probe_once(name: str, url: str, timeout: float = 8.0, proxy: str = "",
               dns_servers: list[str] | None = None) -> ProbeResult:
    """对单个 URL 做一次分层探测。任何一层失败都会记录失败的层，不会抛异常。"""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    r = ProbeResult(name=name, url=url, ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if not host:
        r.error, r.stage = "URL 解析失败", "URL"
        return r
    if proxy:
        r.via = "代理 " + (urlsplit(proxy if "://" in proxy else "http://" + proxy).netloc or proxy)

    sock = None
    ssock = None
    t0 = time.perf_counter()
    try:
        # --- 1. DNS（走代理时不需要本地解析，由代理代劳）---
        if proxy:
            addr = (host, port)
            r.dns_ms = 0.0
            r.ip = "(由代理解析)"
        else:
            try:
                addr, ip, note = _resolve(host, port, list(dns_servers or []))
                # getaddrinfo 返回的是 sockaddr（IPv6 时是 4 元组），create_connection 只收 2 元组
                if len(addr) > 2:
                    addr = (addr[0], addr[1])
                r.ip = ip
                r.note = note
                r.dns_ms = (time.perf_counter() - t0) * 1000
            except Exception as e:  # noqa: BLE001
                r.error, r.stage = f"DNS 解析失败: {getattr(e, 'args', [e.__class__.__name__])[0]}", "DNS"
                r.total_ms = (time.perf_counter() - t0) * 1000
                return r

        # --- 2. TCP / 代理隧道 ---
        t1 = time.perf_counter()
        if proxy:
            try:
                sock, _ = _connect_through_proxy(proxy, host, port, timeout)
            except Exception as e:  # noqa: BLE001
                r.error, r.stage = f"代理连通失败: {e}", "PROXY"
                r.conn_ms = (time.perf_counter() - t1) * 1000
                r.total_ms = (time.perf_counter() - t0) * 1000
                return r
        else:
            try:
                sock = socket.create_connection(addr, timeout=timeout)
            except Exception as e:  # noqa: BLE001
                err = str(e).lower()
                kind = "连接超时" if "timed out" in err or "timeout" in err else \
                       "连接被拒绝/重置" if "refused" in err or "reset" in err else e.__class__.__name__
                r.error, r.stage = f"{kind}", "TCP"
                r.total_ms = (time.perf_counter() - t0) * 1000
                return r
        r.conn_ms = (time.perf_counter() - t1) * 1000

        # --- 3. TLS ---
        t2 = time.perf_counter()
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            try:
                ssock = ctx.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=True)
                sock = ssock
            except ssl.SSLCertVerificationError as e:
                r.error, r.stage = f"证书校验失败({e.reason})：可能遭中间人劫持", "TLS"
                r.tls_ms = (time.perf_counter() - t2) * 1000
                r.total_ms = (time.perf_counter() - t0) * 1000
                return r
            except Exception as e:  # noqa: BLE001
                err = str(e).lower()
                kind = "握手超时" if "timed out" in err or "timeout" in err else e.__class__.__name__
                r.error, r.stage = f"TLS {kind}", "TLS"
                r.tls_ms = (time.perf_counter() - t2) * 1000
                r.total_ms = (time.perf_counter() - t0) * 1000
                return r
            r.tls_ms = (time.perf_counter() - t2) * 1000
            try:
                cert = ssock.getpeercert() or {}
                subj = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
                r.cert_cn = subj.get("commonName", "")
                r.cert_ok = _san_matches(cert, host)
            except Exception:  # noqa: BLE001
                pass

        # --- 4. HTTP ---
        t3 = time.perf_counter()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii", "replace")
        try:
            sock.sendall(req)
        except Exception as e:  # noqa: BLE001
            r.error, r.stage = f"发送请求失败: {e.__class__.__name__}", "HTTP"
            r.total_ms = (time.perf_counter() - t0) * 1000
            return r

        buf = b""
        deadline = time.time() + timeout
        sock.settimeout(timeout)
        while b"\r\n\r\n" not in buf and time.time() < deadline:
            try:
                chunk = sock.recv(4096)
            except Exception:  # noqa: BLE001
                break
            if not chunk:
                break
            buf += chunk
        r.ttfb_ms = (time.perf_counter() - t3) * 1000

        if not buf:
            r.error, r.stage = "连接后无响应（可能被 Reset）", "HTTP"
            r.total_ms = (time.perf_counter() - t0) * 1000
            return r
        try:
            head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
            status_line = head.split("\r\n", 1)[0]
            r.status = int(status_line.split(" ")[1])
        except Exception:  # noqa: BLE001
            r.error, r.stage = "响应不是 HTTP（可能是拦截页/非标准响应）", "HTTP"
            r.total_ms = (time.perf_counter() - t0) * 1000
            return r

        r.reachable = True
        r.ok = r.status < 500
        if not r.ok:
            r.error, r.stage = f"服务端返回 {r.status}", "HTTP"
        r.total_ms = (time.perf_counter() - t0) * 1000
        return r
    finally:
        for s in (ssock, sock):
            try:
                if s:
                    s.close()
            except Exception:  # noqa: BLE001
                pass


@dataclass
class TargetStat:
    name: str
    url: str
    total: int = 0
    oks: int = 0
    streak_fail: int = 0
    max_streak_fail: int = 0
    lats: list[float] = field(default_factory=list)
    last_ok: str = ""
    last: ProbeResult | None = None
    up: bool | None = None            # 上一次判定（用于检测翻转）

    @property
    def rate(self) -> float:
        return (self.oks / self.total * 100) if self.total else 0.0

    def update(self, r: ProbeResult) -> str | None:
        """更新统计，返回状态翻转描述（无翻转返回 None）。"""
        self.total += 1
        self.last = r
        if r.ok:
            self.oks += 1
            self.streak_fail = 0
            self.last_ok = r.ts
            if r.total_ms > 0:
                self.lats.append(r.total_ms)
        else:
            self.streak_fail += 1
            self.max_streak_fail = max(self.max_streak_fail, self.streak_fail)
        now_up = r.ok
        flip = None
        if self.up is not None and self.up != now_up:
            flip = "恢复" if now_up else "中断"
        self.up = now_up
        return flip


class ProbeRunner:
    """按固定间隔对全部目标做探测，结果通过回调/队列吐出。"""

    def __init__(self, interval: float = 10.0, timeout: float = 8.0,
                 targets=None, controls=None, csv_path: Path | None = None,
                 jitter: float = 0.15, proxy: str = "", dns_servers=None):
        self.interval = interval
        self.timeout = timeout
        self.targets = targets or DEFAULT_TARGETS
        self.controls = controls or DEFAULT_CONTROL
        self.csv_path = csv_path
        self.jitter = jitter
        self.proxy = proxy
        self.dns_servers = list(dns_servers or [])
        self.stats: dict[str, TargetStat] = {
            n: TargetStat(n, u) for n, u in self.targets + self.controls}
        self.rounds = 0
        self.events: list[str] = []
        self._lock = threading.Lock()
        self._csv_lock = threading.Lock()
        if csv_path:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            if not csv_path.exists():
                with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
                    csv.DictWriter(f, fieldnames=list(ProbeResult("n", "u", "t").as_row().keys())
                                   + ["rate_%"]).writeheader()

    # ---------- 单轮 ----------
    def one_round(self, parallel: bool = True) -> list[ProbeResult]:
        jobs = list(self.targets) + list(self.controls)
        results: list[ProbeResult] = []
        if parallel:
            q: "queue.Queue[ProbeResult]" = queue.Queue()

            def work(n_u):
                n, u = n_u
                q.put(probe_once(n, u, self.timeout, self.proxy, self.dns_servers))
            ths = [threading.Thread(target=work, args=(j,), daemon=True) for j in jobs]
            for t in ths:
                t.start()
            for t in ths:
                t.join(timeout=self.timeout + 8)
            while not q.empty():
                results.append(q.get())
        else:
            for n, u in jobs:
                results.append(probe_once(n, u, self.timeout, self.proxy, self.dns_servers))

        with self._lock:
            self.rounds += 1
            for r in results:
                st = self.stats.get(r.name)
                if not st:
                    continue
                flip = st.update(r)
                if flip:
                    msg = (f"{r.ts}  {r.name} {flip}"
                           + (f"（{r.stage}: {r.error}）" if flip == "中断" else f"（{int(r.total_ms)} ms）"))
                    self.events.append(msg)
            self._verdict(results)
        self._write_csv(results)
        return results

    def _verdict(self, results: list[ProbeResult]) -> str:
        """总体判定：正常 / GitHub 不通但你网络正常 / 整体断网 / 部分受损。"""
        by = {r.name: r for r in results}
        gh = [by[n] for n, _ in self.targets if n in by]
        ctl = [by[n] for n, _ in self.controls if n in by]
        gh_ok = sum(1 for r in gh if r.ok)
        ctl_ok = sum(1 for r in ctl if r.ok)
        if gh_ok == len(gh):
            v = "GitHub 全部可达"
        elif gh_ok == 0 and ctl_ok:
            v = "GitHub 不可达，但你的网络正常（疑似被干扰/墙/DNS 污染）"
        elif gh_ok == 0 and not ctl_ok:
            v = "整体网络异常：对照站点也不通（先排查本机网络/代理/加速器）"
        else:
            v = f"部分可达：{gh_ok}/{len(gh)} 个 GitHub 端点正常"
        self.last_verdict = v
        return v

    # ---------- CSV ----------
    def _write_csv(self, results: list[ProbeResult]) -> None:
        if not self.csv_path:
            return
        with self._csv_lock:
            try:
                with self.csv_path.open("a", newline="", encoding="utf-8-sig") as f:
                    w = csv.DictWriter(f, fieldnames=list(ProbeResult("n", "u", "t").as_row().keys())
                                       + ["rate_%"])
                    for r in results:
                        row = r.as_row()
                        row["rate_%"] = f"{self.stats[r.name].rate:.1f}"
                        w.writerow(row)
            except Exception:  # noqa: BLE001
                pass

    # ---------- 汇总 ----------
    def summary(self) -> str:
        lines = []
        for n, _ in self.targets + self.controls:
            st = self.stats[n]
            lat = ""
            if st.lats:
                lat = f" p50={statistics.median(st.lats):.0f}ms p95={sorted(st.lats)[max(0, int(len(st.lats) * 0.95) - 1)]:.0f}ms"
            lines.append(f"  {n:<24} 成功率 {st.rate:5.1f}%  ({st.oks}/{st.total})"
                         f"  最长连续失败 {st.max_streak_fail}{lat}")
        return "\n".join(lines)

    # ---------- 循环 ----------
    def run_forever(self, on_round, stop: threading.Event) -> None:
        while not stop.is_set():
            results = self.one_round()
            try:
                on_round(results, getattr(self, "last_verdict", ""))
            except Exception:  # noqa: BLE001
                pass
            wait = self.interval * (1 + random.uniform(-self.jitter, self.jitter))
            stop.wait(max(1.0, wait))


def env_report() -> list[str]:
    """把可能影响连通性的本机环境因素列出来（代理/HOSTS/加速器常见坑）。"""
    out = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
              "NO_PROXY", "no_proxy"):
        v = os.environ.get(k)
        if v:
            out.append(f"  环境变量 {k} = {v}")
    try:
        hp = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        if hp.exists():
            hits = [ln.strip() for ln in hp.read_text("utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                    and ("github" in ln.lower() or "githubusercontent" in ln.lower())]
            for h in hits:
                out.append(f"  HOSTS 里有 GitHub 相关条目：{h}")
    except Exception:  # noqa: BLE001
        pass
    return out


def fmt_line(r: ProbeResult) -> str:
    mark = "OK  " if r.ok else ("WARN" if r.reachable else "FAIL")
    detail = f"{r.status}" if r.status else r.stage
    via = f"[{r.via}] " if r.via != "直连" else ""
    if r.ok:
        s = (f"  [{mark}] {via}{r.name:<22} {int(r.total_ms):>5} ms  "
             f"DNS {int(max(r.dns_ms,0)):>4} / TCP {int(max(r.conn_ms,0)):>4} / "
             f"TLS {int(max(r.tls_ms,0)):>4} / TTFB {int(max(r.ttfb_ms,0)):>4}  {r.ip}")
        return s + (f"   ! {r.note}" if r.note else "")
    s = (f"  [{mark}] {via}{r.name:<22} {detail}  {r.error}  (耗时 {int(r.total_ms)} ms)")
    return s + (f"   ! {r.note}" if r.note else "")


def beep(ok: bool) -> None:
    try:
        import winsound
        winsound.Beep(880 if ok else 330, 180)
    except Exception:  # noqa: BLE001
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="GitHub 实时可达性探测")
    ap.add_argument("-i", "--interval", type=float, default=10.0, help="探测间隔秒数（默认 10）")
    ap.add_argument("-t", "--timeout", type=float, default=8.0, help="单次超时秒数（默认 8）")
    ap.add_argument("-n", "--rounds", type=int, default=0, help="探多少轮后退出，0=一直探")
    ap.add_argument("--once", action="store_true", help="只探一轮就退出")
    ap.add_argument("--csv", default="", help="把每轮结果写入 CSV 文件")
    ap.add_argument("--beep", action="store_true", help="状态翻转时响一声")
    ap.add_argument("--no-control", action="store_true", help="不探国内对照站点")
    ap.add_argument("-v", "--verbose", action="store_true", help="打印本机代理/HOSTS 等环境信息")
    ap.add_argument("--proxy", default="auto",
                    help="auto=若系统设了代理就走代理（默认）/ direct=强制直连 / system=等同于auto / "
                         "或手写如 http://127.0.0.1:7890")
    ap.add_argument("--dns", action="append", default=[],
                    help="系统 DNS 失败时用于对照的公共 DNS，可多次指定；默认阿里 223.5.5.5 + 腾讯 119.29.29.29")
    ap.add_argument("--no-dns-fallback", action="store_true", help="禁用公共 DNS 回退")
    args = ap.parse_args()

    # 解析代理模式
    proxy = ""
    mode = (args.proxy or "auto").strip().lower()
    if mode in ("auto", "system"):
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            v = (os.environ.get(k) or "").strip()
            if v:
                proxy = v
                break
    elif mode != "direct":
        proxy = args.proxy

    dns_servers = [] if args.no_dns_fallback else (args.dns or [ip for _, ip in PUBLIC_DNS])
    csv_path = Path(args.csv) if args.csv else None
    runner = ProbeRunner(interval=args.interval, timeout=args.timeout, csv_path=csv_path,
                         controls=([] if args.no_control else DEFAULT_CONTROL),
                         proxy=proxy, dns_servers=dns_servers)

    print("GitHub 实时可达性探测  (Ctrl+C 结束并输出汇总)")
    print(f"连接模式：{'代理 ' + urlsplit(proxy if '://' in proxy else 'http://' + proxy).netloc if proxy else '直连'}"
          f"    （浏览器/IDE 通常走系统代理，命令行工具常常不走，两者结果可能不同）")
    if args.verbose:
        env = env_report()
        print("本机环境：" + ("\n" + "\n".join(env) if env else " 未发现代理变量 / HOSTS 条目"))
    print("-" * 96)

    if args.once:
        for r in runner.one_round():
            print(fmt_line(r))
        print("-" * 96)
        print("总体判定：" + runner.last_verdict)
        return

    rounds = 1 if args.rounds == 0 else 0
    done = 0
    try:
        while True:
            results = runner.one_round()
            print(f"[{datetime.now():%H:%M:%S}] 第 {runner.rounds} 轮 —— {runner.last_verdict}")
            for r in results:
                print(fmt_line(r))
            if args.beep:
                for r in results:
                    if r.ok and runner.stats[r.name].streak_fail == 0 and runner.stats[r.name].total > 1:
                        pass
                if runner.events and runner.events[-1].startswith(results[0].ts):
                    beep("恢复" in runner.events[-1])
            print()
            done += 1
            if args.rounds and done >= args.rounds:
                break
            time.sleep(max(1.0, args.interval))
    except KeyboardInterrupt:
        pass
    print("=" * 96)
    print(f"汇总（共 {runner.rounds} 轮）：")
    print(runner.summary())
    print("总体判定：" + getattr(runner, "last_verdict", "-"))
    if runner.events:
        print("\n状态翻转记录：")
        for e in runner.events[-20:]:
            print("  " + e)
    if csv_path:
        print(f"\nCSV 已写入：{csv_path}")


if __name__ == "__main__":
    main()
