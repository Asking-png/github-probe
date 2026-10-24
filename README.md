# GitHub 实时探测

实时探测本机到 GitHub 的连通性，并且**定位到底断在哪一层**：

```
DNS 解析 -> TCP 连接 -> TLS 握手 -> HTTP 响应
```

再配一条国内对照站点（百度），用来区分三种完全不同的情况：

| 现象 | 结论 |
|---|---|
| GitHub 全通 | 没问题 |
| GitHub 全断 + 对照站点通 | **GitHub 侧不通**（被干扰 / 被墙 / DNS 污染），你网络本身是好的 |
| 连对照站点也断 | 你这边网络就断了，先查本机网络、代理、加速器 |

## 为什么不只 ping 一下

`ping` 走 ICMP，很多网络环境 ICMP 通但 HTTPS 不通，或者反过来。这个工具按真实访问路径
逐层测：DNS 有没有被污染、TCP 连不连得上、TLS 是不是被中间人、HTTP 拿不拿得到响应，
每一层单独计时。GitHub 也不止一个域名——**网页能开但 `git clone` 不通**是常见现象，
所以它同时探 5 个端点：

- `github.com`（网页）
- `api.github.com`（API / `gh` CLI）
- `raw.githubusercontent.com`（raw 文件）
- `codeload.github.com`（`git clone`、下载 zip 归档）
- `objects.githubusercontent.com`（release 资源、LFS）

## 用法

```bat
rem 图形面板（双击 start-probe.bat 即可）
python probe_gui.py

rem 命令行：只探一轮
python gh_probe.py --once -v

rem 每 10 秒一轮，一直探，写 CSV（Ctrl+C 结束时输出汇总）
python gh_probe.py -i 10 --csv logs/probe.csv

rem 探 20 轮就停
python gh_probe.py -i 10 -n 20
```

常用参数：

| 参数 | 说明 |
|---|---|
| `-i / --interval` | 探测间隔秒数（默认 10） |
| `-t / --timeout` | 单次超时（默认 8 秒） |
| `-n / --rounds` | 探几轮后退出，0 = 一直探 |
| `--once` | 只探一轮 |
| `--csv 路径` | 写 CSV，含每层的耗时与失败原因 |
| `--proxy auto\|direct\|http://host:port` | 连接模式，`auto`=跟随系统代理（默认） |
| `--dns IP` | 系统 DNS 失败时用于对照的公共 DNS，可重复指定 |
| `--no-dns-fallback` | 关掉公共 DNS 回退 |
| `--no-control` | 不探国内对照站点 |
| `--beep` | 状态翻转（通↔断）时响一声 |
| `-v` | 顺带打印本机代理环境变量、HOSTS 里的 GitHub 条目 |

> **重要**：浏览器和 IDE 一般走系统代理，而命令行工具（git、pip）未必走。
> 两种模式结果可能完全不同，建议都测一遍：`--proxy auto` 和 `--proxy direct`。

## 打包成单个 exe（桌面版）

双击 `build-exe.bat` 即可：自动建虚拟环境 → 装 PyInstaller → 打成单文件 `dist\GitHubProbe.exe`
（约 13 MB，不依赖本机 Python，拷到别的机器也能跑）。

构建脚本默认**只输出到 `dist\`**，不会往桌面写任何文件。想顺手在桌面放一份，加参数再跑一次：

```bat
build-exe.bat desktop
```

验证 exe 是否真能工作（无窗口，探一轮后写入文件）：

```bat
dist\GitHubProbe.exe --selftest
type "%LOCALAPPDATA%\GitHubProbe\selftest.txt"
```

打包版的日志/CSV 统一写在 `%LOCALAPPDATA%\GitHubProbe\`（不会往桌面丢文件夹）。

## 怎么读结果

```
[OK  ] 网页 github.com   561 ms  DNS 8 / TCP 92 / TLS 104 / TTFB 189  20.205.243.166
[FAIL] raw.githubusercontent  TCP  连接超时  (耗时 8014 ms)
   ! 系统DNS失败(gaierror)，改用公共DNS 223.5.5.5 成功→疑似DNS污染
```

| 断在哪层 | 常见原因 |
|---|---|
| `DNS` | DNS 污染/劫持（若提示"改用公共DNS成功"基本可确认）；换个 223.5.5.5 / 119.29.29.29 试试 |
| `TCP` | 连接超时 = 被丢包/被墙；连接被重置 = 有设备（防火墙、杀软、加速器）主动掐断 |
| `TLS` | 握手超时 = 中间设备干扰；证书校验失败 = **有中间人**（公司审计、杀软 HTTPS 扫描、恶意劫持） |
| `HTTP` | 连上了但没响应 = 被 Reset；返回 5xx = GitHub 侧或代理侧问题 |
| `PROXY` | 代理本身不通或拒绝了（502 = 代理到不了目标，很可能是加速器/代理的节点问题） |

拿到结果后对症下药：

```bat
rem 换公共 DNS（管理员 PowerShell）
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter|? Status -eq Up|Select -First 1).ifIndex -ServerAddresses 223.5.5.5,119.29.29.29

rem 让 git 走你现在这个代理（端口按本机的改）
git config --global http.proxy http://127.0.0.1:2965
git config --global https.proxy http://127.0.0.1:2965

rem 取消 git 代理
git config --global --unset http.proxy
git config --global --unset https.proxy
```

## 文件说明

| 文件 | 用途 |
|---|---|
| `gh_probe.py` | 核心：分层探测 + 命令行 |
| `probe_gui.py` | 图形面板（实时表格 + 事件日志 + 状态翻转提示音） |
| `start-probe.bat` | 双击启动图形面板（自动找 Python） |
| `build-exe.bat` | 打包成单个 exe（默认只输出 `dist\`，加 `desktop` 参数才复制到桌面） |
| `make_icon.py` | 生成 `icon.ico`（纯标准库画 ICO，不用 Pillow） |
| `smoke_gui.py` | GUI 冒烟测试（自动开窗口探一轮再关） |
| `logs/probe.csv` | CSV 记录（已被 .gitignore 排除，含出口 IP 等信息别外传） |

依赖：Python 3.10+，**零第三方库**，标准库即可跑。

## License

[MIT](LICENSE) © 2026 Asking-png

欢迎提 Issue 反馈探测异常样本（尤其是某一层失败但浏览器能开的场景），也欢迎 PR。
