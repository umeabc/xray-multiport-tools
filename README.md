# Xray 多端口管理器（Lite）

当前版本：**v0.1.3**（[Releases](https://github.com/umeabc/xray-multiport-tools/releases)）

轻量、单文件的 **Xray 多端口代理管理工具**（参照 [chaos-zhu/XrayMultiPortManager](https://github.com/chaos-zhu/XrayMultiPortManager) 的功能做的精简复刻版）。

- 仅依赖 **Python 3.8+ 标准库**（GUI 为 tkinter），无需 `pip install` 任何东西
- 提供 **免安装 EXE**（PyInstaller 打包），双击即用
- 一个 xray.exe 进程 = N 个本地 SOCKS5 端口，每个端口对应一个节点

## 功能一览

| 功能 | 说明 |
| --- | --- |
| 订阅管理 | 添加 / 更新 / 删除订阅，自动拉取并解析节点（Base64 订阅自动识别） |
| 节点解析 | `vmess://`、`vless://`（含 REALITY）、`trojan://`、`ss://`（SIP002 与 legacy） |
| 多端口开启 | 每个勾选节点分配一个本地端口，通过 routing 规则同时开启 |
| 混合端口 | 勾选「混合端口」后每个端口同时支持 HTTP 与 SOCKS5（Xray mixed 入站） |
| 内网直连 | 访问保留地址（127/8、10/8、172.16/12、192.168/16、fe80::/10 等）一律直连不走代理 |
| 局域网共享 | 勾选「允许局域网访问」后监听 0.0.0.0，手机/其它电脑可直接用代理 |
| 延迟测试 | 经本地端口向 `www.gstatic.com/generate_204` 发请求测往返毫秒，多线程并发 |
| 下载测速 | 经本地端口拉取测速文件统计 KB/s / MB/s，可按结果排序 |
| 排序 / 日志 | 按延迟升序 / 速度降序排序；运行日志弹窗（Ctrl+L）可一键保存为文件 |
| 流量统计 | 每节点实时/累计上下行流量（↑↓ 分开），右下角显示全部端口实时总流量 |
| 进程管理 | 启动 / 停止 xray.exe，监控退出码并回显日志 |
| 自动下载 | 界面内一键从 GitHub 下载 Xray-core（windows-64）并解出 xray.exe |
| 配置持久化 | 订阅、节点、端口分配、勾选状态、测速结果保存为 JSON，重启不丢 |

## 与原项目的差异

保留：多端口开启、订阅更新、节点解析、延迟/下载测速、排序、日志。
未实现（精简）：PyQt6 精致主题与深浅色切换、TUN 模式感知测速、V2RayN 端口自动检测、kcp/quic 传输层、系统托盘。

## 快速开始

### 方式一：EXE（推荐）

1. 运行 `dist\XrayMultiPortLite.exe`（免安装单文件，约 12 MB）
2. 首次使用点 **[自动下载 xray.exe]**（或自行把 [Xray-core](https://github.com/XTLS/Xray-core/releases) 的 `xray.exe` 放到程序目录）
3. 添加订阅 → 更新 → 勾选节点 → **[▶ 启动所选节点]**

### 方式二：源码运行

```bash
python xray_multi_port.py            # 启动 GUI
python xray_multi_port.py --selftest # 无 GUI 自测（解析/配置生成）
```

或直接双击 `启动GUI.bat`。

## 使用说明

1. **开启多端口**：在节点列表点击行首 `☐` 变 `☑`，点 [▶ 启动所选节点]，日志会列出每个节点的代理地址。
2. **使用代理**：把浏览器 / 程序的代理指到 `<监听地址>:<本地端口>`；双击"本地"列可改端口；右键节点可复制代理地址。默认 SOCKS5；勾选「混合端口 (HTTP+SOCKS)」后同一端口同时支持 HTTP 代理与 SOCKS5。
3. **测延迟 / 测速**：Xray 启动后点对应按钮；若未启动会自动启动已勾选节点。延迟列显示毫秒，速度列显示下载速度。
4. **排序**：测完点 [按延迟排序] / [按速度排序]。
5. **导入本地节点**：点 [导入节点链接]，粘贴一行或多行分享链接（也支持整段 Base64 订阅内容），按回车或点 [导入]。
6. **局域网共享**：勾选「允许局域网访问 (0.0.0.0)」再启动，所有端口改为监听 0.0.0.0；局域网设备用 `socks5://<本机局域网IP>:端口` 访问（启动日志会打印本机 IP）。如连不上，在 Windows 防火墙放行 xray.exe 入站。
7. **运行日志**：主窗口左下角 [运行日志] 按钮或 `Ctrl+L` 打开日志弹窗，可一键保存 / 清空；关闭弹窗不丢日志。
8. **流量统计**：启动后每秒通过 Xray Stats API 统计各端口上下行流量，「实时流量」列为当秒速率，「累计流量」列为本次运行累计；右下角显示全部端口合计。
9. **配置文件**：程序目录下 `xmp_lite_settings.json`（订阅/节点/端口等），生成的 Xray 配置为 `xray_config.json`。

## 目录结构

```text
xray-multi-port-lite/
├── xray_multi_port.py          # 主程序（单文件，含 GUI 与核心逻辑）
├── dist/XrayMultiPortLite.exe  # 免安装 EXE（PyInstaller --onefile --noconsole）
├── app.ico                     # 应用图标
├── 打包EXE.bat                 # 一键重新打包 EXE
├── 启动GUI.bat                 # 源码一键启动
└── make_icon.py                # 图标生成脚本（开发用）
```

> 运行期产物：`xray.exe`（核心，可自动下载）、`xmp_lite_settings.json`、`xray_config.json`。

## 免责声明

本项目仅用于学习与技术研究，请遵守所在地区法律法规。使用 Xray-core 产生的任何行为与本项目无关。
