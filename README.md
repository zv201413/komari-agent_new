# komari-agent_new

> **Komari 生态**: [`komari_new`](https://github.com/zv201413/komari_new) (服务端) ← **`komari-agent_new`** (本仓库, 探针) · [`Komari_ttyd`](https://github.com/zv201413/Komari_ttyd) (Docker) · [`komari-web_new`](https://github.com/zv201413/komari-web_new) (前端 UI 源码)

Cgroup 感知的 Go 探针客户端，优化了在受限容器环境下的 CPU 核数和内存限额探测精度

**当前版本**: v1.3.0
**技术栈**: Go, Cgroups, gopsutil

---

## 🌟 核心特色

- Cgroup v1/v2 CPU Core Quota 自动识别与小数核数保留
- Cgroup 容器内存限额 memory.max/limit_in_bytes 嗅探
- cgroup 容器内存真实用量 memory.current/usage_in_bytes 统计

---

## 🚀 快速开始

### 使用安装脚本（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/zv201413/komari-agent_new/main/install.sh \
  | bash -s -- -e https://your-server.com:25774 -t your_agent_secret
```

> 支持 root 和非 root 环境：root 下安装到 `/opt/komari` + systemd 服务；非 root 下自动用 `~/.komari` + nohup 后台模式。

### IPv6-only 与默认 DNS64/NAT64

Unix 安装脚本默认将 [nat64.net](https://nat64.net/) 的 `2a00:1098:2c::1`
作为 `--fallback-dns` 备用路径：先用系统 DNS 并连接，解析超时、解析失败或所有地址连接失败后
才尝试 DNS64/NAT64，不修改系统 DNS。Komari 和 Argosbx 网页安装入口默认勾选该选项，
可以取消勾选关闭。直接使用脚本时可通过 `--install-dns64 off` 关闭默认 DNS64。
若另行显式传入 `--custom-dns`，该自定义 DNS 仍保留。

旧安装命令中的 `--custom-dns 2a00:1098:2c::1` 在新版探针中同样按系统 DNS 优先的备用路径处理。
其他自定义 DNS 仍优先使用，完整查询或连接失败后回退系统 DNS。配置备用路径时每个解析路径最多 5 秒，
其中 DNS 查询最多 2 秒；所有路径受调用方总超时和取消控制。UDP 响应截断时支持 TCP DNS 重试，
HTTP、WebSocket、自动发现、更新检查和公网 IP 检测共用回退逻辑，TLS 验证继续生效。

运行时可通过 `--fallback-dns`、`AGENT_FALLBACK_DNS` 或 JSON 的 `fallback_dns` 配置备用服务器。

直接下载 GitHub 发布包失败时，安装脚本用 `nat64-download.py` 通过 DNS64/NAT64 回退下载；
需要 Python 3.8+。辅助程序只接受 HTTPS，保留原域名的 TLS SNI 与证书验证，拒绝降级到 HTTP，
成功后原子替换下载文件。新内核下载并通过可执行检查前，不停止旧安装。

```bash
# Disable third-party DNS64/NAT64 for a new installation.
curl -fsSL https://raw.githubusercontent.com/zv201413/komari-agent_new/main/install.sh \
  | bash -s -- --install-dns64 off -e https://your-server.example -t YOUR_TOKEN

# Existing agent: keep its endpoint/token and add this runtime argument.
./komari-agent --fallback-dns 2a00:1098:2c::1 -e https://your-server.example -t YOUR_TOKEN
```

公共 NAT64 会增加第三方网络依赖。HTTPS/WSS 正常验证证书时，中转无法解密 Token、终端命令和回显，
但能观察访问目标及流量元数据，亦可能中断连接。不要为连通而开启 `--ignore-unsafe-cert`。
Windows 的运行时参数同样可用；其 PowerShell 安装下载不使用此 Python 回退。

### 安装命令快捷后缀（Linux / macOS / FreeBSD）

在原来的 `bash -s -- ...` 安装参数末尾加一个空格和后缀：

| 后缀 | 行为 |
| --- | --- |
| `rep` | 覆盖安装；新二进制下载并验证后才停止旧进程、替换文件和重建服务 |
| `del` | 停止服务或后台进程并卸载二进制、启动脚本和日志；保留目录中的其他文件及保存的数据 |
| `status` | 查看现有安装状态，不下载或重新安装；未安装或后台进程未运行时返回退出码 3 |

```bash
curl -fsSL https://raw.githubusercontent.com/zv201413/komari-agent_new/main/install.sh \
  | bash -s -- -e https://your-server.example -t YOUR_TOKEN rep
```

将示例最后的 `rep` 替换为 `del` 或 `status` 即可。自定义过安装目录或服务名时，
保留对应的 `--install-dir`、`--install-service-name` 参数，并使用原安装账号运行。
后缀不会传给探针；`status` 和 `del` 不要求 Token。后台进程停止前会核对 PID 对应的可执行文件，
避免旧 PID 指向其他程序；覆盖安装失败时保留旧二进制和运行进程。

### 手动编译运行

1. 编译: go build
2. 运行: ./komari-agent -s http://server_addr:port -k agent_key

---

## 🛠️ 环境映射 (Env Mapping)

| 变量名 | 说明 | 示例 |
|:---|:---|:---|
| - | - | - |

---

**文档更新时间**: 2026-05-19
