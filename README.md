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

Unix 安装脚本默认使用 [nat64.net](https://nat64.net/) 的 `2a00:1098:2c::1`，
为探针添加 `--custom-dns`，不修改系统 DNS。Komari 和 Argosbx 网页安装入口默认勾选该选项，
可以取消勾选关闭。直接使用脚本时可通过 `--install-dns64 off` 关闭默认 DNS64。
若另行显式传入 `--custom-dns`，该自定义 DNS 仍保留。

直接下载 GitHub 发布包失败时，安装脚本用 `nat64-download.py` 通过 DNS64/NAT64 回退下载；
需要 Python 3.8+。辅助程序只接受 HTTPS，保留原域名的 TLS SNI 与证书验证，拒绝降级到 HTTP，
成功后原子替换下载文件。新内核下载并通过可执行检查前，不停止旧安装。

```bash
# Disable third-party DNS64/NAT64 for a new installation.
curl -fsSL https://raw.githubusercontent.com/zv201413/komari-agent_new/main/install.sh \
  | bash -s -- --install-dns64 off -e https://your-server.example -t YOUR_TOKEN

# Existing agent: keep its endpoint/token and add this runtime argument.
./komari-agent --custom-dns 2a00:1098:2c::1 -e https://your-server.example -t YOUR_TOKEN
```

公共 NAT64 会增加第三方网络依赖。HTTPS/WSS 正常验证证书时，中转无法解密 Token、终端命令和回显，
但能观察访问目标及流量元数据，亦可能中断连接。不要为连通而开启 `--ignore-unsafe-cert`。
Windows 的运行时参数同样可用；其 PowerShell 安装下载不使用此 Python 回退。

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
