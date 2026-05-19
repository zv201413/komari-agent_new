# komari-agent_new

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

1. 编译: go build
2. 运行: ./komari-agent -s http://server_addr:port -k agent_key

---

## 🛠️ 环境映射 (Env Mapping)

| 变量名 | 说明 | 示例 |
|:---|:---|:---|
| - | - | - |

---

**文档更新时间**: 2026-05-19
