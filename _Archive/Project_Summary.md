# 🔒 komari-agent_new 技术深度总结

**项目状态**: Completed & Verified (v1.3.0)
**更新日期**: 2026-05-19
**技术栈**: Go → Cgroups → gopsutil

---

## 1. 项目背景与目标

Cgroup 感知的 Go 探针客户端，优化了在受限容器环境下的 CPU 核数和内存限额探测精度

---

## 2. 核心架构设计

- Go
- Cgroup Linux Kernel API

---

## 3. 开发日志 (最近更新)

### [2026-05-19] patch - 升级 cgroup 核心数与内存监测

| 字段 | 内容 |
|:---|:---|
| 问题 | 在 0.5核或受限内存容器中，探针报告宿主机核心数/物理内存总数且 Used 只封顶不真实反映容器用量 |
| 解法 | 重构 cgroup.go 适配 v1/v2；CPU 核心支持小数精度；内存使用量对接 memory.current / usage_in_bytes |

---

**文档性质**: 本地私密归档
**生成时间**: 2026-05-19 15:28:05
