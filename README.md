# ASFA-OS-Ξ (Xi) - Cognitive Operating System

[![Formal Verification](https://img.shields.io/badge/verified-Coq%2FLean-blue)](docs/FORMAL_VERIFICATION.md)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

ASFA-OS-Ξ 是第一个基于**认知超图**（Cognitive HyperGraphs）与**形式化验证**的操作系统，融合：
- **SuperHyperGraphs**: n-ary 关系调度与推理
- **Compositional Neuroscience**: Operads/Monoids 神经形态组合
- **Hippocampal Small-World**: 小世界拓扑认知内存
- **Graph Schemas**: 跨域迁移学习与类比推理

## 架构亮点

- **推演即证明**: 每个系统调用生成 Nova 折叠证明
- **涌现即类型**: 编译期验证集群安全性质 (依赖类型)
- **认知即内存**: 海马体启发的小世界知识寻址

## 快速开始

```bash
# 构建内核 (需 Rust nightly)
cargo build --release -p asfa-kernel

# 运行形式化验证测试
cargo test --features formal-verification

# 启动示例: 科学发现 Agent
cargo run --example scientific_discovery
```

## 系统要求

- Rust 1.75+ (nightly for const generics)
- Coq 8.18+ (形式化证明)
- CUDA 12.0+ (可选, ZK 加速)

## 文档

- [架构总览](docs/ARCHITECTURE.md)
- [认知超图理论](docs/COGNITIVE_HYPERGRAPH.md)
- [系统调用 API](docs/SYSCALL_API.md)
