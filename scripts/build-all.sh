#!/bin/bash
set -e

echo "Building ASFA-OS-Ξ..."

# 安装工具链
echo "Installing Rust toolchain..."
rustup component add rust-src llvm-tools-preview

# 构建内核
echo "Building kernel..."
cd kernel
cargo build --release --target x86_64-unknown-none

# 构建用户空间
echo "Building userspace..."
cd ../userspace
cargo build --release

# 构建示例
echo "Building examples..."
cd ../examples
cargo build --release

# 形式化验证
echo "Running formal verification..."
cd ../formal/coq
make

echo "Build complete!"
