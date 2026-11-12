#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

# 若本机有 Hyperscan/Vectorscan 开发库，则带 accel-hyperscan-ffi 构建；否则 skip（退出 0）。
# 说明见 docs/HYPERSCAN.md

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

has_libhs=0
if command -v pkg-config >/dev/null 2>&1; then
  if pkg-config --exists libhs 2>/dev/null; then
    has_libhs=1
  fi
fi

if [[ "$has_libhs" -eq 0 ]]; then
  # 常见头文件/库路径兜底探测（无 pkg-config 时）
  for cand in \
    /usr/include/hs/hs.h \
    /usr/local/include/hs/hs.h \
    /usr/include/hs.h; do
    if [[ -f "$cand" ]]; then
      has_libhs=1
      break
    fi
  done
fi

PKG="${PKG:-nerve-antibody-accel}"

if [[ "$has_libhs" -eq 0 ]]; then
  echo "skip: libhyperscan/vectorscan (libhs) not found; install libhyperscan-dev or see docs/HYPERSCAN.md"
  echo "hint: cargo build -p ${PKG} --features accel-hyperscan   # RegexSet path, no native lib"
  exit 0
fi

echo "==> libhs detected; building ${PKG} with features accel-hyperscan-ffi"
cargo build -p "${PKG}" --features accel-hyperscan-ffi "$@"
