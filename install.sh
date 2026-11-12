#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

# Nerve Antibody 一键安装：依赖自检 → 构建 → 自检
#
#   bash install.sh                # release 构建 + 跑测试
#   bash install.sh --skip-test    # 只构建，不跑测试（CI 已跑过时用）
#   bash install.sh --debug        # debug 构建（开发更快）
#   bash install.sh --with-ui      # 额外构建 Arc-Cortex Console 前端
#
# 前置：Rust 工具链（rustup）、Node 20+（仅 --with-ui 需要）
# 本仓库是库 + 引擎：产物被 Nerve WAF 以 path 依赖调用；独立验证用 `make dashboard`。

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

BUILD_MODE="release"
RUN_TEST=1
WITH_UI=0

log() { printf '[install] %s\n' "$*"; }
die() {
  printf '[install] ✗ %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '8,15p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-test)
      RUN_TEST=0
      shift
      ;;
    --debug)
      BUILD_MODE="debug"
      shift
      ;;
    --with-ui)
      WITH_UI=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "未知参数: $1（用 --help 查看用法）"
      ;;
  esac
done

echo "────────────────────────────────────────────────"
echo " Nerve Antibody 一键安装"
echo " 目录：$ROOT"
echo "────────────────────────────────────────────────"

# ---------------------------------------------------------------- 依赖自检
command -v cargo >/dev/null 2>&1 ||
  die "未找到 cargo。安装 Rust：https://rustup.rs"

RUSTC_VER="$(rustc --version 2>/dev/null | awk '{print $2}')"
log "✓ rustc ${RUSTC_VER:-?}"

# 仓库若声明了 rust-toolchain.toml，rustup 会自动切换；这里只做提示
if [[ -f rust-toolchain.toml ]]; then
  PINNED="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml | head -1)"
  [[ -n "$PINNED" ]] && log "· 仓库固定工具链：$PINNED（rustup 会自动使用）"
fi

if ((WITH_UI)); then
  command -v node >/dev/null 2>&1 || die "未找到 node（--with-ui 需要 Node 20+）"
  command -v npm >/dev/null 2>&1 || die "未找到 npm（--with-ui 需要）"
  NODE_VER="$(node --version | sed 's/^v//')"
  NODE_MAJOR="${NODE_VER%%.*}"
  if [[ "${NODE_MAJOR:-0}" -lt 18 ]]; then
    die "Node ${NODE_VER} 过旧，需要 18+（推荐 20+）"
  fi
  log "✓ node v${NODE_VER}"
fi

# ---------------------------------------------------------------- 构建
if [[ "$BUILD_MODE" == "release" ]]; then
  log "构建（release，首次可能数分钟）…"
  cargo build --release
  TARGET_DIR="target/release"
else
  log "构建（debug）…"
  cargo build
  TARGET_DIR="target/debug"
fi
log "✓ 构建完成：$ROOT/$TARGET_DIR"

# ---------------------------------------------------------------- 自检
if ((RUN_TEST)); then
  log "运行测试（--skip-test 可跳过）…"
  if cargo test --quiet; then
    log "✓ 测试通过"
  else
    die "测试失败。单独复现：cargo test -- --nocapture"
  fi
fi

# ---------------------------------------------------------------- 前端（可选）
if ((WITH_UI)); then
  log "构建 Console 前端（apps/dashboard）…"
  (cd apps/dashboard && npm install && npm run build)
  log "✓ 前端产物：apps/dashboard/dist"
fi

echo
echo "────────────────────────────────────────────────"
echo " ✓ Nerve Antibody 就绪"
echo
echo " 被 Nerve WAF 调用：作为 path 依赖（crate nerve-antibody / nerve-waf-expert）"
echo " 本地验证 Console：make dashboard  → API :8790 + Vite :5178"
echo " 规则包签名：      make seal PACK=packs/baseline"
echo " 产物目录：        $TARGET_DIR"
echo "────────────────────────────────────────────────"
