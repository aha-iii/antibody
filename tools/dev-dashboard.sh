#!/usr/bin/env bash
# 一键启动 Native 引擎 API (:8790) + Dashboard 前端热更新 (:5178)
# 用法（WSL）：
#   cd Nerve-antibody
#   bash tools/dev-dashboard.sh
#
# 可选环境变量：DEFAULT_PACK / LISTEN / PACK_ROOT / NERVE_NATIVE_DEV_PACK
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export NERVE_NATIVE_DEV_PACK="${NERVE_NATIVE_DEV_PACK:-1}"
export DEFAULT_PACK="${DEFAULT_PACK:-baseline}"
export LISTEN="${LISTEN:-127.0.0.1:8790}"
export NERVE_AUTH_ENABLED="${NERVE_AUTH_ENABLED:-1}"
export NERVE_AUTH_MODE="${NERVE_AUTH_MODE:-local}"
export NERVE_AUTH_USER="${NERVE_AUTH_USER:-admin}"
export NERVE_AUTH_PASSWORD="${NERVE_AUTH_PASSWORD:-admin}"
export KEYCLOAK_ENABLED="${KEYCLOAK_ENABLED:-0}"

API_LOG="${API_LOG:-$ROOT/target/dashboard-api-dev.log}"
UI_DIR="$ROOT/apps/dashboard"
BIN="$ROOT/target/debug/nerve-antibody-dashboard"
API_PID=""

cleanup() {
  if [[ -n "${API_PID}" ]] && kill -0 "${API_PID}" 2>/dev/null; then
    echo ">> stop API pid=${API_PID}"
    kill "${API_PID}" 2>/dev/null || true
    wait "${API_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing command: $1" >&2
    exit 1
  }
}

need_cmd cargo
need_cmd npm
need_cmd curl

# @nerve/ui 随仓库提供（apps/dashboard/vendor/nerve-ui），缺失时直接给出可读错误，
# 避免 npm install 抛 ENOENT 让人误判成网络或权限问题。
if [[ ! -f "$ROOT/apps/dashboard/vendor/nerve-ui/src/index.ts" ]]; then
  echo "ERROR: missing apps/dashboard/vendor/nerve-ui/src/index.ts" >&2
  echo "       Dashboard 前端依赖的 @nerve/ui 源码副本不完整。" >&2
  exit 1
fi

# WSL+/mnt/d 下 Vite 原生 watch 易 EMFILE
ulimit -n 65535 2>/dev/null || ulimit -n 4096 2>/dev/null || true
export CHOKIDAR_USEPOLLING="${CHOKIDAR_USEPOLLING:-1}"
export CHOKIDAR_INTERVAL="${CHOKIDAR_INTERVAL:-800}"
export VITE_USE_POLLING="${VITE_USE_POLLING:-1}"

mkdir -p "$ROOT/target"

# Windows 宿主 npm install 的 node_modules 带 @esbuild/win32-*，WSL 会报错；
# 且 .bin/vite 可能是无 .js 后缀的 ESM 副本，在 Linux 下会被 Node 当 CJS 解析而失败。
# 若缺 linux 包、残留 win32 包或 bin stub 异常，则清掉后按当前平台重装。
ui_deps_need_reinstall() {
  local nm="$UI_DIR/node_modules"
  [[ ! -d "$nm" ]] && return 0
  if [[ -d "$nm/@esbuild/win32-x64" || -d "$nm/@esbuild/win32-arm64" ]]; then
    if [[ "$(uname -s)" == Linux* ]]; then
      return 0
    fi
  fi
  if [[ "$(uname -s)" == Linux* ]] && [[ ! -d "$nm/@esbuild/linux-x64" && ! -d "$nm/@esbuild/linux-arm64" ]]; then
    # vite/esbuild 已装但无 linux 原生包
    if [[ -d "$nm/esbuild" ]]; then
      return 0
    fi
  fi
  if [[ "$(uname -s)" == Linux* ]]; then
    local vite_bin="$nm/.bin/vite"
    if [[ -f "$vite_bin" ]]; then
      local first_line
      first_line="$(head -1 "$vite_bin" 2>/dev/null || true)"
      if [[ "$first_line" != "#!/bin/sh" ]]; then
        return 0
      fi
    fi
  fi
  return 1
}

if ui_deps_need_reinstall; then
  echo ">> reinstall apps/dashboard deps for $(uname -s)/$(uname -m) (platform or npm bin mismatch)"
  rm -rf "$UI_DIR/node_modules"
  (cd "$UI_DIR" && npm install)
elif [[ ! -d "$UI_DIR/node_modules" ]]; then
  echo ">> npm install (apps/dashboard)"
  (cd "$UI_DIR" && npm install)
fi

echo ">> cargo build -p nerve-antibody-dashboard (首次可能较久，请等待编译完成)"
cargo build -p nerve-antibody-dashboard
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: binary missing: $BIN" >&2
  exit 1
fi

# 释放旧监听，避免 Conflict
if command -v fuser >/dev/null 2>&1; then
  fuser -k 8790/tcp 2>/dev/null || true
fi

echo ">> start API: $BIN"
echo "   LISTEN=${LISTEN} DEFAULT_PACK=${DEFAULT_PACK}"
echo "   log: ${API_LOG}"
(
  cd "$ROOT"
  exec "$BIN"
) >"$API_LOG" 2>&1 &
API_PID=$!

echo ">> wait API health http://${LISTEN}/api/health"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://${LISTEN}/api/health" >/dev/null 2>&1; then
    echo ">> API ready"
    ready=1
    break
  fi
  if ! kill -0 "${API_PID}" 2>/dev/null; then
    echo "ERROR: API exited early — see ${API_LOG}" >&2
    tail -n 80 "$API_LOG" >&2 || true
    exit 1
  fi
  sleep 0.5
done

if [[ "$ready" -ne 1 ]]; then
  echo "ERROR: API health timeout — see ${API_LOG}" >&2
  tail -n 80 "$API_LOG" >&2 || true
  exit 1
fi

echo ">> start UI: npm run dev → http://127.0.0.1:5178 (proxy /api → ${LISTEN})"
echo "   Ctrl+C 同时停止前端与 API"
cd "$UI_DIR"
npm run dev
