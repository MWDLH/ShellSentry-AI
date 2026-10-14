#!/usr/bin/env bash
# ShellSentry-AI — Linux / macOS launcher
#
# 与 start-shellsentry.cmd 保持同一套流程：
#   1. 首次运行时创建项目内的独立 .venv（须为 Python 3.10+）
#   2. 依赖缺失时自动安装
#   3. 启动本地 Web 界面（端口占用时由应用自动避让）
#
# 用法：
#   ./start-shellsentry.sh
#   ./start-shellsentry.sh --port 9000
#   ./start-shellsentry.sh --no-browser
#
# 其余参数原样透传给 `python -m shellsentry serve`。

set -euo pipefail

# 切到脚本所在目录（即项目根）。用 shell 参数展开而非 `dirname` 命令，
# 避免在极简 PATH 环境下外部命令缺失导致定位失败。
SCRIPT_DIR="${0%/*}"
[ "$SCRIPT_DIR" = "$0" ] && SCRIPT_DIR="."
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

# ── 探测可用的 Python 解释器（须为 3.10+）────────────────────────
find_python() {
    local candidate
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
                printf '%s' "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

# ── 环境自检：不存在，或低于 3.10，则（重）建 ────────────────────
VENV_PYTHON=""
if [ -x "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
fi

if [ -n "$VENV_PYTHON" ]; then
    # 旧环境可能是用 3.9 建的，项目要求 3.10+，留着会一路报错，直接重建。
    "$VENV_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null || {
        echo "[ShellSentry] 现有环境使用 Python 3.9 或更低版本，正在重建..."
        rm -rf "$VENV_DIR"
        VENV_PYTHON=""
    }
fi

if [ -z "$VENV_PYTHON" ]; then
    echo "[ShellSentry] 首次启动：正在创建独立的 Python 环境..."
    if ! PYTHON_BIN="$(find_python)"; then
        # 用 echo 而非 heredoc（cat），少依赖一个外部命令
        echo "[ShellSentry] 未找到 Python 3.10 或更高版本。" >&2
        echo "  Ubuntu/Debian : sudo apt install python3 python3-venv" >&2
        echo "  CentOS/RHEL   : sudo yum install python3" >&2
        echo "  macOS         : brew install python@3.12（或从 python.org 下载）" >&2
        echo "  安装后重新运行本脚本。" >&2
        exit 1
    fi
    "$PYTHON_BIN" -m venv "$VENV_DIR" || {
        echo "[ShellSentry] 创建虚拟环境失败（Debian/Ubuntu 可能需要：sudo apt install python3-venv）" >&2
        exit 1
    }
    # 以实际生成的解释器为准，而不是假定 bin/ 结构：
    # 在 Git Bash / WSL 互操作场景下，Python 可能生成 Windows 结构（Scripts/）。
    if [ -x "$VENV_DIR/bin/python" ]; then
        VENV_PYTHON="$VENV_DIR/bin/python"
    elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then
        VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
    else
        echo "[ShellSentry] 虚拟环境已创建，但找不到解释器（预期 $VENV_DIR/bin/python）。" >&2
        exit 1
    fi
fi

# ── 依赖自检与安装 ───────────────────────────────────────────────
if ! "$VENV_PYTHON" -c 'import shellsentry, fastapi, uvicorn, openai, multipart' >/dev/null 2>&1; then
    echo "[ShellSentry] 正在安装本地运行依赖..."
    # 先升级 pip：venv 自带的 pip 可能早于 21.3，而 editable 安装（PEP 660）
    # 是 21.3 才支持的，否则会报 setup.py not found 而装不上。
    "$VENV_PYTHON" -m pip install --disable-pip-version-check --upgrade pip setuptools wheel || {
        echo "[ShellSentry] pip 升级失败，请检查网络连接。" >&2
        exit 1
    }
    "$VENV_PYTHON" -m pip install --disable-pip-version-check -e . || {
        echo "[ShellSentry] 依赖安装失败，请检查网络连接。" >&2
        exit 1
    }
fi

# ── 启动 ─────────────────────────────────────────────────────────
echo "[ShellSentry] 正在启动，浏览器将自动打开。"
echo "[ShellSentry] 按 Ctrl+C 停止服务。"
exec "$VENV_PYTHON" -m shellsentry serve --port 8765 "$@"
