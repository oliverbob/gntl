#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
VENV_DIR="$ROOT_DIR/.venv"
TLS_DIR="$ROOT_DIR/configs/tls"
AUTO_TLS_CERT="$TLS_DIR/webadmin.crt"
AUTO_TLS_KEY="$TLS_DIR/webadmin.key"
PID_FILE="$ROOT_DIR/.gntl-webadmin.pid"
APP_ENTRY="$ROOT_DIR/main.py"
MOBILE_DOCROOT="$ROOT_DIR/mobile"
MOBILE_ROUTER="$MOBILE_DOCROOT/router.php"
MOBILE_PHP_PORT="${GNTL_MOBILE_PHP_PORT:-2027}"
MOBILE_LOG_DIR="$ROOT_DIR/configs/logs"

# Helper: print to stderr
err() { printf "%s\n" "$*" >&2; }

is_termux() {
  [[ -n "${TERMUX_VERSION:-}" ]] || [[ "${PREFIX:-}" == *"com.termux"* ]] || command -v termux-info >/dev/null 2>&1
}

is_ish_ios() {
  [[ -f /etc/alpine-release ]] && grep -qi "ish\|ios" /proc/version 2>/dev/null
}

is_mobile_runtime() {
  is_termux || is_ish_ios
}

ensure_mobile_packages() {
  if is_termux; then
    if ! command -v php >/dev/null 2>&1; then
      err "[mobile] Installing PHP + SQLite runtime in Termux..."
      pkg update -y && pkg install -y php sqlite caddy || true
    fi
  elif is_ish_ios; then
    if ! command -v php >/dev/null 2>&1; then
      err "[mobile] Installing PHP + SQLite runtime in iSH..."
      apk update && apk add php84 php84-session php84-pdo_sqlite php84-sqlite3 sqlite caddy || true
    fi
  fi
}

run_mobile_server() {
  ensure_mobile_packages
  mkdir -p "$MOBILE_LOG_DIR"

  if ! command -v php >/dev/null 2>&1; then
    err "[mobile] PHP not found after install attempt."
    err "[mobile] Termux: pkg install php sqlite"
    err "[mobile] iSH: apk add php84 php84-session php84-pdo_sqlite php84-sqlite3 sqlite"
    exit 1
  fi

  if [ ! -f "$MOBILE_ROUTER" ]; then
    err "[mobile] Missing mobile app router: $MOBILE_ROUTER"
    exit 1
  fi

  stop_previous_instance

  if command -v caddy >/dev/null 2>&1; then
    err "[mobile] Starting PHP app on 127.0.0.1:$MOBILE_PHP_PORT"
    php -S "127.0.0.1:$MOBILE_PHP_PORT" -t "$MOBILE_DOCROOT" "$MOBILE_ROUTER" >"$MOBILE_LOG_DIR/gntl-mobile-php.log" 2>&1 &
    PHP_PID=$!

    CADDY_FILE="$ROOT_DIR/configs/mobile.Caddyfile"
    mkdir -p "$ROOT_DIR/configs"
    cat > "$CADDY_FILE" <<EOF
:2026 {
  reverse_proxy 127.0.0.1:$MOBILE_PHP_PORT
}
EOF

    err "[mobile] Starting Caddy on http://127.0.0.1:2026"
    if caddy run --config "$CADDY_FILE" --adapter caddyfile >"$MOBILE_LOG_DIR/gntl-mobile-caddy.log" 2>&1 & then
      SERVER_PID=$!
      echo "$SERVER_PID" > "$PID_FILE"
    else
      err "[mobile] Caddy failed to start (permission or execution issue). Falling back to direct PHP on 127.0.0.1:2026"
      kill "$PHP_PID" >/dev/null 2>&1 || true
      php -S "127.0.0.1:2026" -t "$MOBILE_DOCROOT" "$MOBILE_ROUTER" >"$MOBILE_LOG_DIR/gntl-mobile-php.log" 2>&1 &
      SERVER_PID=$!
      echo "$SERVER_PID" > "$PID_FILE"
    fi

    cleanup() {
      rm -f "$PID_FILE" || true
      kill "$PHP_PID" >/dev/null 2>&1 || true
    }

    trap cleanup EXIT INT TERM
    wait "$SERVER_PID"
  else
    err "[mobile] Caddy not found; starting PHP server directly on http://127.0.0.1:2026"
    php -S "127.0.0.1:2026" -t "$MOBILE_DOCROOT" "$MOBILE_ROUTER" >"$MOBILE_LOG_DIR/gntl-mobile-php.log" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$PID_FILE"

    cleanup() {
      rm -f "$PID_FILE" || true
    }

    trap cleanup EXIT INT TERM
    wait "$SERVER_PID"
  fi
}

TLS_CERT="${GNTL_TLS_CERT:-}"
TLS_KEY="${GNTL_TLS_KEY:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --tls-cert)
      TLS_CERT="${2:-}"
      shift 2
      ;;
    --tls-key)
      TLS_KEY="${2:-}"
      shift 2
      ;;
    *)
      err "Unknown argument: $1"
      err "Usage: ./run.sh [--tls-cert /path/to/cert.pem --tls-key /path/to/key.pem]"
      exit 1
      ;;
  esac
done

if { [ -n "$TLS_CERT" ] && [ -z "$TLS_KEY" ]; } || { [ -z "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; }; then
  err "Both TLS cert and key are required when enabling TLS."
  err "Set both GNTL_TLS_CERT and GNTL_TLS_KEY, or pass --tls-cert and --tls-key."
  exit 1
fi

if [ -n "$TLS_CERT" ]; then
  export GNTL_TLS_CERT="$TLS_CERT"
  export GNTL_TLS_KEY="$TLS_KEY"
fi

ensure_auto_tls() {
  if [ -n "${GNTL_TLS_CERT:-}" ] || [ -n "${GNTL_TLS_KEY:-}" ]; then
    return 0
  fi

  mkdir -p "$TLS_DIR"
  if [ -s "$AUTO_TLS_CERT" ] && [ -s "$AUTO_TLS_KEY" ]; then
    export GNTL_TLS_CERT="$AUTO_TLS_CERT"
    export GNTL_TLS_KEY="$AUTO_TLS_KEY"
    err "Using existing auto-generated TLS cert/key in $TLS_DIR"
    return 0
  fi

  if command -v openssl >/dev/null 2>&1; then
    err "No TLS cert/key provided; generating local self-signed cert automatically..."
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "$AUTO_TLS_KEY" \
      -out "$AUTO_TLS_CERT" \
      -days 365 \
      -subj "/CN=localhost" >/dev/null 2>&1
    chmod 600 "$AUTO_TLS_KEY" || true
    chmod 644 "$AUTO_TLS_CERT" || true
    export GNTL_TLS_CERT="$AUTO_TLS_CERT"
    export GNTL_TLS_KEY="$AUTO_TLS_KEY"
    err "Generated TLS cert/key at $TLS_DIR (self-signed)."
  else
    err "OpenSSL not found; TLS auto-generation skipped. Running without TLS."
  fi
}

terminate_pid() {
  local pid="$1"
  if [ -z "$pid" ]; then
    return 0
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  err "Stopping previous webadmin process (PID $pid)..."
  kill "$pid" >/dev/null 2>&1 || true
  sleep 1
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi
}

stop_previous_instance() {
  if [ -f "$PID_FILE" ]; then
    old_pid=$(cat "$PID_FILE" 2>/dev/null || true)
    terminate_pid "$old_pid"
    rm -f "$PID_FILE" || true
  fi

  old_pids=$(pgrep -f "$APP_ENTRY" || true)
  if [ -n "$old_pids" ]; then
    for pid in $old_pids; do
      if [ "$pid" != "$$" ]; then
        terminate_pid "$pid"
      fi
    done
  fi
}

# Find a python executable (prefer python3)
find_python() {
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
  elif command -v python >/dev/null 2>&1; then
    command -v python
  else
    echo ""
  fi
}

PYTHON=$(find_python)
OS_NAME=$(uname -s || true)

if is_mobile_runtime; then
  err "Detected mobile shell environment (Termux/iSH). Using mobile PHP+SQLite runtime."
  run_mobile_server
  exit 0
fi

if [ -z "$PYTHON" ]; then
  err "Python not found. Attempting to install (best-effort)."
  case "$OS_NAME" in
    Linux*)
      if is_termux; then
        err "Detected Termux on Android. Installing python with pkg..."
        pkg update -y && pkg install -y python openssl || true
      elif command -v apt-get >/dev/null 2>&1; then
        err "Using apt-get to install python3... (may require sudo)"
        sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip || true
      elif command -v dnf >/dev/null 2>&1; then
        err "Using dnf to install python3... (may require sudo)"
        sudo dnf install -y python3 python3-venv python3-pip || true
      elif command -v yum >/dev/null 2>&1; then
        err "Using yum to install python3... (may require sudo)"
        sudo yum install -y python3 python3-venv python3-pip || true
      elif command -v pacman >/dev/null 2>&1; then
        err "Using pacman to install python3... (may require sudo)"
        sudo pacman -Syu --noconfirm python python-virtualenv || true
      elif command -v apk >/dev/null 2>&1; then
        if is_ish_ios; then
          err "Detected iSH (iOS Alpine). Installing python3 with apk..."
        else
          err "Using apk to install python3..."
        fi
        apk update && apk add python3 py3-pip py3-virtualenv openssl || true
      else
        err "No supported package manager found."
        err "Android users: install via Termux and run: pkg install python"
        err "iOS users: run in iSH (apk add python3) or in a Homebrew-enabled shell on macOS."
      fi
      ;;
    Darwin*)
      if command -v brew >/dev/null 2>&1; then
        err "Using Homebrew to install python..."
        brew install python || true
      else
        err "Homebrew not found."
        err "If this is iOS shell without Homebrew, install Python in iSH (apk add python3) or use a Python-capable shell app."
        err "On macOS, install Homebrew then run this script again."
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      err "Detected Windows environment. Please install Python 3 from https://www.python.org/downloads/windows/ and ensure 'python' is on PATH."
      ;;
    *)
      err "Unsupported OS: $OS_NAME. Please install Python 3 manually."
      ;;
  esac
  PYTHON=$(find_python)
fi

if [ -z "$PYTHON" ]; then
  err "Python still not found. Aborting."
  exit 1
fi

err "Using python: $PYTHON"

# Create venv if missing
if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON" -m venv "$VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

if [ -x "$VENV_PY" ]; then
  err "Using virtualenv python: $VENV_PY"
else
  err "Virtualenv python not found, falling back to system python: $PYTHON"
  VENV_PY="$PYTHON"
fi

# Ensure pip is available inside the venv. Some systems create venv without pip.
if [ -x "$VENV_PY" ]; then
  if ! "$VENV_PY" -m pip --version >/dev/null 2>&1; then
    err "pip not found in venv; attempting to bootstrap pip with ensurepip"
    if "$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1; then
      err "pip bootstrapped with ensurepip"
    else
      err "ensurepip failed; downloading get-pip.py as fallback"
      if command -v curl >/dev/null 2>&1; then
        curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py || true
      elif command -v wget >/dev/null 2>&1; then
        wget -q -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py || true
      fi
      if [ -f /tmp/get-pip.py ]; then
        "$VENV_PY" /tmp/get-pip.py || true
        rm -f /tmp/get-pip.py || true
      else
        err "Could not obtain get-pip.py; pip may be unavailable."
      fi
    fi
  fi
fi

if [ -x "$VENV_PIP" ]; then
  "$VENV_PIP" install --upgrade pip
  "$VENV_PIP" install -r "$ROOT_DIR/requirements.txt"
else
  # fallback: use python -m pip
  "$VENV_PY" -m pip install --upgrade pip
  "$VENV_PY" -m pip install -r "$ROOT_DIR/requirements.txt"
fi

ensure_auto_tls
stop_previous_instance

if [ -n "${GNTL_TLS_CERT:-}" ]; then
  err "Starting server on https://127.0.0.1:2026"
else
  err "Starting server on http://127.0.0.1:2026"
fi

"$VENV_PY" "$ROOT_DIR/main.py" &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

cleanup() {
  rm -f "$PID_FILE" || true
}

trap cleanup EXIT INT TERM
wait "$SERVER_PID"