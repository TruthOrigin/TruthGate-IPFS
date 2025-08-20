#!/usr/bin/env bash
set -euo pipefail

# ───────────────────────────────────────────────
# TruthGate Runner (dynamic TFM + RID)
# ───────────────────────────────────────────────

# =========================
# Defaults (override via env or flags)
# =========================
PROJECT_ROOT_DEFAULT="/root/TruthGate-IPFS"
SERVER_CSPROJ_DEFAULT=""
SELF_CONTAINED_DEFAULT="true"
WASM_NATIVE_DEFAULT="false"
AUTO_UPDATE_DEFAULT="true"        # <-- NEW
ASPNETCORE_URLS_DEFAULT="http://0.0.0.0:7175"

# =========================
# Environment hygiene
# =========================
if [[ -z "${HOME:-}" ]]; then
  if command -v getent >/dev/null 2>&1 && [[ -n "${USER:-}" ]]; then
    HOME="$(getent passwd "$USER" | cut -d: -f6 || true)"
  fi
  : "${HOME:="/root"}"
fi
export HOME

export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-$HOME}"
export NUGET_PACKAGES="${NUGET_PACKAGES:-$HOME/.nuget/packages}"
mkdir -p "$DOTNET_CLI_HOME" "$NUGET_PACKAGES"
export DOTNET_PRINT_TELEMETRY_MESSAGE="false"

# =========================
# Helpers
# =========================
norm() { local p="${1:-}"; echo "${p%/}"; }

is_musl() {
  if command -v ldd >/dev/null 2>&1; then
    ldd --version 2>&1 | grep -qi musl && return 0
  fi
  [[ -f /etc/alpine-release ]] && return 0
  return 1
}

detect_rid() {
  local arch="$(uname -m)"
  local base="linux"
  local libc_suffix=""
  if is_musl; then libc_suffix="-musl"; fi

  case "$arch" in
    x86_64)  echo "${base}${libc_suffix}-x64" ;;
    aarch64) echo "${base}${libc_suffix}-arm64" ;;
    armv7l)  echo "${base}-arm" ;;
    armv6l)  echo "${base}-arm" ;;
    *)       echo "${base}-x64" ;;
  esac
}

detect_server_csproj() {
  local pr="$1"
  if [[ -f "$pr/TruthGate-Web/TruthGate-Web/TruthGate-Web.csproj" ]]; then
    echo "$pr/TruthGate-Web/TruthGate-Web/TruthGate-Web.csproj"
    return
  fi
  local hit
  hit="$(grep -RIl --include='*.csproj' 'Sdk="Microsoft.NET.Sdk.Web' "$pr" || true)"
  [[ -n "${hit:-}" ]] && { echo "${hit%%$'\n'*}"; return; }
  echo ""
}

extract_tfm() {
  local csproj="$1"
  local tfm=""
  tfm="$(grep -oP '(?<=<TargetFramework>)[^<]+' "$csproj" || true)"
  if [[ -z "${tfm:-}" ]]; then
    local tfms
    tfms="$(grep -oP '(?<=<TargetFrameworks>)[^<]+' "$csproj" || true)"
    if [[ -n "${tfms:-}" ]]; then
      IFS=';' read -r tfm _ <<< "$tfms"
    fi
  fi
  [[ -z "${tfm:-}" ]] && { echo "ERROR: Could not determine <TargetFramework> from $csproj" >&2; exit 2; }
  echo "$tfm"
}

# =========================
# Parse env + flags
# =========================
PROJECT_ROOT="${PROJECT_ROOT:-$PROJECT_ROOT_DEFAULT}"
SERVER_CSPROJ="${SERVER_CSPROJ:-$SERVER_CSPROJ_DEFAULT}"
RID="${ARCH:-$(detect_rid)}"
SELF_CONTAINED="${SELF_CONTAINED:-$SELF_CONTAINED_DEFAULT}"
WASM_NATIVE="${WASM_NATIVE:-$WASM_NATIVE_DEFAULT}"
AUTO_UPDATE="${AUTO_UPDATE:-$AUTO_UPDATE_DEFAULT}"   # <-- NEW
ASPNETCORE_URLS="${ASPNETCORE_URLS:-$ASPNETCORE_URLS_DEFAULT}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-root|-p) PROJECT_ROOT="$2"; shift 2 ;;
    --csproj)          SERVER_CSPROJ="$2"; shift 2 ;;
    --arch|-r)         RID="$2"; shift 2 ;;
    --self-contained)  SELF_CONTAINED="$2"; shift 2 ;;
    --wasm-native)     WASM_NATIVE="$2"; shift 2 ;;
    --auto-update)     AUTO_UPDATE="$2"; shift 2 ;;   # <-- NEW
    --urls)            ASPNETCORE_URLS="$2"; shift 2 ;;
    --help|-h)
      cat <<'EOF'
Usage: truthgate-run.sh [options]

Options:
  -p, --project-root PATH   Root of repo (default: /root/TruthGate-IPFS)
      --csproj PATH         Server .csproj (auto-detect if omitted)
  -r, --arch RID            .NET RID override
      --self-contained B    true|false (default: true)
      --wasm-native B       true|false (default: false)
      --auto-update B       true|false (default: true)
      --urls URLS           ASPNETCORE_URLS (default: http://0.0.0.0:7175)

EOF
      exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

PR="$(norm "$PROJECT_ROOT")"

# =========================
# Resolve .csproj & TFM
# =========================
if [[ -z "$SERVER_CSPROJ" ]]; then
  SERVER_CSPROJ="$(detect_server_csproj "$PR")"
fi
[[ -f "$SERVER_CSPROJ" ]] || { echo "ERROR: server csproj not found: $SERVER_CSPROJ" >&2; exit 3; }

TFM="$(extract_tfm "$SERVER_CSPROJ")"

# =========================
# Compute publish folder
# =========================
PUB="$PR/TruthGate-Web/TruthGate-Web/bin/Release/${TFM}/${RID}/publish"
mkdir -p "$PUB"

echo "== TruthGate Runner =="
echo "Project root   : $PR"
echo "Server csproj  : $SERVER_CSPROJ"
echo "TargetFramework: $TFM"
echo "RID            : $RID"
echo "Publish dir    : $PUB"
echo "Self-contained : $SELF_CONTAINED"
echo "WASM native    : $WASM_NATIVE"
echo "Auto-update    : $AUTO_UPDATE"
echo "ASPNETCORE_URLS: $ASPNETCORE_URLS"
echo

# =========================
# Optional: auto-update
# =========================
if [[ "$AUTO_UPDATE" == "true" ]]; then
  if command -v git >/dev/null 2>&1; then
    echo "[git] fetch/reset ..."
    git -C "$PR" fetch --all
    git -C "$PR" reset --hard origin/master
  fi
else
  echo "[git] auto-update skipped (AUTO_UPDATE=$AUTO_UPDATE)"
fi

# =========================
# Publish
# =========================
SC_ARG="--self-contained ${SELF_CONTAINED}"
echo "[dotnet] publish ..."
dotnet publish "$SERVER_CSPROJ" \
  -c Release -r "$RID" $SC_ARG \
  -p:WasmBuildNative="$WASM_NATIVE" \
  -o "$PUB"

# =========================
# Run
# =========================
export ASPNETCORE_CONTENTROOT="$PUB"
export ASPNETCORE_WEBROOT="$PUB/wwwroot"
export ASPNETCORE_URLS="$ASPNETCORE_URLS"

BIN="$PUB/TruthGate-Web"
if [[ "$SELF_CONTAINED" == "false" ]]; then
  BIN="$PUB/TruthGate-Web.dll"
  echo "[run] dotnet $BIN"
  exec dotnet "$BIN"
else
  echo "[run] $BIN"
  exec "$BIN"
fi
