#!/usr/bin/env bash
set -euo pipefail

# RITA installer script
# this installer must be run directly on the system where RITA will be installed

# -------------------------
# constants
# -------------------------
RITA_VERSION="REPLACE_ME"

# -------------------------
# paths inside installer
# -------------------------
INSTALLER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_FILES="${INSTALLER}/files"
SRC_OPT="${SRC_FILES}/opt"
SRC_ETC="${SRC_FILES}/etc"

# -------------------------
# paths on target system
# -------------------------
ETC="/etc/rita"
OPT="/opt/rita"

# -------------------------
# load helper functions
# -------------------------
HELPER_FILE="${INSTALLER}/scripts/helper.sh"
[[ -f "$HELPER_FILE" ]] || { echo "Helper functions script not found: $HELPER_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$HELPER_FILE"

# ensure /usr/local/bin is in PATH
export PATH="/usr/local/bin:${PATH}"

# -------------------------
# local functions
# -------------------------
show_help() {
    cat >&2 <<EOF

Usage: $(basename "$0") [options]

This installer installs RITA on the local system.

Options:
  -h, --help        Show this help message and exit

Example:
  $(basename "$0")

EOF
    exit 0
}


require_docker_ready() {
    command -v docker >/dev/null 2>&1 || fail "Docker is required. Install Docker Engine + the compose plugin, then re-run."

    "${DSUDO[@]}" docker info >/dev/null 2>&1 || fail "Docker daemon is not reachable. Ensure docker is running (systemctl enable --now docker)."

    if command -v docker-compose >/dev/null 2>&1 && ! "${DSUDO[@]}" docker compose version >/dev/null 2>&1; then
        fail "'docker-compose' (v1) is installed, but RITA requires Docker Compose v2 ('docker compose')."
    fi

    "${DSUDO[@]}" docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required (the 'docker compose' plugin). Install Docker Compose v2, then re-run."
}

# -------------------------
# early help check
# -------------------------
if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    show_help
fi

# --------------------------
# requirements checks
# --------------------------
status "Verifying system requirements..."

# sudo checks and setup
require_sudo

# special-case sudo for docker commands
DSUDO=()
if [[ "$(uname)" != "Darwin" && -n "${SUDO:-}" ]]; then
    DSUDO=("$SUDO")
fi

# docker checks
require_docker_ready

# command checks
require_cmd install
require_cmd cp

# --------------------------
# begin installation
# --------------------------
status "Installing RITA..."

# verify required source directories exist
require_dir "$SRC_FILES"
require_dir "$SRC_OPT"
require_dir "$SRC_ETC"

# -------------------------
# stop running old system
# -------------------------
status "Checking for existing RITA installation..."
if command -v rita >/dev/null 2>&1; then
    status "Stopping existing RITA..."
    "${DSUDO[@]}" rita down >/dev/null 2>&1 || true
elif [[ -x /usr/local/bin/rita ]]; then
    status "Stopping existing RITA..."
    "${DSUDO[@]}" /usr/local/bin/rita down >/dev/null 2>&1 || true
fi

# ---------------------------
# create required directories
# ---------------------------
status "Creating directories..."
"${DSUDO[@]}" mkdir -p "$ETC" "$OPT"
"${DSUDO[@]}" chmod 0755 "$ETC" "$OPT"

# -------------------------
# install rita command
# -------------------------
status "Installing rita..."
require_file "${SRC_OPT}/rita.sh"
RITA_BIN="/usr/local/bin/rita"
"${DSUDO[@]}" install -m 0755 "${SRC_OPT}/rita.sh" "$RITA_BIN"
command -v "$RITA_BIN" >/dev/null 2>&1 || fail "rita was not installed correctly to ${RITA_BIN}"

# -------------------------
# copy opt
# -------------------------
"${DSUDO[@]}" cp -a "${SRC_OPT}/." "${OPT}/"

# --------------------------------------------
# copy etc and preserve existing config.hjson
# --------------------------------------------
CFG_DST="${ETC}/config.hjson"
CFG_BACKUP=""

cleanup_cfg_backup() {
    if [[ -n "${CFG_BACKUP:-}" && -f "${CFG_BACKUP:-}" ]]; then
        "${DSUDO[@]}" rm -f "$CFG_BACKUP" || true
    fi
}
trap cleanup_cfg_backup EXIT

if [[ -f "$CFG_DST" ]]; then
    status "Preserving existing config.hjson..."
    CFG_BACKUP="$(mktemp /tmp/rita_config.hjson.XXXXXX)"
    "${DSUDO[@]}" cp -f "$CFG_DST" "$CFG_BACKUP"
    if [[ "$(uname)" == "Darwin" ]]; then
        "${DSUDO[@]}" chown root:wheel "$CFG_BACKUP" || true
    else
        "${DSUDO[@]}" chown root:root "$CFG_BACKUP" || true
    fi
    "${DSUDO[@]}" chmod 0644 "$CFG_BACKUP" || true
fi

"${DSUDO[@]}" cp -a "${SRC_ETC}/." "${ETC}/"

if [[ -n "$CFG_BACKUP" && -f "$CFG_BACKUP" ]]; then
    status "Restoring preserved config.hjson..."
    "${DSUDO[@]}" cp -f "$CFG_BACKUP" "$CFG_DST"
    if [[ "$(uname)" == "Darwin" ]]; then
        "${DSUDO[@]}" chown root:wheel "$CFG_DST" || true
    else
        "${DSUDO[@]}" chown root:root "$CFG_DST" || true
    fi
    "${DSUDO[@]}" chmod 0644 "$CFG_DST" || true
    "${DSUDO[@]}" rm -f "$CFG_BACKUP" || true
    CFG_BACKUP=""
fi

trap - EXIT

# -------------------------
# load installer env
# -------------------------
ENV="${OPT}/.env"
require_file "$ENV"
set -a
# shellcheck disable=SC1090
source "$ENV"
set +a

# -------------------------
# pull rita docker image
# -------------------------
status "Pulling RITA docker image..."
RITA_IMAGE="ghcr.io/activecm/rita:${RITA_VERSION}"
load_image() {
    local name="$1" pull_ref="$2" tar_path="$3"
    status "Loading ${name} image..."
    if [[ -f "$tar_path" ]]; then
        "${DSUDO[@]}" docker load -i "$tar_path"
    elif "${DSUDO[@]}" docker pull "$pull_ref"; then
        :
    else
        fail "Unable to load ${name} image. No local image at ${tar_path} and pull failed."
    fi
}

load_image "RITA" "$RITA_IMAGE" "${OPT}/rita-${RITA_VERSION}-image.tar.gz"
load_image "syslog-ng" "lscr.io/linuxserver/syslog-ng:latest" "${OPT}/syslog-ng-latest.tar.gz"
load_image "ClickHouse" "clickhouse/clickhouse-server:${CLICKHOUSE_VERSION}" "${OPT}/clickhouse-${CLICKHOUSE_VERSION}.tar.gz"


echo \
"
░█▀▀█ ▀█▀ ▀▀█▀▀ ─█▀▀█
░█▄▄▀ ░█─ ─░█── ░█▄▄█
░█─░█ ▄█▄ ─░█── ░█─░█ ${RITA_VERSION}

Brought to you by Active CounterMeasures©
"

cat >&2 <<EOF
Installation complete!
EOF
