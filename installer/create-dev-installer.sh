#!/usr/bin/env bash
set -euo pipefail

# creates a dev installer with locally built Docker images

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RITA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# load helper functions
HELPER_FILE="$SCRIPT_DIR/helper.sh"
[[ -f "$HELPER_FILE" ]] || { echo "Helper functions script not found: $HELPER_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$HELPER_FILE"

status "Creating RITA dev installer..."

ARM=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arm)
            ARM=true
            shift
            ;;
        -*|--*)
            echo "Unknown option $1" >&2
            exit 1
            ;;
        *)
            shift
            ;;
    esac
done

# -------------------------
# create base installer
# -------------------------
"$SCRIPT_DIR/generate_installer.sh"

# -------------------------
# determine docker command
# -------------------------
if docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
else
    DOCKER_CMD=(sudo docker)
fi

# -------------------------
# determine version
# -------------------------
if VERSION="$(git -C "$RITA_DIR" describe --tags --exact-match 2>/dev/null)"; then
    :
elif VERSION="$(git -C "$RITA_DIR" describe --tags --dirty --always 2>/dev/null)"; then
    :
else
    fail "Unable to determine RITA version."
fi
[[ -n "$VERSION" ]] || fail "VERSION not set"

# paths
TARBALL="${SCRIPT_DIR}/rita-${VERSION}.tar.gz"
INSTALLER_DIR="${SCRIPT_DIR}/rita-${VERSION}-installer"
ENV_FILE="${INSTALLER_DIR}/files/opt/.env"
COMPOSE_FILE="${RITA_DIR}/docker-compose.yml"

# -------------------------
# unpack installer tarball
# -------------------------
require_file "$TARBALL"
tar -xzf "$TARBALL" -C "$SCRIPT_DIR"

# parse clickhouse version from .env
require_file "$ENV_FILE"
CLICKHOUSE_VERSION="$(awk -F= '$1=="CLICKHOUSE_VERSION"{v=$2} END{gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); gsub(/^"|"$|^\047|\047$/,"",v); print v}' "$ENV_FILE")"
[[ -n "${CLICKHOUSE_VERSION:-}" ]] || fail "CLICKHOUSE_VERSION is missing from $ENV_FILE"
status "Using CLICKHOUSE_VERSION=$CLICKHOUSE_VERSION"

# determine target platform
PLATFORM="linux/amd64"
if [ "${ARM}" = "true" ]; then
    PLATFORM="linux/arm64/v8"
fi

# verify docker is available
"${DOCKER_CMD[@]}" version >/dev/null 2>&1 || fail "docker is required and must be runnable"

# verify gzip is available
command -v gzip >/dev/null 2>&1 || fail "gzip is required"

# -------------------------
# build rita image
# -------------------------
status "Building RITA image for ${PLATFORM}..."
export DOCKER_BUILDKIT=1
export RITA_VERSION="${VERSION}"
if [ "${DOCKER_CMD[0]}" = "sudo" ]; then
    sudo env DOCKER_DEFAULT_PLATFORM="$PLATFORM" BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker compose --project-directory "$RITA_DIR" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build rita
else
    DOCKER_DEFAULT_PLATFORM="$PLATFORM" BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker compose --project-directory "$RITA_DIR" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build rita
fi

# -------------------------
# save images to disk
# -------------------------
INSTALL_OPT="${INSTALLER_DIR}/files/opt"
require_dir "$INSTALL_OPT"

RITA_IMAGE="ghcr.io/activecm/rita:${VERSION}"

# docker save --platform requires Docker 26+
status "Saving RITA image..."
"${DOCKER_CMD[@]}" save --platform "$PLATFORM" "$RITA_IMAGE" | gzip -c > "$INSTALL_OPT/rita-${VERSION}-image.tar.gz"

save_pulled_image() {
    local name="$1" ref="$2" outfile="$3"
    status "Saving ${name} image..."
    "${DOCKER_CMD[@]}" pull --platform "$PLATFORM" "$ref"
    "${DOCKER_CMD[@]}" save --platform "$PLATFORM" "$ref" | gzip -c > "$outfile"
}

save_pulled_image "syslog-ng" "lscr.io/linuxserver/syslog-ng:latest" "$INSTALL_OPT/syslog-ng-latest.tar.gz"
save_pulled_image "ClickHouse" "clickhouse/clickhouse-server:${CLICKHOUSE_VERSION}" "$INSTALL_OPT/clickhouse-${CLICKHOUSE_VERSION}.tar.gz"

# sanity checks
require_nonempty_file "$INSTALL_OPT/rita-${VERSION}-image.tar.gz"
require_nonempty_file "$INSTALL_OPT/syslog-ng-latest.tar.gz"
require_nonempty_file "$INSTALL_OPT/clickhouse-${CLICKHOUSE_VERSION}.tar.gz"

# -------------------------
# repack tarball
# -------------------------
if [ "$(uname -s)" = "Darwin" ]; then
    tar --no-xattrs --disable-copyfile -czf "$TARBALL" -C "$SCRIPT_DIR" "$(basename "$INSTALLER_DIR")"
else
    tar -czf "$TARBALL" -C "$SCRIPT_DIR" "$(basename "$INSTALLER_DIR")"
fi

# clean up
remove_dir "$INSTALLER_DIR"

status "Dev installer created: $(basename "$TARBALL")"
status "Platform: ${PLATFORM}"
