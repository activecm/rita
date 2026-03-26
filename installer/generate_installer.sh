#!/usr/bin/env bash
set -euo pipefail

# this script generates the RITA installer

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RITA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# load helper functions
HELPER_FILE="$SCRIPT_DIR/helper.sh"
[[ -f "$HELPER_FILE" ]] || { echo "Helper functions script not found: $HELPER_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$HELPER_FILE"

# get RITA version from git
if VERSION="$(git -C "$RITA_DIR" describe --tags --exact-match 2>/dev/null)"; then
    :  # release / ci
elif VERSION="$(git -C "$RITA_DIR" describe --tags --dirty --always 2>/dev/null)"; then
    :  # dev
else
    fail "Unable to determine RITA_VERSION."
fi
[[ -n "$VERSION" ]] || { echo "Unable to determine RITA_VERSION." >&2; exit 1; }

status "Generating installer for RITA $VERSION..."

# create staging directory
INSTALLER_DIR="${SCRIPT_DIR}/rita-$VERSION-installer"
OUTPUT_TARBALL="${SCRIPT_DIR}/rita-$VERSION.tar.gz"
remove_dir "$INSTALLER_DIR"
remove_file "$OUTPUT_TARBALL"
create_new_dir "$INSTALLER_DIR"

# create subfolders
SCRIPTS="$INSTALLER_DIR/scripts"
FILES="$INSTALLER_DIR/files"
create_new_dir "$SCRIPTS"
create_new_dir "$FILES"

INSTALL_OPT="$FILES/opt"
INSTALL_ETC="$FILES/etc"
create_new_dir "$INSTALL_OPT"
create_new_dir "$INSTALL_ETC"

# copy entrypoint
copy_file "${SCRIPT_DIR}/install_rita.sh" "$INSTALLER_DIR"

# copy helper scripts
copy_file "${SCRIPT_DIR}/helper.sh" "$SCRIPTS"

# copy configuration files to /files/etc
copy_dir_contents "${RITA_DIR}/deployment" "$INSTALL_ETC"
rm -f "$INSTALL_ETC/threat_intel_feeds/.gitkeep"
copy_file "${RITA_DIR}/default_config.hjson" "$INSTALL_ETC/config.hjson"

# copy installed files to /files/opt
copy_file "${RITA_DIR}/rita.sh" "$INSTALL_OPT"
copy_file "${RITA_DIR}/.env.production" "${INSTALL_OPT}/.env"
copy_file "${RITA_DIR}/docker-compose.prod.yml" "${INSTALL_OPT}/docker-compose.yml"
copy_file "${RITA_DIR}/LICENSE" "${INSTALL_OPT}/LICENSE"
copy_file "${RITA_DIR}/README.md" "${INSTALL_OPT}/README"

# update version variables
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install_rita.sh"
    remove_file "${INSTALLER_DIR}/install_rita.sh.bak"
else
    sed -i "s/REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install_rita.sh"
fi

# write RITA_VERSION into the env file so docker compose resolves the image tag
printf 'RITA_VERSION=%s\n' "${VERSION}" >> "${INSTALL_OPT}/.env"

# create tarball
tar -czf "$OUTPUT_TARBALL" -C "$SCRIPT_DIR" "$(basename "$INSTALLER_DIR")"

# clean up staging directory
remove_dir "$INSTALLER_DIR"

status "Finished generating installer: $(basename "$OUTPUT_TARBALL")"
