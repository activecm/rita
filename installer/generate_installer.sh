#!/usr/bin/env bash
set -euo pipefail

# This script generates the RITA installer by creating a temporary folder in the current directory named 'stage'
# and copies files that must be in the installer into the stage folder.
# Once all directories are placed in stage, it is compressed and stage is deleted.

ZEEK_VERSION=6.2.1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RITA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# load helper functions
HELPER_FILE="$SCRIPT_DIR/install_scripts/helper.sh"
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

# change working directory to directory of this script
# pushd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" > /dev/null

# create staging directory
INSTALLER_DIR="${SCRIPT_DIR}/rita-$VERSION-installer"
OUTPUT_TARBALL="${SCRIPT_DIR}/rita-$VERSION.tar.gz"
remove_dir "$INSTALLER_DIR"
remove_file "$OUTPUT_TARBALL"
create_new_dir "$INSTALLER_DIR"

# create ansible subfolders
SCRIPTS="$INSTALLER_DIR/scripts"
ANSIBLE_FILES="$INSTALLER_DIR/files"
create_new_dir "$SCRIPTS"
create_new_dir "$ANSIBLE_FILES"

# create subfolders (for files that installed RITA will contain)
INSTALL_OPT="$ANSIBLE_FILES"/opt
INSTALL_ETC="$ANSIBLE_FILES"/etc
create_new_dir "$INSTALL_OPT"
create_new_dir "$INSTALL_ETC"

# copy files in base dir
copy_file "${SCRIPT_DIR}/install-rita-zeek-here.sh" "$INSTALLER_DIR"
copy_file "${SCRIPT_DIR}/install_scripts/install_zeek.yml" "$INSTALLER_DIR"
copy_file "${SCRIPT_DIR}/install_scripts/install_rita.yml" "$INSTALLER_DIR"
copy_file "${SCRIPT_DIR}/install_scripts/install_pre.yml" "$INSTALLER_DIR"

copy_file "${SCRIPT_DIR}/install_scripts/install_rita.sh" "$INSTALLER_DIR" # entrypoint

# copy files to helper script folder
copy_file "${SCRIPT_DIR}/install_scripts/ansible-installer.sh" "$SCRIPTS"
copy_file "${SCRIPT_DIR}/install_scripts/helper.sh" "$SCRIPTS"
copy_file "${SCRIPT_DIR}/install_scripts/sshprep.sh" "$SCRIPTS"

# copy files to the ansible files folder
copy_file "${SCRIPT_DIR}/install_scripts/docker-compose" "$ANSIBLE_FILES" # docker-compose v1 backwards compatibility script

# copy over configuration files to /files/etc
copy_dir_contents "${RITA_DIR}/deployment" "$INSTALL_ETC"
copy_file "${RITA_DIR}/default_config.hjson" "$INSTALL_ETC/config.hjson"

# copy over installed files to /opt
copy_file "${RITA_DIR}/rita.sh" "$INSTALL_OPT"
curl --fail --silent --show-error -o "${INSTALL_OPT}/zeek" https://raw.githubusercontent.com/activecm/docker-zeek/master/zeek
chmod +x "${INSTALL_OPT}/zeek"
curl --fail --silent --show-error -o "${INSTALL_OPT}/zeek_log_transport.sh" https://raw.githubusercontent.com/activecm/zeek-log-transport/refs/heads/master/zeek_log_transport.sh
chmod +x "${INSTALL_OPT}/zeek_log_transport.sh"
copy_file "${RITA_DIR}/.env.production" "${INSTALL_OPT}/.env"
copy_file "${RITA_DIR}/docker-compose.prod.yml" "${INSTALL_OPT}/docker-compose.yml"
copy_file "${RITA_DIR}/LICENSE" "${INSTALL_OPT}/LICENSE"
copy_file "${RITA_DIR}/README.md" "${INSTALL_OPT}/README"

# update version variables for files that need them
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i'.bak' "s/RITA_REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install-rita-zeek-here.sh"
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install_rita.yml" 
    sed -i'.bak' "s/REPLACE_ME/${ZEEK_VERSION}/g" "${INSTALLER_DIR}/install_zeek.yml" 
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install_rita.sh"
    sed -i'.bak' "s#ghcr.io/activecm/rita:latest#ghcr.io/activecm/rita:${VERSION}#g" "${INSTALL_OPT}/docker-compose.yml"
    
    remove_file "${INSTALLER_DIR}/install-rita-zeek-here.sh.bak"
    remove_file "${INSTALLER_DIR}/install_rita.yml.bak"
    remove_file "${INSTALLER_DIR}/install_zeek.yml.bak"
    remove_file "${INSTALLER_DIR}/install_rita.sh.bak"
    remove_file "${INSTALL_OPT}/docker-compose.yml.bak"
else 
    sed -i  "s/RITA_REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install-rita-zeek-here.sh"
    sed -i  "s/REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install_rita.yml" 
    sed -i  "s/REPLACE_ME/${ZEEK_VERSION}/g" "${INSTALLER_DIR}/install_zeek.yml" 
    sed -i  "s/REPLACE_ME/${VERSION}/g" "${INSTALLER_DIR}/install_rita.sh"
    sed -i  "s#ghcr.io/activecm/rita:latest#ghcr.io/activecm/rita:${VERSION}#g" "${INSTALL_OPT}/docker-compose.yml"
fi

# create tarball from staging folder
tar -czf "$OUTPUT_TARBALL" -C "$SCRIPT_DIR" "$(basename "$INSTALLER_DIR")"

# delete staging folder
remove_dir "$INSTALLER_DIR"

status "Finished generating installer."