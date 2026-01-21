#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RITA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

droplet_ip="$1"
if [[ -z "$droplet_ip" ]]; then
    echo "droplet ip was not provided"
    exit 1
fi

# get RITA version from git
if VERSION="$(git -C "$RITA_DIR" describe --tags --exact-match 2>/dev/null)"; then
    :  # release / ci
elif VERSION="$(git -C "$RITA_DIR" describe --tags --dirty --always 2>/dev/null)"; then
    :  # dev
else
    fail "Unable to determine RITA_VERSION."
fi
[[ -n "$VERSION" ]] || { echo "Unable to determine RITA_VERSION." >&2; exit 1; }


# generate installer
"${SCRIPT_DIR}/generate_installer.sh"

INSTALLER_DIR="${SCRIPT_DIR}/rita-${VERSION}-installer"

# verify tar ball exists
[[ -f "${INSTALLER_DIR}.tar.gz" ]] || { echo "RITA installer tarball not found." >&2; exit 1; }
tar -xf "${INSTALLER_DIR}.tar.gz"
[[ -f "${INSTALLER_DIR}/install_rita.sh" ]] || { echo "RITA installer script not found." >&2; exit 1; }
"${INSTALLER_DIR}/install_rita.sh" "root@$droplet_ip"

# # # # ansible-playbook -i digitalocean_inventory.py -e "install_hosts=${droplet_ip}" "./rita-${VERSION}-installer/install_rita.yml"

# copy over test data
scp -r "${RITA_DIR}/test_data/open_sni" "root@$droplet_ip":/root/sample_logs

# # copy over test script
scp "${SCRIPT_DIR}/test_installed.sh" "root@$droplet_ip":/root/test_installed.sh

# run test script
ssh -t "root@$droplet_ip" /root/test_installed.sh "$VERSION"
#