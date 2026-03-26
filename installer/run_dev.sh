#!/usr/bin/env bash
set -euo pipefail

# dev script for testing the installer on a remote droplet.
# generates the installer, copies it to the droplet, runs it, then runs tests.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RITA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

droplet_ip="$1"
if [[ -z "$droplet_ip" ]]; then
    echo "Usage: $0 <droplet_ip>" >&2
    exit 1
fi

# get RITA version from git
if VERSION="$(git -C "$RITA_DIR" describe --tags --exact-match 2>/dev/null)"; then
    :  # release / ci
elif VERSION="$(git -C "$RITA_DIR" describe --tags --dirty --always 2>/dev/null)"; then
    :  # dev
else
    echo "Unable to determine RITA_VERSION." >&2
    exit 1
fi
[[ -n "$VERSION" ]] || { echo "Unable to determine RITA_VERSION." >&2; exit 1; }

# generate dev installer (bundles Docker images for offline install)
"${SCRIPT_DIR}/create-dev-installer.sh"

INSTALLER_TARBALL="${SCRIPT_DIR}/rita-${VERSION}.tar.gz"
[[ -f "$INSTALLER_TARBALL" ]] || { echo "RITA installer tarball not found." >&2; exit 1; }

# copy tarball to droplet, extract, and run
scp "$INSTALLER_TARBALL" "root@$droplet_ip":/root/
ssh -t "root@$droplet_ip" "cd /root && tar -xf rita-${VERSION}.tar.gz && cd rita-${VERSION}-installer && ./install_rita.sh"

# copy over test data
scp -r "${RITA_DIR}/test_data/open_sni" "root@$droplet_ip":/root/sample_logs

# copy over test script and run it
scp "${SCRIPT_DIR}/test_installed.sh" "root@$droplet_ip":/root/test_installed.sh
ssh -t "root@$droplet_ip" /root/test_installed.sh "$VERSION"
