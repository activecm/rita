#!/usr/bin/env bash
set -euo pipefail

# Ansible Install Script
# This script installs Ansible on the current system using pipx.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# cd to the directory where this script is located
pushd "$SCRIPT_DIR" > /dev/null

# load helper functions
HELPER_FILE="$SCRIPT_DIR/helper.sh"
[[ -f "$HELPER_FILE" ]] || { echo "Helper functions script not found: $HELPER_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$HELPER_FILE"

# verify that user has sudo privileges
require_sudo

# enable any needed repositories
enable_repositories() {
	status "Enabling necessary package repositories..."

	if [[ ! -s /etc/os-release ]]; then
		fail "Unable to read /etc/os-release"
	else
		. /etc/os-release
		case "$ID/$VERSION_ID" in
		rocky/8*|almalinux/8*)
			$SUDO dnf config-manager --set-enabled powertools
			$SUDO dnf install -y epel-release
			;;
		rocky/9*)
			$SUDO dnf config-manager --set-enabled crb
			$SUDO dnf install -y epel-release
			;;
		centos/9)
			$SUDO dnf config-manager --set-enabled crb
			$SUDO dnf install -y epel-release epel-next-release
			;;
		rhel/8*)
			$SUDO subscription-manager repos --enable codeready-builder-for-rhel-8-$(arch)-rpms
			$SUDO dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
			;;
		rhel/9*)
			$SUDO subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
			$SUDO dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
			;;
		ubuntu/*)
			$SUDO apt update
			;;
		*)
			fail "Unsupported Distribution $ID/$VERSION_ID"
			;;
		esac
	fi
}


# Install a required executable 
# This function attempts to install a system package only if the corresponding binary does
# not already exist in PATH. This is only intended for tools that provide a real executable
# $1 = binary name to check for (e.g., "python3", "pip3", "curl")
# $2 = space-separated list of package names that provide the binary (preferred packages first)
install_tool() {
    binary="$1"
    potential_packages="$2"

    # if the binary already exists, nothing to do
    if type -path "$binary" >/dev/null 2>&1; then
        status "== $binary executable is already installed"
        return 0
    fi

    status "== Installing package that contains $binary"

    # Ubuntu
    if command -v apt-get >/dev/null 2>&1; then
        for pkg in $potential_packages; do
            if ! type -path "$binary" >/dev/null 2>&1; then
                $SUDO apt-get -q -y install "$pkg"
            fi
        done

    # RHEL / CentOS / Rocky / Alma
    elif command -v yum >/dev/null 2>&1; then
        for pkg in $potential_packages; do
            if ! type -path "$binary" >/dev/null 2>&1; then
                $SUDO yum -y -q -e 0 install "$pkg"
            fi
        done

    else
        fail "Unable to install packages: unsupported package manager"
    fi

    # final verification
    if type -path "$binary" >/dev/null 2>&1; then
        return 0
    else
        echo "WARNING: Unable to install $binary from system package" >&2
        return 1
    fi
}

install_ansible() {
    # Make sure venv support actually works on this system.
    if ! python3 -m venv --help >/dev/null 2>&1; then
        fail "Python venv support is missing on this system. Cannot continue."
    fi

    # Bootstrap a local virtualenv whose only job is to host pipx,
    # so we never touch system Python even on PEP 668 distros.
    python3 -m venv .ansenv || fail "Unable to create Python virtual environment"

    # shellcheck disable=SC1091
    source .ansenv/bin/activate

    # Make sure pip in the venv is up to date before installing pipx
    python3 -m pip install --upgrade pip || fail "Unable to upgrade pip in virtual environment"

    # install pipx into this bootstrap venv
    python3 -m pip install pipx || fail "Unable to install pipx in virtual environment"

    # ask pipx to ensure ~/.local/bin is added to future shells' PATH
    pipx ensurepath --prepend || true

    # install a specific, pinned ansible-core via pipx.
    # pipx will create/own its own venv under ~/.local/pipx/venvs/ansible-core
    # and expose the entrypoints (ansible, ansible-playbook, ansible-galaxy)
    # under ~/.local/bin/.
    pipx install "ansible-core==2.15.13" --force || fail "Unable to install ansible-core with pipx"

    deactivate

    # After deactivating, PATH is restored to its previous value, so any edits we
    # made inside the venv are lost. Re-ensure ~/.local/bin is on PATH for the rest
    # of this script so ansible/ansible-playbook/ansible-galaxy are visible.
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) export PATH="$HOME/.local/bin:$PATH" ;;
    esac

    # Sanity check: make sure the expected Ansible CLIs are now visible
    for bin in ansible ansible-playbook ansible-galaxy; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            fail "$bin not found in PATH after pipx installation"
        fi
    done

	# Link Ansible binaries globally so they work for root, users, cron, and systemd
	status "Linking Ansible binaries globally..."

	for bin in ansible ansible-playbook ansible-galaxy; do
		SRC="$(command -v "$bin" || true)"
		if [ -n "$SRC" ]; then
			$SUDO ln -sf "$SRC" "/usr/local/bin/$bin"
		else
			fail "Unable to locate $bin for global linking"
		fi
	done

	# install requisite ansible collections
	status "Installing required Ansible collections..."
	ansible-galaxy collection install community.general community.docker --force
}



# ======== main script starts here ========

# require sudo privileges
require_sudo

# check if macOS, and install ansible via brew if so
if [[ "$(uname)" == "Darwin" ]]; then
	# check if ansible is installed
	which -s ansible
	if [[ $? != 0 ]] ; then
		# check if homebrew is installed
		which -s brew
		if [[ $? != 0 ]] ; then
			fail "Homebrew is required to install Ansible."
		fi
		# install ansible via homebrew
		echo "Installing Ansible via brew..."
		brew install ansible
	else 
		echo "== Ansible is already installed."
	fi
else # assume linux
	# enable necessary repositories
	enable_repositories

	status "Installing required tools..."

	# install python dependencies
	install_tool python3 "python3"
	install_tool pip3 "python3-pip"
	
	# ensure python venv support is available - cannot use install_tool for this since
	# venv is a module, not a binary
	# Ensure `python3 -m venv` actually works on Debian/Ubuntu.
	# On these systems the stdlib venv module requires the extra
	# `python3-venv` package (which provides ensurepip).
	# This is safe to run even if it's already installed: `apt-get install`
	# is idempotent and will return success in that case.
	if command -v apt-get >/dev/null 2>&1; then
		status "Ensuring python3-venv is installed for virtualenv support"
		$SUDO apt-get -q -y install python3-venv
	fi

	# sanity check after install
	if ! python3 -m venv --help >/dev/null 2>&1; then
		fail "python3 venv module is still not available after installation"
	fi

	# verify that pip is functional
	if ! python3 -m pip -V >/dev/null 2>&1; then
    	fail "Unable to run python3's pip"
	fi

	# install other dependencies
	install_tool wget "wget"
	install_tool curl "curl"

	# install ansible
	install_ansible
fi

# ensure /usr/local/bin is in PATH
status "Ensuring /usr/local/bin is in PATH..."
if ! printf '%s\n' "$PATH" | grep -qE '(^|:)/usr/local/bin(:|$)'; then
    echo "Adding /usr/local/bin to PATH" >&2

    # For current session
    export PATH="$PATH:/usr/local/bin"

    # For future logins (prefer system-wide drop-in if available)
    if [ -d /etc/profile.d ]; then
        echo 'export PATH="$PATH:/usr/local/bin"' | $SUDO tee /etc/profile.d/local-bin-path.sh >/dev/null
    elif [ -s /etc/profile ]; then
        echo 'export PATH="$PATH:/usr/local/bin"' | $SUDO tee -a /etc/profile >/dev/null
    else
        echo "Warning: Unable to persist /usr/local/bin in PATH" >&2
    fi
fi

# switch back to original working directory
popd > /dev/null

status "Final verification..."
# verify the binary is resolvable
if ! command -v ansible-playbook >/dev/null 2>&1; then
    fail "ansible-playbook is not in PATH after installation"
fi
# verify ansible-playbook executes
if ! ansible-playbook --version >/dev/null 2>&1; then
    fail "ansible-playbook is present but failed to execute"
fi
# verify ansible-galaxy executes
if ! ansible-galaxy --version >/dev/null 2>&1; then
    fail "ansible-galaxy is present but failed to execute"
fi

status "Ansible installation complete"