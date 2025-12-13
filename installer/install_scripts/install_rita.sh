#!/bin/bash
set -euo pipefail

# RITA Install Script
# This script installs Ansible and uses it to install RITA and Zeek on a target system.

RITA_VERSION="REPLACE_ME"
_INSTALL_ZEEK=true

# Function `show_help` displays usage information
show_help() {
    echo "Usage: $0 [--disable-zeek] <target_hostname_or_ip>" >&2
    echo "Example: $0 127.0.0.1" >&2
    exit 1
}

# No arguments provided
if [ $# -eq 0 ]; then
    show_help
fi

# Parse optional flag
if [ "${1:-}" = "--disable-zeek" ]; then
    _INSTALL_ZEEK=false
    shift
fi

# Hostname/IP must now be present
if [ $# -eq 0 ]; then
    show_help
fi

install_target="$1"
shift

# If someone puts --disable-zeek after the host, still support it:
if [ "${1:-}" = "--disable-zeek" ]; then
    _INSTALL_ZEEK=false
    shift
fi

# Change working directory to directory of this script
pushd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" > /dev/null

# Load helper functions
source ./scripts/helper.sh

# Install ansible
./scripts/ansible-installer.sh

# Install rita
status "Installing rita via ansible on $install_target"
if [ "$install_target" = "localhost" -o "$install_target" = "127.0.0.1" -o "$install_target" = "::1" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            # TODO support macOS install target
            echo "${YELLOW}Installing RITA via Ansible on the local system is not yet supported on MacOS.${NORMAL}"
            exit 1
        fi
	status "When prompted for a BECOME password, enter your sudo password. If your user does not need one for sudo, just press Enter."
	if [ "$_INSTALL_ZEEK" = 'true' ]; then
		ansible-playbook --connection=local -K -i "127.0.0.1," -e "install_hosts=127.0.0.1," install_pre.yml install_rita.yml install_zeek.yml
	else
		ansible-playbook --connection=local -K -i "127.0.0.1," -e "install_hosts=127.0.0.1," install_pre.yml install_rita.yml
	fi
else
	status "Setting up future ssh connections to $install_target .  You may be asked to provide your ssh password to $install_target ."
	./scripts/sshprep.sh "$install_target"
	status "When prompted for a BECOME password, enter your sudo password for $install_target. If your user does not need one for sudo, just press Enter."
	if [ "$_INSTALL_ZEEK" = 'true' ]; then
		# TODO: fix and re-implement cron setup after RITA#65 is resolved
		# status "Creating Zeek log transport Cron file"
		# rm -f zeek_log_transport.cron ; touch zeek_log_transport.cron
		# #NON_ROOT_ACCOUNT_NAME will be replaced after being placed on the target system (by an ansible recipe in install_zeek.yml
		# echo "5 * * * * NON_ROOT_ACCOUNT_NAME /usr/local/bin/zeek_log_transport.sh --dest $install_target" >>zeek_log_transport.cron

		ansible-playbook -K -i "${install_target}," -e "install_hosts=${install_target}," install_pre.yml install_rita.yml install_zeek.yml
	else
		ansible-playbook -K -i "${install_target}," -e "install_hosts=${install_target}," install_pre.yml install_rita.yml
	fi
fi


echo \
"
░█▀▀█ ▀█▀ ▀▀█▀▀ ─█▀▀█
░█▄▄▀ ░█─ ─░█── ░█▄▄█
░█─░█ ▄█▄ ─░█── ░█─░█ ${RITA_VERSION}

Brought to you by Active CounterMeasures©
"
echo "Installation complete!"
echo ""

if [ "$_INSTALL_ZEEK" = 'true' ]; then
	echo "Please run the following commands on any new zeek sensors" >&2
	echo "	zeek start ; zeek enable" >&2
	echo "" >&2
fi

# switch back to original working directory
popd > /dev/null
