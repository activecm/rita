#!/bin/bash

RED=""
YELLOW=""
NORMAL=""

# enable verbose output by default
verbose="yes"

# use colors if terminal supports it
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
	RED=$(tput setaf 1)
	YELLOW=$(tput setaf 3)
	NORMAL=$(tput sgr0)
fi

# something failed, exit
fail() {
	echo "${RED}$*, exiting.${NORMAL}" >&2
	exit 1
}

# print status message if verbose is enabled
status() {
	if [ "${verbose:-}" = "yes" ]; then
		echo "== $*" >&2
	fi
}