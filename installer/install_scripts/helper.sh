#!/usr/bin/env bash

# helper.sh must be sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "This script must be sourced, not executed." >&2
    exit 1
fi

RED=""
YELLOW=""
BLUE=""
GREEN=""
NORMAL=""

# SUDO and SUDO_E are intentionally initialized to empty here.
# helper functions will never use sudo unless a script explicitly opts in
# by calling require_sudo(). This prevents accidental privilege escalation in scripts that source
# helper.sh but are not intended to run as root.
SUDO=""
SUDO_E=""
export SUDO SUDO_E

# enable verbose output by default
verbose="yes"

# use colors if terminal supports it
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
	RED=$(tput setaf 1)
	YELLOW=$(tput setaf 3)
	BLUE=$(tput setaf 4)
	GREEN=$(tput setaf 2)
	NORMAL=$(tput sgr0)
fi

# something failed, exit
fail() {
	echo "${RED}$*, exiting.${NORMAL}" >&2
	exit 1
}

# print status message if verbose is enabled
status() {
	if [[ "${verbose:-}" == "yes" ]]; then
		echo "== $*" >&2
	fi
}

# ensure script is run with sudo privileges 
require_sudo() {
    # check if running as root
    if [[ "$EUID" -eq 0 ]]; then
        SUDO=""
        SUDO_E=""
        export SUDO SUDO_E
        return 0
    fi

    # check that we are able to run commands with sudo (non-interactive)
    if sudo -v </dev/null 2>/dev/null; then
        SUDO="sudo"
        SUDO_E="sudo -E"
        export SUDO SUDO_E
        return 0
    fi

    fail "Missing administrator privileges. Please run with an account that has sudo privileges."
}

# require that a command exists
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

# require that a file exists
require_file() {
	[[ -f "$1" ]] || { fail "Required file not found: $1"; }
}

# require that a directory exists
require_dir() {
	[[ -d "$1" ]] || { fail "Required directory not found: $1"; }
}

# require that an environment variable is set and non-empty
require_env() {
    [[ -n "${!1:-}" ]] || fail "Required environment variable not set or empty: $1"
}

# copy a file, ensuring the source exists and the destination parent directory exists
copy_file() {
    local src="$1"
    local dst="$2"

    require_file "$src"

	# if user provided a directory as destination, copy into that directory
    if [[ -d "$dst" ]]; then
        cp -- "$src" "$dst" || fail "Failed to copy file from $src to $dst"
        require_file "$dst/$(basename "$src")"
    else
		# if user provided a full destination path (including filename), ensure parent directory exists
        require_dir "$(dirname "$dst")"
        cp -- "$src" "$dst" || fail "Failed to copy file from $src to $dst"
        require_file "$dst"
    fi
}


# copy a directory recursively, ensuring the source exists and the destination parent directory exists
copy_dir() {
    require_dir "$1"
    require_dir "$2"
    cp -r -- "$1" "$2" || fail "Failed to copy directory from $1 to $2"
}

# this version does not copy the dir itself, nor any dotfiles inside it
copy_dir_contents() {
    require_nonempty_dir "$1"
    require_dir "$2"
    cp -r -- "$1"/* "$2" || fail "Failed to copy contents from $1 to $2"
}

create_new_dir() {
    if [[ -e "$1" ]]; then
        fail "Failed to create new directory, path already exists: $1"
    fi
    mkdir -p -- "$1" || fail "Failed to create directory: $1"
    require_dir "$1"
}

# check if a directory exists and is empty
dir_is_empty() {
    [[ -d "$1" ]] || return 1
    [[ -z "$(ls -A "$1" 2>/dev/null)" ]]
}

# ensure a directory exists; create it if missing
ensure_dir() {
    [[ -d "$1" ]] && return 0
	create_new_dir "$1"
}

# ensure a directory exists (create if not) and is empty
ensure_empty_dir() {
    ensure_dir "$1"
    if ! dir_is_empty "$1"; then
        clear_dir "$1"
    fi
}

# require that a directory has at least one non-dot entry (file or dir)
require_nonempty_dir() {
    require_dir "$1"
    if ! find "$1" -mindepth 1 -maxdepth 1 ! -name '.*' -print -quit | grep -q .; then
        fail "Directory is empty: $1"
    fi
}

# remove a file (or symlink) if it exists
remove_file() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
    	rm -f -- "$path" || fail "Failed to remove file: $path"
    fi
}

# remove a directory if it exists
remove_dir() {
    if [[ -d "$1" ]]; then
    	rm -rf -- "$1" || fail "Failed to remove directory: $1"
    elif [[ -e "$1" || -L "$1" ]]; then
        fail "Expected directory but found non-directory: $1"
    fi
}

# delete everything inside a directory, but keep the directory itself
clear_dir() {
    [[ -n "${1:-}" ]] || fail "clear_dir: missing dir"
    local dir="$1"

    if [[ -e "$dir" || -L "$dir" ]]; then
        [[ -d "$dir" ]] || fail "Expected directory but found non-directory: $dir"
    else
        ensure_dir "$dir"
    fi

    # Delete contents (including dotfiles) but not the directory itself.
    find -- "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + || fail "Failed to clear directory: $dir"
}