#!/usr/bin/env bash

# helper.sh must be sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "This script must be sourced, not executed." >&2
    exit 1
fi

RED=""
YELLOW=""
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
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        SUDO=""
        SUDO_E=""
        export SUDO SUDO_E
        return 0
    fi

    # sudo must exist
    require_cmd "sudo"

    # check for passwordless sudo
    if sudo -n true >/dev/null 2>&1; then
        SUDO="sudo"
        SUDO_E="sudo -E"
        export SUDO SUDO_E
        return 0
    fi

    # check for password-required sudo if in an interactive shell
    if [[ -t 0 ]]; then
        status "Administrator privileges required. You may be prompted for your sudo password."
        if sudo -v; then
            SUDO="sudo"
            SUDO_E="sudo -E"
            export SUDO SUDO_E
            return 0
        fi
    fi

    fail "Missing administrator privileges. Please run with an account that has sudo privileges."
}

# require that a command exists
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

# require that a file exists
require_file() {
    [[ -f "$1" ]] || fail "Required file not found: $1"
}

# require that a file exists and is not empty
require_nonempty_file() {
    [[ -s "$1" ]] || fail "Required file missing or empty: $1"
}

# require that a directory exists
require_dir() {
    [[ -d "$1" ]] || fail "Required directory not found: $1"
}

# copy a file, ensuring the source exists and the destination parent directory exists
copy_file() {
    local src="$1"
    local dst="$2"

    require_file "$src"

    if [[ -d "$dst" ]]; then
        cp -- "$src" "$dst" || fail "Failed to copy file from $src to $dst"
        require_file "$dst/$(basename "$src")"
    else
        require_dir "$(dirname "$dst")"
        cp -- "$src" "$dst" || fail "Failed to copy file from $src to $dst"
        require_file "$dst"
    fi
}

# copy the contents of a directory (not the directory itself or dotfiles)
copy_dir_contents() {
    require_dir "$1"
    if ! find "$1" -mindepth 1 -maxdepth 1 ! -name '.*' -print -quit | grep -q .; then
        fail "Directory is empty: $1"
    fi
    require_dir "$2"
    cp -r -- "$1"/* "$2" || fail "Failed to copy contents from $1 to $2"
}

# create a new directory, failing if it already exists
create_new_dir() {
    if [[ -e "$1" ]]; then
        fail "Failed to create new directory, path already exists: $1"
    fi
    mkdir -p -- "$1" || fail "Failed to create directory: $1"
    require_dir "$1"
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
