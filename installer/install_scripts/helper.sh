#!/bin/bash


RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
NORMAL=$(tput sgr0)


fail() {
	#Something failed, exit.

	echo "${RED}$@, exiting.${NORMAL}" >&2
	exit 1
}


status() {
	if [ "$verbose" = 'yes' ]; then
		echo "== $@" >&2
	fi
}

verbose="yes"
