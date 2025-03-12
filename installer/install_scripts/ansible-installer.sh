#!/bin/bash
#Copyright 2024, Active Countermeasures
#Written by WS with guidance from NG
pushd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" > /dev/null


source ./helper.sh

#This script installs ansible and supporting tools needed for rita
#and/or AC-Hunter on a deb, rpm, port, or brew package -based system. 
#It also patches all installed packages.

#The general aim is that this will work on multiple Linux distributions
#that use either .deb or .rpm packages, though more testing is needed.
#Please contact bill@activecountermeasures.com if you have any updates
#on errors or compatibility issues found.  Many thanks to NG for 
#the original idea and multiple improvements.


ansible_installer_version="0.3.7"

#Uncomment one of the following lines to set the default program to download and install
data_needed="rita"




require_sudo() {
	#Stops the script if the user does not have root priviledges and cannot sudo
	#Additionally, sets $SUDO to "sudo" and $SUDO_E to "sudo -E" if needed.

	status "Checking sudo; if asked for a password this will be your user password on the machine running the installer."		#================
	if [ "$EUID" -eq 0 ]; then
		SUDO=""
		SUDO_E=""
		return 0
	elif sudo -v; then			#Confirms I'm allowed to run commands via sudo
		SUDO="sudo"
		SUDO_E="sudo -E"
		return 0
	else
		#I'm _not_ allowed to run commands as sudo.
		echo "It does not appear that user $USER has permission to run commands under sudo." >&2
		if grep -q '^wheel:' /etc/group ; then
			fail "Please run    usermod -aG wheel $USER   as root, log out, log back in, and retry the install"
		elif grep -q '^sudo:' /etc/group ; then
			fail "Please run    usermod -aG sudo $USER   as root, log out, log back in, and retry the install"
		else
			fail "Please give this user the ability to run commands as root under sudo, log out, log back in, and retry the install"
		fi
	fi
}


tmp_dir() {
	mkdir -p "$HOME/tmp/"
	tdirname=`mktemp -d -q "$HOME/tmp/install-tools.XXXXXXXX" </dev/null`
	if [ ! -d "$tdirname" ]; then
		fail "Unable to create temporary directory."
	fi
	echo "$tdirname"
}

enable_repositories() {
	status "Enable additional repository/repositories"		#================

	if [ ! -s /etc/os-release ]; then
		fail "Unable to read /etc/os-release"
	else
		. /etc/os-release
		case "$ID/$VERSION_ID" in
		alma/8*|almalinux/8*|rocky/8*)
			$SUDO dnf config-manager --set-enabled powertools
			$SUDO dnf install -y epel-release
			;;
		alma/9*|almalinux/9*|rocky/9*)
			$SUDO dnf config-manager --set-enabled crb
			$SUDO dnf install -y epel-release
			;;
		centos/7)
			$SUDO yum install epel-release
			;;
		centos/8)
			$SUDO dnf config-manager --set-enabled powertools
			$SUDO dnf install epel-release epel-next-release
			;;
		centos/9)
			$SUDO dnf config-manager --set-enabled crb
			$SUDO dnf install epel-release epel-next-release
			;;
		debian/12|zorin/16)
			:	#Does not appear that any extra repositories are needed
			;;
		kali/*)
			$SUDO apt update
			$SUDO apt install software-properties-common || sudo apt install python-software-properties
			$SUDO add-apt-repository --yes --update ppa:ansible/ansible
			;;
		ol/*)											#Oracle linux, which is also the base for security onion 2470
			:
			;;
		rhel/7)
			$SUDO subscription-manager repos --enable rhel-*-optional-rpms --enable rhel-*-extras-rpms --enable rhel-ha-for-rhel-*-server-rpms
			$SUDO yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
			;;
		rhel/8)
			$SUDO subscription-manager repos --enable codeready-builder-for-rhel-8-$(arch)-rpms
			$SUDO dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
			;;
		rhel/9)
			$SUDO subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
			$SUDO dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
			;;
		fedora/*)
			:										#It does not appear that fedora needs any extra repositories
			;;
		pop/*)
			:										#popos does not appear to need any extra repositories
			;;
		ubuntu/*)
			$SUDO apt update
			$SUDO apt install software-properties-common || sudo apt install python-software-properties
			$SUDO add-apt-repository --yes --update ppa:ansible/ansible
			;;
		*)
			fail "unknown OS $ID/$VERSION_ID"
			;;
		esac
	fi
}

patch_system() {
	#Make sure all currently installed packages are updated.  This has the added benefit
	#that we update the package metadata for later installing new packages.

	status "Patching system"		#================
	if [ -x /usr/bin/apt-get -a -x /usr/bin/dpkg-query ]; then
		if [ -s /etc/os-release ] && egrep -iq '(^ID=ubuntu|^ID=pop|^ID=Zorin OS)' /etc/os-release ; then	#The "universe" repository is only available on Ubuntu (and, in theory, popos and Zorin)  Kali DOES NOT have universe
			while ! $SUDO add-apt-repository --yes universe ; do
				echo "Error subscribing to universe repository, perhaps because a system update is running; will wait 60 seconds and try again." >&2
				sleep 60
			done
		fi
		while ! $SUDO apt-get -q -y update >/dev/null ; do
			echo "Error updating package metadata, perhaps because a system update is running; will wait 60 seconds and try again." >&2
			sleep 60
		done
		while ! $SUDO apt-get -q -y upgrade >/dev/null ; do
			echo "Error updating packages, perhaps because a system update is running; will wait 60 seconds and try again." >&2
			sleep 60
		done
		while ! $SUDO apt-get -q -y install lsb-release >/dev/null ; do
			echo "Error installing lsb-release, perhaps because a system update is running; will wait 60 seconds and try again." >&2
			sleep 60
		done
	elif [ -x /usr/bin/yum -a -x /bin/rpm ]; then
		$SUDO yum -q -e 0 makecache
		$SUDO yum -q -e 0 -y update
		$SUDO yum -y -q -e 0 -y install yum-utils
		$SUDO yum -y -q -e 0 -y install redhat-lsb-core >/dev/null 2>/dev/null || /bin/true		#If available, we install it.  If not, we ignore the error and continue on.
		if [ -s /etc/redhat-release -a -s /etc/os-release ]; then
			. /etc/os-release
			if [ "$VERSION_ID" = "7" ]; then
				$SUDO yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
				if [ ! -e /etc/centos-release ]; then
					$SUDO yum -y install subscription-manager
					$SUDO subscription-manager repos --enable "rhel-*-optional-rpms" --enable "rhel-*-extras-rpms"  --enable "rhel-ha-for-rhel-*-server-rpms"
				fi
			elif [ "$VERSION_ID" = "8" ]; then
				$SUDO yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
				if [ -e /etc/centos-release ]; then
					$SUDO dnf config-manager --set-enabled powertools
				else
					$SUDO yum -y install subscription-manager
					$SUDO subscription-manager repos --enable "codeready-builder-for-rhel-8-`/bin/arch`-rpms"
				fi
			fi
		fi
		$SUDO yum -q -e 0 makecache
	fi
}


install_tool() {
	#Install a program.  $1 holds the name of the executable we need
	#$2 is one or more packages that can supply that executable (put preferred package names early in the list).


	binary="$1"
	potential_packages="$2"

	if type -path "$binary" >/dev/null ; then
		status "== $binary executable is installed."		#================
	else
		status "== Installing package that contains $binary"		#================
		if [ -x /usr/bin/apt-get -a -x /usr/bin/dpkg-query ]; then
			for one_package in $potential_packages ; do
				if ! type -path "$binary" >/dev/null ; then		#if a previous package was successfully able to install, don't try again.
					$SUDO apt-get -q -y install $one_package
				fi
			done
		elif [ -x /usr/bin/yum -a -x /bin/rpm ]; then
			#Yum takes care of the lock loop for us
			for one_package in $potential_packages ; do
				if ! type -path "$binary" >/dev/null ; then		#if a previous package was successfully able to install, don't try again.
					$SUDO yum -y -q -e 0 install $one_package
				fi
			done
		else
			fail "Neither (apt-get and dpkg-query) nor (yum, rpm, and yum-config-manager) is installed on the system"
		fi
	fi

	if type -path "$binary" >/dev/null ; then
		return 0
	else
		echo "WARNING: Unable to install $binary from a system package" >&2
		return 1
	fi
}

echo "ansible_installer version $ansible_installer_version" >&2

#FIXME We no longer need these choices, remove the following block
#if [ -n "$1" ]; then
#	if [ "$1" = "rita" ]; then
#		data_needed="rita"
#		shift
#	elif [ "$1" = "achunter" ]; then
#		data_needed="achunter"
#		shift
#	else
#		install_target="$1"
#		shift
#	fi
#fi
#if [ -n "$1" ]; then
#	install_target="$1"
#fi
#
#if [ -z "$install_target" ]; then
#	install_target="localhost"
#fi

require_sudo

# check if macOS
if [ "$(uname)" == "Darwin" ]; then
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
	# FIXME
	# exit to avoid fubaring mac
	# fail "bingbong"
else
	patch_system

	enable_repositories


	status "Installing needed tools"		#================
	install_tool python3 "python3"
	install_tool pip3 "python3-pip"			#Note, oracle linux does not come with pip at all.  The "python3-pip-wheel" package does not include pip.
	python3 -m pip -V ; retcode="$?"
	if [ "$retcode" != 0 ]; then
		fail "Unable to run python3's pip, exiting."
	fi


	install_tool wget "wget"
	install_tool curl "curl"
	install_tool sha256sum "coreutils"
	install_tool ansible "ansible ansible-core"
fi


#We need to install zeek through the rita installer in order to install both
#install_tool zeek "zeek"
#install_tool zeekctl "zeekctl"





status "Preparing this system"		#================
#Try to add /usr/local/bin/ to path (though the better way is to log out and log back in)
if ! echo "$PATH" | grep -q '/usr/local/bin' ; then
	echo "Adding /usr/local/bin to path" >&2
	#For this login only...
	export PATH="$PATH:/usr/local/bin/"
	#...and for future logins
	if [ -s /etc/environment ]; then
		echo 'export PATH="$PATH:/usr/local/bin/"' | sudo tee -a /etc/environment >/dev/null
	elif [ -s /etc/profile ]; then
		echo 'export PATH="$PATH:/usr/local/bin/"' | sudo tee -a /etc/profile >/dev/null
	else
		echo "Unable to add /usr/local/bin/ to path." >&2
	fi
fi

ansible-galaxy collection install community.docker --force




popd > /dev/null
