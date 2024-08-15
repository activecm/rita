#!/bin/bash
#This installs docker, rita, and zeek on the current system.
#V0.1.4

#Run one of the following 3 command lines:
#	curl -A Mozilla -fsSL https://github.com/activecm/rita/releases/latest/download/install-rita-zeek-here.sh | sudo bash -
#	wget -U Mozilla -q -O - https://github.com/activecm/rita/releases/latest/download/install-rita-zeek-here.sh | sudo bash -
#or download the above file and run:
#	sudo bash install-rita-zeek-here.sh

export RITA_VERSION="RITA_REPLACE_ME"
export zeek_release='latest'
export PATH="$PATH:/usr/local/bin/"
echo 'export PATH=$PATH:/usr/local/bin/' | sudo tee -a /etc/profile.d/localpath.sh

if [ "$EUID" -ne 0 ]; then
	Sudo="/usr/bin/sudo "
fi

$Sudo mkdir -p /usr/local/bin/

echo "==== Installing rita $RITA_VERSION ====" >&2
cd
wget https://github.com/activecm/rita/releases/download/${RITA_VERSION}/rita-${RITA_VERSION}.tar.gz
tar -xzvf rita-${RITA_VERSION}.tar.gz
cd rita-${RITA_VERSION}-installer
./install_rita.sh localhost </dev/stderr
rita help </dev/stderr

echo "==== Installing zeek $zeek_release ====" >&2
$Sudo wget -O /usr/local/bin/zeek https://raw.githubusercontent.com/activecm/docker-zeek/master/zeek
$Sudo chmod +x /usr/local/bin/zeek
/usr/local/bin/zeek pull </dev/stderr
sleep 2
/usr/local/bin/zeek stop </dev/stderr
echo "Please run 'zeek start' if you want to start zeek running in the background." >&2
echo 'If your system has trouble locating either zeek or rita we recommend logging out and logging back in.' >&2