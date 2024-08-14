#!/usr/bin/env bash
set -e

# Generates the RITA installer by creating a temporary folder in the current directory named 'stage'
# and copies files that must be in the installer into the stage folder.
# Once all directories are placed in stage, it is compressed and stage is deleted

ZEEK_VERSION=6.2.1

# get RITA version from git
VERSION=$(git describe --always --abbrev=0 --tags)
echo "Generating installer for RITA $VERSION..."


# change working directory to directory of this script
pushd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" > /dev/null

BASE_DIR="./rita-$VERSION-installer" # was ./stage/bin

# create staging folder
rm -rf "$BASE_DIR"
# mkdir ./stage

# create ansible subfolders
SCRIPTS="$BASE_DIR/scripts"
ANSIBLE_FILES="$BASE_DIR/files"

mkdir "$BASE_DIR"
mkdir -p "$ANSIBLE_FILES"
mkdir -p "$SCRIPTS"

# create subfolders (for files that installed RITA will contain)
INSTALL_OPT="$ANSIBLE_FILES"/opt
INSTALL_ETC="$ANSIBLE_FILES"/etc
mkdir "$ANSIBLE_FILES"/opt
mkdir "$ANSIBLE_FILES"/etc


# copy files in base dir
cp ./install_scripts/install_zeek.yml "$BASE_DIR"
cp ./install_scripts/install_rita.yml "$BASE_DIR"
cp ./install_scripts/install_pre.yml "$BASE_DIR"
cp ./install_scripts/install_post.yml "$BASE_DIR"

cp ./install_scripts/install_rita.sh "$BASE_DIR" # entrypoint

# copy files to helper script folder
cp ./install_scripts/ansible-installer.sh "$SCRIPTS"
cp ./install_scripts/helper.sh "$SCRIPTS"
cp ./install_scripts/sshprep "$SCRIPTS"

# copy files to the ansible files folder
cp ./install_scripts/docker-compose "$ANSIBLE_FILES" # docker-compose v1 backwards compatibility script


# copy over configuration files to /files/etc
cp -r ../deployment/* "$INSTALL_ETC"
cp ../default_config.hjson "$INSTALL_ETC"/config.hjson

# copy over installed files to /opt
cp ../rita.sh "$INSTALL_OPT"/rita.sh
curl --fail --silent --show-error -o "$INSTALL_OPT"/zeek https://raw.githubusercontent.com/activecm/docker-zeek/master/zeek
chmod +x "$INSTALL_OPT"/zeek
cp ../.env.production "$INSTALL_OPT"/.env
cp ../docker-compose.prod.yml "$INSTALL_OPT"/docker-compose.yml
cp ../LICENSE "$INSTALL_OPT"/LICENSE
cp ../README.md "$INSTALL_OPT"/README


cp ./install-rita-zeek-here-tmp.sh install-rita-zeek-here.sh

# update version variables for files that need them
if [ "$(uname)" == "Darwin" ]; then
    sed -i'.bak' "s/RITA_REPLACE_ME/${VERSION}/g" "install-rita-zeek-here.sh" 
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.yml" 
    sed -i'.bak' "s/REPLACE_ME/${ZEEK_VERSION}/g" "$BASE_DIR/install_zeek.yml" 
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.sh"
    sed -i'.bak' "s#ghcr.io/activecm/rita:latest#ghcr.io/activecm/rita:${VERSION}#g" "$INSTALL_OPT/docker-compose.yml"
    
    rm "install-rita-zeek-here.sh.bak"
    rm "$BASE_DIR/install_rita.yml.bak"
    rm "$BASE_DIR/install_zeek.yml.bak"
    rm "$BASE_DIR/install_rita.sh.bak"
    rm "$INSTALL_OPT/docker-compose.yml.bak"
else 
    sed -i  "s/RITA_REPLACE_ME/${VERSION}/g" ./install-rita-zeek-here.sh
    sed -i  "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.yml" 
    sed -i  "s/REPLACE_ME/${ZEEK_VERSION}/g" "$BASE_DIR/install_zeek.yml" 
    sed -i  "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.sh"
    sed -i  "s#ghcr.io/activecm/rita:latest#ghcr.io/activecm/rita:${VERSION}#g" "$INSTALL_OPT/docker-compose.yml"
fi





# ./build_image.sh


# create tar
tar -czf "rita-$VERSION.tar.gz" "$BASE_DIR"

# delete staging folder
rm -rf "$BASE_DIR"

# switch back to original working directory
popd > /dev/null

echo "Finished generating installer."