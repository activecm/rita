#!/usr/bin/env bash
set -e

# Generates the RITA installer by creating a temporary folder in the current directory named 'stage'
# and copies files that must be in the installer into the stage folder.
# Once all directories are placed in stage, it is compressed and stage is deleted

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
# ANSIBLE_FILES=./stage/.ansible/files
SCRIPTS="$BASE_DIR/scripts"
ANSIBLE_FILES="$BASE_DIR/files"
ANSIBLE_PLAYBOOKS="$BASE_DIR/.ansible/playbooks"

mkdir "$BASE_DIR"
mkdir -p "$ANSIBLE_FILES"
mkdir -p "$SCRIPTS"
mkdir -p "$ANSIBLE_PLAYBOOKS"

# create subfolders (for files that installed RITA will contain)
INSTALL_OPT="$ANSIBLE_FILES"/opt
INSTALL_ETC="$ANSIBLE_FILES"/etc
mkdir "$ANSIBLE_FILES"/opt
mkdir "$ANSIBLE_FILES"/etc


# copy files in base dir
cp ./install_scripts/install_rita.yml "$BASE_DIR"
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
cp ../.env.production "$INSTALL_OPT"/.env
cp ../docker-compose.prod.yml "$INSTALL_OPT"/docker-compose.yml
cp ../LICENSE "$INSTALL_OPT"/LICENSE
cp ../README.md "$INSTALL_OPT"/README



# update version variables for files that need them
if [ "$(uname)" == "Darwin" ]; then
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.yml" # WAS $ANSIBLE_PLAYBOOKS
    sed -i'.bak' "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.sh"
    sed -i'.bak' "s#ghcr.io/activecm/rita-v2:latest#ghcr.io/activecm/rita-v2:${VERSION}#g" "$INSTALL_OPT/docker-compose.yml"

    rm "$BASE_DIR/install_rita.yml.bak"
    rm "$BASE_DIR/install_rita.sh.bak"
    rm "$INSTALL_OPT/docker-compose.yml.bak"
else 
    sed -i  "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.yml" # WAS $ANSIBLE_PLAYBOOKS
    sed -i  "s/REPLACE_ME/${VERSION}/g" "$BASE_DIR/install_rita.sh"
    sed -i  "s#ghcr.io/activecm/rita-v2:latest#ghcr.io/activecm/rita-v2:${VERSION}#g" "$INSTALL_OPT/docker-compose.yml"
fi




# TODO remove when repo is public
./build_image.sh
cp "./rita-v2-$VERSION-image.tar" "$ANSIBLE_FILES" # was $INSTALL_OPT
rm "./rita-v2-$VERSION-image.tar"

# create tar
# TODO the inner folder is named stage, should be rita-$VERSION
tar -czf "rita-$VERSION.tar.gz" "$BASE_DIR"

# delete staging folder
rm -rf "$BASE_DIR"

# switch back to original working directory
popd > /dev/null

echo "Finished generating installer."