#!/usr/bin/env bash
set -euo pipefail

VERSION="$1"

if [ -z "$VERSION" ]; then 
    echo "VERSION was not set"
    exit 1
fi

# check that all files exist in expected locations
[ -f /usr/local/bin/rita ] || { echo >&2 "rita should be in /usr/local/bin"; exit 1; }
# opt files
[ -f /opt/rita/rita.sh ] || { echo >&2 "rita.sh should be in /opt/rita"; exit 1; }
[ -f /opt/rita/docker-compose.yml ] || { echo >&2 "docker-compose.yml should be in /opt/rita"; exit 1; }
[ -f /opt/rita/.env ] || { echo >&2 ".env should be in /opt/rita"; exit 1; }

# etc files
[ -f /etc/rita/config.hjson ] || { echo >&2 "config.hjson should be in /etc/rita"; exit 1; }
[ -f /etc/rita/config.xml ] || { echo >&2 "config.xml should be in /etc/rita"; exit 1; }
[ -f /etc/rita/http_extensions_list.csv ] || { echo >&2 "http_extensions_list.csv should be in /etc/rita"; exit 1; }
[ -f /etc/rita/logger-cron ] || { echo >&2 "logger-cron should be in /etc/rita"; exit 1; }
[ -f /etc/rita/syslog-ng.conf ] || { echo >&2 "syslog-ng.conf should be in /etc/rita"; exit 1; }
[ -f /etc/rita/timezone.xml ] || { echo >&2 "timezone.xml should be in /etc/rita"; exit 1; }
[ -d /etc/rita/threat_intel_feeds ] || { echo >&2 "/threat_intel_feeds should be in /etc/rita"; exit 1; }

# verify that sed worked during installer generation
if [ "$(grep -c "image: ghcr.io/activecm/rita:${VERSION}" /opt/rita/docker-compose.yml)" -ne 1 ]; then
    echo "/opt/rita/docker-compose.yml should have ghcr.io/activecm/rita:${VERSION} set as the image definition for the rita service."
    exit 1
fi 


# verify .env has production looking values
if [ "$(grep -c "^CONFIG_DIR=/etc/rita" /opt/rita/.env)" -ne 1 ]; then
    echo "/opt/rita/.env should have CONFIG_DIR=/etc/rita set"
    exit 1
fi 

if [ "$(grep -c "^CONFIG_FILE=/etc/rita/config.hjson" /opt/rita/.env)" -ne 1 ]; then
    echo "/opt/rita/.env should have CONFIG_FILE=/etc/rita/config.hjson set"
    exit 1
fi 

if [ "$(grep -c "^DB_ADDRESS=db:9000" /opt/rita/.env)" -ne 1 ]; then
    echo "/opt/rita/.env should have DB_ADDRESS=db:9000 set"
    exit 1
fi 


# verify rita version
if [ "$(rita --version | grep -c "$VERSION")" -ne 1 ]; then
    echo "rita version command did not work correctly"
    exit 1
fi 


# verify rita can run an import
rita import --database=testymcgee --logs=/root/sample_logs --rebuild

# check to see if this database appears in db list
rita list | grep "testymcgee"

# check to see that this dataset has data in it
rita view --stdout testymcgee