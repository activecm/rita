#!/usr/bin/env bash

apt-get update
apt-get install -y libfaketime
rm -rf /var/lib/apt/lists/*

export LD_PRELOAD=/usr/lib/$(uname -m)-linux-gnu/faketime/libfaketime.so.1
export FAKETIME="-15d"
export FAKETIME_DONT_RESET=1
export DONT_FAKE_MONOTONIC=1