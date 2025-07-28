#!/bin/bash
set -e
BIN=/usr/local/bin

# ----- httprobe --------------------------------------------------------------
curl -L --silent --show-error \
  -o $BIN/httprobe \
  https://github.com/tomnomnom/httprobe/releases/latest/download/httprobe-linux-amd64
chmod +x $BIN/httprobe

# ----- subfinder -------------------------------------------------------------
curl -L --silent --show-error \
  -o /tmp/subfinder.tgz \
  https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_amd64_linux.tar.gz
tar -xz -C $BIN -f /tmp/subfinder.tgz subfinder && rm /tmp/subfinder.tgz
chmod +x $BIN/subfinder

# ----- findomain -------------------------------------------------------------
curl -L --silent --show-error \
  -o $BIN/findomain \
  https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
chmod +x $BIN/findomain

echo "✅  Binaries dropped in $BIN"
