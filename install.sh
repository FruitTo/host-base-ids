#!/usr/bin/env bash

echo "[*] install dependencies"
sudo apt update
sudo apt install -y build-essential cmake git libpcap-dev libssl-dev libtins-dev libpqxx-dev

# json library
git clone https://github.com/nlohmann/json.git /tmp/json
cd /tmp/json
mkdir build
cd build
cmake ..
sudo make install

rm -rf /tmp/json

echo "[*] install done."