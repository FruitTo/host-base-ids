#!/usr/bin/env bash

echo "[*] install dependencies"
sudo apt update
sudo apt install -y build-essential cmake git libpcap-dev libssl-dev libtins-dev libpqxx-dev libcurl4-openssl-dev at

sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# # json library
# git clone https://github.com/nlohmann/json.git /tmp/json
# cd /tmp/json
# mkdir build
# cd build
# cmake ..
# sudo make install

# rm -rf /tmp/json

echo "[*] install done."