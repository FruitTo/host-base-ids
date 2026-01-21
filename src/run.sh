#!/bin/bash

g++ main.cpp -o hips -O3 -lpthread -ltins -lpqxx -lpq -lcurl -std=c++17

sudo mv hips /usr/local/bin

hips

sudo rm /usr/local/bin/hips