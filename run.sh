#!/bin/bash

g++ main.cpp -o main -O3 -lpthread -ltins -lpqxx -lpq -lcurl -std=c++17

sudo ./main

rm -rf main