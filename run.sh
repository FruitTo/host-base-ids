#!/bin/bash

g++ main.cpp -o main -O3 -lpthread -ltins -lpqxx -lcurl -std=c++20

sudo ./main

rm -rf main