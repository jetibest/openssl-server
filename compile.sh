#!/bin/bash
gcc -L/usr/lib main.c -lssl -lcrypto -o openssl-server
