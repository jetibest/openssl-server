#!/bin/bash
gcc -L/usr/lib -lssl -lcrypto main.c -o openssl-server
