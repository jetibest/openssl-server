#!/bin/bash
cp openssl-server /usr/local/bin/openssl-server && echo "Installation successful (openssl-server). Uninstall using: rm -f /usr/local/bin/openssl-server." || echo "Failed to install openssl-server. Try run as root with sudo."
