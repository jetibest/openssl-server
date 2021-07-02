# openssl-server
Modular TLS wrapper, a functional version of openssl s_server (for Linux).

# DISCLAIMER: DO NOT USE

This software is not finished, and just proof-of-concept/draft code for what it is intended to do.

## Usage

Grab the code and compile:

    cd /tmp
    git clone https://github.com/jetibest/openssl-server
    cd openssl-server
    ./compile.sh

Create a self-signed certificate/key files if not yet created:

    openssl req -x509 -days 36500 -subj '/CN=localhost' -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem

First run any socket server daemon at any port:

    nc -l -p 8080

Then wrap this socket server in TLS:

    ./openssl-server -key key.pem -cert cert.pem -p 8443 127.0.0.1:8080

Connect to the TLS socket server:

    openssl s_client -connect 127.0.0.1:8443 -quiet

Any data sent through this client, is encrypted with TLS at :8443, and sent to :8080.
Similarly, any data returned by the server running at :8080 is written back to the client over the socket with TLS.
