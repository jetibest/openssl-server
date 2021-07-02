# openssl-server
Modular TLS wrapper, a functional version of openssl s_server (for Linux).

## DISCLAIMER

**NO WARRANTY, MAY CONTAIN BUGS, MEMORY LEAKS, ETC. ETC. ETC.**

## `openssl-server --help`

    Usage: openssl-server [OPTIONS] [target-address]
    
    Accepts incoming client sockets with TLS, and pipes the decrypted data to the
    given target address (bidirectional). Target address defaults to 127.0.0.1, and
    the set or default value of the bind port.
    
    OPTIONS
      -h,--help             Show this help.
      -b,--bind <address>   Bind to the given address (defaults to 127.0.0.1:4433).
    
      -cert <file>          Path to certificate file (defaults to cert.pem).
      -key <file>           Path to key file (defaults to key.pem).
      -verify               Client must send a client certificate.
      -verify_return_error  Verify client certificate, or handshake failure.
      -CAfile <file>        Path to CA bundle file for verify.
      -CApath <path>        CA certificates directory for verify. Uses the first
                            path in a colon delimited string that exists.
                            Defaults to: /etc/ssl/certs:/etc/pki/tls/certs
      -tls1_2               Enforce a minimum protocol version of TLS 1.2.
      -tls1_3               Enforce a minimum protocol version of TLS 1.3.
    
    Formatting:
      address = {host:port|host|:port|port}
    
    Hint:
      Use host 0.0.0.0 for any/all interfaces (public).
      Use host 127.0.0.1 for local-loopback only (private).
    
    EXAMPLES
      Generate a self-signed certificate:
      > openssl req -x509 -days 36500 -subj '/CN=localhost' -nodes -newkey rsa:4096 
      -keyout key.pem -out cert.pem
    
      Connect with openssl-server instance (using TLS):
      > openssl s_client -connect 127.0.0.1:4433 -quiet
    
      Enable HTTPS for a HTTP webserver running on port 80:
      > openssl-server --bind 0.0.0.0:443 80

## Example: Basic usage

Grab the code and compile:

    cd /tmp
    git clone https://github.com/jetibest/openssl-server
    cd openssl-server
    ./compile.sh && ./install.sh

Create a self-signed certificate/key files if not yet created:

    openssl req -x509 -days 36500 -subj '/CN=localhost' -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem

First run any socket server daemon at any port:

    nc -l -p 8080

Then wrap this socket server in TLS:

    openssl-server -key key.pem -cert cert.pem -b 127.0.0.1:8443 127.0.0.1:8080

Connect to the TLS socket server:

    openssl s_client -connect 127.0.0.1:8443 -quiet

Any data sent through this client, is encrypted with TLS at port 8443, and sent to port 8080.
Similarly, any data returned by the server running at port 8080 is written back to the client over the socket with TLS.

## Example: Modular TLS/SSL for webservers

Start with running [any webserver](https://gist.github.com/willurd/5720255) at 8080 at the local-loopback address (127.0.0.1):

    php -S 127.0.0.1:8080

Then run the TLS server at any/all interface(s) at the default HTTPS port (0.0.0.0:443), and then pipe incoming connections to the local-loopback device at the alternative HTTP port (127.0.0.1:8080).

    [sudo] openssl-server -key key.pem -cert cert.pem -b 0.0.0.0:443 127.0.0.1:8080

If the TLS-certificate is self-signed, then you must add this certificate as an exception in order to continue for testing purposes.
For instance, to test the webserver over HTTPS, use curl:

    curl --insecure https://localhost:443/

If the webserver is supposed to be HTTPS-only, then a redirect from http:// to https:// is in order.
So an additional webserver with a redirect must listen at 0.0.0.0:80.

    cat <<EOF >redirect-to-https.php && [sudo] php -S 127.0.0.1:80
    <?php
    header('HTTP/1.1 302 Found');
    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    ?>
    EOF

Of course, you can also simply run the webserver on the HTTP port (:80) directly, and do a conditional redirect to HTTPS (:443) in the application code (i.e. in PHP test for: `empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off"`).


## TODO

 - IPv6 addresses are not yet supported.
 - Extensive testing of handling unexpected errors.


