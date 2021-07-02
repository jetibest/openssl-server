#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L // if OpenSSL version < 1.1.0
#error "This program is not compatible with OpenSSL version less than 1.1.0"
#endif

#define BUFFER_SIZE 4096 // SOCK_MIN_RCVBUF from net/sock.h

static volatile sig_atomic_t connected = 1;

struct options_s
{
	char listen_host[256];
	int listen_port;
	char host[256];
	int port;
	char cert_file[4096];
	char key_file[4096];
};
struct options_s options_default = {
    "127.0.0.1",
    4433,
    "127.0.0.1",
    0,
    "cert.pem",
    "key.pem"
};
typedef struct options_s options;

void die(const char * msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(EXIT_FAILURE);
}

struct sockaddr_in create_sockaddr(const char * host, int port)
{
	struct sockaddr_in s;
	s.sin_family = AF_INET;
	if(inet_pton(AF_INET, host, &s.sin_addr) <= 0)
	{
		die("error(%d: %s): inet_pton(): Failed to parse host address (%s).", errno, strerror(errno), host);
	}
	s.sin_port = htons(port);
	return s;
}


static void signal_handler(int signalno)
{
	fprintf(stderr, "info: Caught signal (%d), exiting gracefully.\n", signalno);
	connected = 0;
}

void print_help()
{
	fprintf(stdout,
		"Usage: openssl-server [OPTIONS] [target-address]\n"
		"\n"
		"Accepts incoming client sockets with TLS, and pipes the decrypted data to the\n"
		"given target address (bidirectional). Target address defaults to %s, and\n"
		"the set or default value of the bind port.\n"
		"\n"
		"OPTIONS\n"
		"  -cert <file>          Path to certificate file (defaults to %s).\n"
		"  -key <file>           Path to key file (defaults to %s).\n"
		"  -b,--bind <address>   Bind to the given address (defaults to %s:%d).\n"
		"  -h,--help             Show this help.\n"
		"\n"
		"Formatting:\n"
		"  address = {host:port,host,:port,port}\n"
		"\n"
		"Hint:\n"
		"  Use host 0.0.0.0 for any/all interfaces (public).\n"
		"  Use host 127.0.0.1 for local-loopback only (private).\n"
		"\n"
		"EXAMPLES\n"
		"  Generate a self-signed certificate:\n"
		"  > openssl req -x509 -days 36500 -subj '/CN=localhost' -nodes -newkey rsa:4096 \n"
		"  -keyout key.pem -out cert.pem\n"
		"\n"
		"  Connect with openssl-server instance (using TLS):\n"
		"  > openssl s_client -connect %s:%d -quiet\n"
		"\n"
		"\n",
         options_default.host,
         options_default.cert_file,
         options_default.key_file,
         options_default.listen_host,
         options_default.listen_port,
         options_default.listen_host,
         options_default.listen_port
    );
}

int child(int server_fd, SSL_CTX * sslctx, options opts)
{
	// Make server_fd nonblocking
	fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL) | O_NONBLOCK);
	
	// Create SSL for the given fd
	SSL * ssl = SSL_new(sslctx);
	SSL_set_fd(ssl, server_fd);
	
	// Wait for SSL to accept:
	int ret;
	while(connected == 1 && (ret = SSL_accept(ssl)) != 1)
	{
		int err = SSL_get_error(ssl, ret);
        if(ret == SSL_ERROR_ZERO_RETURN)
        {
            // TLS session has been closed
            connected = 0;
        }
		else if(!(err == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_NONE))
		{
			die("error: Unexpected OpenSSL SSL_ERROR_*: %d.", err);
		}
	}
	
	// Create client fd:
	int clientfd_in = -1;
	int clientfd_out = -1;
	
    if(connected == 1)
    {
        if(opts.port == 0)
        {
            // Set stdin as nonblocking for non-blocking read:
            fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
            
            clientfd_in = STDIN_FILENO;
            clientfd_out = STDOUT_FILENO;
        }
        else
        {
            // Create socket:
            clientfd_in = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if(clientfd_in < 0)
            {
                die("error(%d: %s): socket()", errno, strerror(errno));
            }
            
            // Connect to socket:
            struct sockaddr_in addr = create_sockaddr(opts.host, opts.port);
            while(connected == 1 && connect(clientfd_in, (struct sockaddr *) &addr, sizeof(addr)) == -1)
            {
                if(errno != EINPROGRESS)
                {
                    die("error(%d: %s): connect()", errno, strerror(errno));
                }
            }
            
            // Socket is bidirectional:
            clientfd_out = clientfd_in;
        }
    }
	
	// Pipe server to client (bidirectional)
	char read_buffer[BUFFER_SIZE];
    char write_buffer[BUFFER_SIZE];
    
    int ssl_write_ret = 1;
    int ssl_write_len = 0;
    
    
    if(connected == 1)
    {
        // Prepare reads from fd's
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        FD_SET(clientfd_in, &readfds);
        
        int select_max_fd = 0;
        if(server_fd > select_max_fd) select_max_fd = server_fd;
        if(clientfd_in > select_max_fd) select_max_fd = clientfd_in;
        
        // wait for read, and then write
        while(connected == 1)
        {
            fd_set rfds = readfds;
            if(select(select_max_fd + 1, &rfds, NULL, NULL, NULL) == -1)
            {
                die("error(%d: %s): select()", errno, strerror(errno));
            }
            
            // check read from ssl socket
            {
                int ret = SSL_read(ssl, read_buffer, BUFFER_SIZE);
                if(ret > 0)
                {
                    if(write(clientfd_out, read_buffer, ret) == -1)
                    {
                        die("error(%d: %s): write()", errno, strerror(errno));
                    }
                }
                else
                {
                    int ssl_err = SSL_get_error(ssl, ret);
                    
                    if(ssl_err == SSL_ERROR_ZERO_RETURN)
                    {
                        // TLS session has been closed
                        connected = 0;
                    }
                    else if(!(ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE))
                    {
                        die("error: Unexpected OpenSSL SSL_ERROR_*: %d", ssl_err);
                    }
                }
            }
            
            // check read from client socket
            {
                ssl_write_len = ssl_write_ret <= 0 ? ssl_write_len : read(clientfd_in, write_buffer, BUFFER_SIZE);
                
                if(ssl_write_len > 0)
                {
                    ssl_write_ret = SSL_write(ssl, write_buffer, ssl_write_len);
                    
                    if(ssl_write_ret <= 0)
                    {
                        int ssl_err = SSL_get_error(ssl, ssl_write_ret);
                        
                        if(ssl_err == SSL_ERROR_ZERO_RETURN)
                        {
                            // TLS session has been closed
                            connected = 0;
                        }
                        else if(!(ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE))
                        {
                            die("error: Unexpected OpenSSL SSL_ERROR_*: %d", ssl_err);
                        }
                    }
                }
                else if(clientfd_in != STDIN_FILENO)
                {
                    int err;
                    socklen_t errlen = sizeof(err);
                    getsockopt(clientfd_in, SOL_SOCKET, SO_ERROR, &err, &errlen);
                    if(err != 0)
                    {
                        die("error(%d: %s): read(): %d", errno, strerror(errno), err);
                    }
                }
                else
                {
                    if(!(errno == EAGAIN || errno == EWOULDBLOCK))
                    {
                        die("error(%d: %s): read()", errno, strerror(errno));
                    }
                }
            }
        }
    }
	
	if(clientfd_in != -1 && clientfd_in != STDIN_FILENO)
	{
		close(clientfd_in);
		close(clientfd_out);
	}
	
	SSL_shutdown(ssl); // do not call, if SSL_ERROR_SYSCALL or SSL_ERROR_SSL
	SSL_free(ssl);
	
	close(server_fd);
	
	return 0;
}

int main(int argc, char * argv[])
{
	// Parse command-line options:
	options opts = options_default;
	int parse_opts = 1;
	for(int i=1;i<argc;++i)
	{
		char * arg = argv[i];
        
		if(arg[0] == '\0')
		{
			continue;
		}
		else if(strcmp(arg, "--") == 0)
		{
			parse_opts = 0;
		}
		else if(parse_opts == 1 && arg[0] == '-')
		{
			if(strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
			{
				print_help();
				return 0;
			}
			else if(strcmp(arg, "-cert") == 0)
			{
				if(i + 1 == argc)
				{
					die("error: Invalid usage. Expected value for option. Use: %s <file>. Defaults to: %s \"%s\".", arg, arg, options_default.cert_file);
					return 1;
				}
				strcpy(opts.cert_file, argv[i + 1]);
			}
			else if(strcmp(arg, "-key") == 0)
			{
				if(i + 1 == argc)
				{
					die("error: Invalid usage. Expected value for option. Use: %s <file>. Defaults to: %s \"%s\".", arg, arg, options_default.key_file);
					return 1;
				}
				strcpy(opts.key_file, argv[i + 1]);
			}
			else if(strcmp(arg, "-l") == 0 || strcmp(arg, "--listen") == 0)
			{
				if(i + 1 == argc)
				{
					die("error: Invalid usage. Expected value for option. Use: %s [host][:port]. Defaults to: %s \"%s:%d\"", arg, arg, opts.listen_host, opts.listen_port);
					return 1;
				}
				char * addr = argv[i + 1];
				if(addr[0] != '\0')
				{
                    char * index = strchr(addr, ':');
					if(index == NULL)
					{
						if(strspn(addr, "0123456789") == strlen(addr))
						{
							opts.listen_port = atoi(addr);
						}
						else
						{
							strcpy(opts.listen_host, addr);
						}
					}
					else
					{
						// could be formatted as :1234 (no host, but : prefix)
						if(index != addr)
						{
							strncpy(opts.listen_host, addr, index - addr);
                            opts.listen_host[index - addr] = '\0';
						}
						
						opts.listen_port = atoi(index + 1);
					}
				}
			}
			else
			{
				die("error: Invalid usage. Unknown option (%s).", arg);
				return 1;
			}
		}
		else
		{
			// must be host:port, or host, or :port, or port
			// TODO: add IPv6 support by putting brackets around host, usage: [ipv6]:port
            
            char * index = strchr(arg, ':');
			if(index == NULL)
			{
				if(strspn(arg, "0123456789") == strlen(arg))
				{
					// set only port
					opts.port = atoi(arg);
				}
				else
				{
					// set only host
					if(opts.port == 0)
					{
						// assume listen port as target port value if port was omitted
						opts.port = opts.listen_port;
					}
					strcpy(opts.host, arg);
				}
			}
			else
			{
				// host could be zero-length, if using colon prefixed port (:4433)
				if(index != arg)
				{
					strncpy(opts.host, arg, index - arg);
                    opts.host[index - arg] = '\0';
				}
				
				opts.port = atoi(index + 1);
			}
		}
	}
	
	// Initialize OpenSSL library:
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	
	// Create SSL context:
	SSL_CTX * sslctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
	// SSL_CTX_set_mode(sslctx, SSL_MODE_AUTO_RETRY);
	int use_cert = SSL_CTX_use_certificate_file(sslctx, opts.cert_file, SSL_FILETYPE_PEM);
	int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, opts.key_file, SSL_FILETYPE_PEM);
	
    // Create socket server:
	int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if(server_fd == -1)
	{
		die("error(%d: %s): socket()", errno, strerror(errno));
	}
	
	fprintf(stderr, "info: Going to listen on %s:%d for incoming connections.\n", opts.listen_host, opts.listen_port);
	
	// Bind socket:
	struct sockaddr_in s = create_sockaddr(opts.listen_host, opts.listen_port);
	if(bind(server_fd, (struct sockaddr *) &s, sizeof(s)) == -1)
	{
		die("error(%d: %s): bind()", errno, strerror(errno));
	}
	
	// Listen:
	if(listen(server_fd, 128) == -1)
	{
		die("error(%d: %s): listen()", errno, strerror(errno));
	}
	
	// Setup signal handlers:
	signal(SIGPIPE, signal_handler);
	signal(SIGINT, signal_handler);
	
	// Prepare read on server_fd:
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(server_fd, &readfds);
	
	fprintf(stderr, "info: Internally forwarding incoming connections to: ");
	if(opts.port == 0)
	{
		fprintf(stderr, "stdin/stdout\n");
	}
	else
	{
        fprintf(stderr, "%s:%d\n", opts.host, opts.port);
	}
	
	while(connected == 1)
	{
		// Wait for activity on server_fd
		fd_set rfds = readfds;
		if(select(server_fd + 1, &rfds, NULL, NULL, NULL) == -1)
		{
			die("error(%d: %s): select()", errno, strerror(errno));
		}
		
		struct sockaddr_in client_addr;
		int client_len;
		int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_len);
		if(client_fd < 0)
		{
			die("error(%d: %s): accept()", errno, strerror(errno));
		}
		
		if(opts.port == 0)
		{
			child(client_fd, sslctx, opts);
		}
		else
		{
			pid_t pid = fork();
			if(pid == 0)
			{
				// forked process (child):
				close(server_fd);
				return child(client_fd, sslctx, opts);
			}
			// original process (parent):
			close(client_fd);
		}
	}
	
	// Clean up OpenSSL
	ERR_free_strings();
    
    return 0;
}
