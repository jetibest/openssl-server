#include <iostream>
#include <string>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <signal.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096 // SOCK_MIN_RCVBUF from net/sock.h

static volatile sig_atomic_t connected = 1;

struct options_s
{
	std::string listen_host = "127.0.0.1"; // listen on local loopback only by default
	int listen_port = 4433; // OpenSSL s_server default port
	std::string host = "127.0.0.1"; // local loopback IPv4 address
	int port = 0;
	std::string cert_file = "cert.pem";
	std::string key_file = "key.pem";
};

void die(std::string str)
{
	std::cerr << "error(" << errno << "): " << str << std::endl;
	exit(1);
}

sockaddr_in create_sockaddr(std::string host, int port)
{
	struct sockaddr_in s;
	s.sin_family = AF_INET;
	if(inet_pton(AF_INET, host.c_str(), &s.sin_addr) <= 0)
	{
		die("inet_pton(): Failed to parse host address (" + host + ").");
	}
	s.sin_port = htons(port);
	return s;
}


static void signal_handler(int _)
{
	(void)_; // disable warning unused variable
	std::cout << "Caught signal (" << _ << ")." << std::endl;
	connected = 0;
}

std::string ssl_error_to_string(int ssl_error)
{
	if(ssl_error == SSL_ERROR_NONE)
	{
		return "SSL_ERROR_NONE";
	}
	else if(ssl_error == SSL_ERROR_ZERO_RETURN)
	{
		return "SSL_ERROR_ZERO_RETURN";
	}
	else if(ssl_error == SSL_ERROR_WANT_READ)
	{
		return "SSL_ERROR_WANT_READ";
	}
	else if(ssl_error == SSL_ERROR_WANT_WRITE)
	{
		return "SSL_ERROR_WANT_WRITE";
	}
	else if(ssl_error == SSL_ERROR_WANT_CONNECT)
	{
		return "SSL_ERROR_WANT_CONNECT";
	}
	else if(ssl_error == SSL_ERROR_WANT_ACCEPT)
	{
		return "SSL_ERROR_WANT_ACCEPT";
	}
	else if(ssl_error == SSL_ERROR_WANT_X509_LOOKUP)
	{
		return "SSL_ERROR_WANT_X509_LOOKUP";
	}
	else if(ssl_error == SSL_ERROR_WANT_ASYNC)
	{
		return "SSL_ERROR_WANT_ASYNC";
	}
	else if(ssl_error == SSL_ERROR_WANT_ASYNC_JOB)
	{
		return "SSL_ERROR_WANT_ASYNC_JOB";
	}
	else if(ssl_error == SSL_ERROR_WANT_CLIENT_HELLO_CB)
	{
		return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
	}
	else if(ssl_error == SSL_ERROR_SYSCALL)
	{
		return "SSL_ERROR_SYSCALL";
	}
	else if(ssl_error == SSL_ERROR_SSL)
	{
		return "SSL_ERROR_SSL";
	}
	else
	{
		return "UNKNOWN";
	}
}


void print_help()
{
	std::cout << "TODO: usage and help not implemented yet" << std::endl;
	
	// feature:
	// if opt_target_port is 0, then write to stdout, and read from stdin instead of a socket
	// this also automatically means that we will only accept at most 1 socket at a time
	
}

int child(int server_fd, SSL_CTX * sslctx, options_s options)
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
		if(!(err == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_ZERO_RETURN || ret == SSL_ERROR_NONE))
		{
			die(ssl_error_to_string(err));
		}
	}
	
	// Create client fd:
	int clientfd_in;
	int clientfd_out;
	
	if(options.port == 0)
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
			die("socket()");
		}
		
		// Connect to socket:
		struct sockaddr_in addr = create_sockaddr(options.host, options.port);
		while(connected == 1 && connect(clientfd_in, (struct sockaddr *) &addr, sizeof(addr)) == -1)
		{
			if(errno != EINPROGRESS)
			{
				die("connect()");
			}
		}
		
		// Socket is bidirectional:
		clientfd_out = clientfd_in;
	}
	
	// Pipe server to client (bidirectional)
	char buffer[BUFFER_SIZE];
	
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
			die("select()");
		}
		
		// check read from ssl socket
		{
			int ret = SSL_read(ssl, buffer, BUFFER_SIZE);
			if(ret > 0)
			{
				write(clientfd_out, buffer, ret);
			}
			else
			{
				int err = SSL_get_error(ssl, ret);
				
				if(!(err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_ZERO_RETURN))
				{
					die(ssl_error_to_string(err));
				}
			}
		}
		
		// check read from client socket
		{
			int ret = read(clientfd_in, buffer, BUFFER_SIZE);
			if(ret > 0)
			{
				int ssl_ret = SSL_write(ssl, buffer, ret);
				if(ssl_ret <= 0)
				{
					int ssl_err = SSL_get_error(ssl, ssl_ret);
					die(ssl_error_to_string(ssl_err));
				}
			}
			else if(clientfd_in != STDIN_FILENO)
			{
				int err;
				socklen_t errlen = sizeof(err);
				getsockopt(clientfd_in, SOL_SOCKET, SO_ERROR, &err, &errlen);
				if(err != 0)
				{
					die("read()");
				}
			}
			else
			{
				if(!(errno == EAGAIN || errno == EWOULDBLOCK))
				{
					die("read()");
				}
			}
		}
	}
	
	if(clientfd_in != STDIN_FILENO)
	{
		close(clientfd_in);
		close(clientfd_out);
	}
	
	ERR_free_strings();
	EVP_cleanup();
	
	SSL_shutdown(ssl);
	SSL_free(ssl);
	
	close(server_fd);
	
	return 0;
}

int main(int argc, char * argv[])
{
	// Parse command-line options:
	options_s options;
	int parse_opts = 1;
	for(int i=1;i<argc;++i)
	{
		std::string arg = argv[i];
		if(arg.length() == 0)
		{
			continue;
		}
		else if(arg == "--")
		{
			parse_opts = 0;
		}
		else if(parse_opts == 1 && arg[0] == '-')
		{
			if(arg == "-h" || arg == "--help")
			{
				print_help();
			}
			else if(arg == "-cert")
			{
				if(i + 1 == argc)
				{
					die(std::string("") + "Invalid usage. Expected value for option. Use: " + arg + " <file>. Defaults to: " + arg + " \"" + options.cert_file + "\".");
					return 1;
				}
				options.cert_file = argv[i + 1];
			}
			else if(arg == "-key")
			{
				if(i + 1 == argc)
				{
					die(std::string("") + "Invalid usage. Expected value for option. Use: " + arg + " <file>. Defaults to: " + arg + " \"" + options.key_file + "\".");
					return 1;
				}
				options.key_file = argv[i + 1];
			}
			else if(arg == "-p" || arg == "--port")
			{
				if(i + 1 == argc)
				{
					die(std::string("") + "Invalid usage. Expected value for option. Use: " + arg + " <port>. Defaults to: " + arg + " \"" + std::to_string(options.listen_port) + "\"");
					return 1;
				}
				options.listen_port = std::stoi(std::string(argv[i+1]));
			}
			else
			{
				die(std::string("") + "Invalid usage. Unknown option.");
				return 1;
			}
		}
		else
		{
			// must be host:port, or host, or :port, or port
			// TODO: add IPv6 support by putting brackets around host, usage: [ipv6]:port
			size_t index = arg.find(':');
			if(index == std::string::npos)
			{
				if(arg.find_first_not_of("0123456789") == std::string::npos)
				{
					// set only port
					options.port = std::stoi(arg);
				}
				else
				{
					// set only host
					if(options.port == 0)
					{
						// assume listen port as target port value if port was omitted
						options.port = options.listen_port;
					}
				}
			}
			else
			{
				std::string host = arg.substr(0, index);
				std::string port = arg.substr(index + 1);
				
				// host could be zero-length, if using colon prefixed port (:4433)
				if(host.length() != 0)
				{
					options.host = host;
				}
				
				options.port = std::stoi(port);
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
	int use_cert = SSL_CTX_use_certificate_file(sslctx, options.cert_file.c_str(), SSL_FILETYPE_PEM);
	int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, options.key_file.c_str(), SSL_FILETYPE_PEM);
	
	// Create socket server:
	int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if(server_fd == -1)
	{
		die("socket()");
	}
	
	// Bind socket:
	struct sockaddr_in s = create_sockaddr(options.listen_host, options.listen_port);
	if(bind(server_fd, (struct sockaddr *) &s, sizeof(s)) == -1)
	{
		die("bind()");
	}
	
	// Listen:
	if(listen(server_fd, 128) == -1)
	{
		die("listen()");
	}
	
	// Setup signal handlers:
	signal(SIGPIPE, signal_handler);
	signal(SIGINT, signal_handler);
	
	// Prepare read on server_fd:
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(server_fd, &readfds);
	
	while(connected == 1)
	{
		// Wait for activity on server_fd
		fd_set rfds = readfds;
		if(select(server_fd + 1, &rfds, NULL, NULL, NULL) == -1)
		{
			die("select()");
		}
		
		struct sockaddr_in client_addr;
		int client_len;
		int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_len);
		if(client_fd < 0)
		{
			die("accept()");
		}
		
		if(options.port == 0)
		{
			child(client_fd, sslctx, options);
		}
		else
		{
			pid_t pid = fork();
			if(pid == 0)
			{
				// forked process (child):
				close(server_fd);
				return child(client_fd, sslctx, options);
			}
			// original process (parent):
			close(client_fd);
		}
	}
	
	// Clean up OpenSSL
	ERR_free_strings();
	EVP_cleanup();
}
