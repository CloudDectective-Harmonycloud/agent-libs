#define VISIBILITY_PRIVATE

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <list>
#include <cassert>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <netdb.h>
#include <sys/socket.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include "Poco/URIStreamOpener.h"
#include "Poco/StreamCopier.h"
#include "Poco/Path.h"
#include "Poco/URI.h"
#include "Poco/Exception.h"
#include "Poco/Net/HTTPStreamFactory.h"
#include "Poco/Net/HTTPSStreamFactory.h"
#include "Poco/Net/FTPStreamFactory.h"
#include "Poco/NullStream.h"

// For HTTP server
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTTPServerRequestImpl.h>
#include <Poco/Net/HTTPSClientSession.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer_thread.h"
#include "protostate.h"
#include "procfs_parser.h"
#include <array>
#include <thread>
#include <memory>

using namespace std;

using Poco::NumberFormatter;
using Poco::NumberParser;
using Poco::SharedPtr;

using Poco::URIStreamOpener;
using Poco::StreamCopier;
using Poco::Path;
using Poco::URI;
using Poco::Exception;
using Poco::Net::HTTPStreamFactory;
using Poco::Net::HTTPSStreamFactory;
using Poco::Net::FTPStreamFactory;
using Poco::NullOutputStream;

using Poco::Net::HTTPServer;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerParams;
using Poco::Net::HTTPResponse;
using Poco::Net::ServerSocket;
using Poco::Net::SecureServerSocket;
using Poco::Net::SecureStreamSocket;


#define SITE "www.google.com"
#define SITE1 "www.yahoo.com"
#define BUFSIZE 1024
#define N_CONNECTIONS 2
#define N_REQS_PER_CONNECTION 10

/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

//
// SSL server stuff
//

///
/// Read the SSL certificate and key given as parameters.
///
/// The cert and key are read into the provided SSL context.
///
void load_certs(SSL_CTX* ctx, string cert_fn, string key_fn)
{
	int ret;

	FILE* certf = fopen(cert_fn.c_str(), "r");
	FILE* keyf = fopen(key_fn.c_str(), "r");

	// Read the cert and key
	X509* cert_x509 = PEM_read_X509(certf, NULL, NULL, NULL);
	EVP_PKEY* pkey = PEM_read_PrivateKey(keyf, NULL, NULL, NULL);

	if(cert_x509 == nullptr)
	{
		cerr << "Error reading certificate" << endl;
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}
	if(pkey == nullptr)
	{
		cerr << "Error reading private key" << endl;
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	// Set the cert and key in the context
	ret = SSL_CTX_use_certificate(ctx, cert_x509);
	if(ret <= 0)
	{
		cerr << "Error using certificate: " << ret << endl;
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}
	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	if(ret <= 0)
	{
		cerr << "Error using private key: " << ret << endl;
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

cleanup:
	fclose(certf);
	fclose(keyf);
}

///
/// Encapsulates an SSL server socket
///
class ssl_socket
{
	int sock_fd = -1;
	int sock_err = 0;
	SSL_CTX* ctx = nullptr;
	bool run_server = false;
 public:
	ssl_socket()
	{
		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_ssl_algorithms();

		// Create the SSL context
		ctx = SSL_CTX_new(SSLv23_server_method());
		if(!ctx)
		{
			cerr << "Unable to build SSL context" << endl;
			ERR_print_errors_fp(stderr);
			sock_err = -1;
			return;
		}

		SSL_CTX_set_ecdh_auto(ctx, 1);

		load_certs(ctx, "certificate.pem", "key.pem");
	}

	~ssl_socket()
	{
		if(run_server)
		{
			stop();
		}
		if(sock_fd > 0)
		{
			close(sock_fd);
			sock_fd = -1;
		}
		SSL_CTX_free(ctx);
		EVP_cleanup();
	}

	bool error()
	{
		return sock_err != 0;
	}

	void start(uint16_t port)
	{
		uint32_t MAX_WAIT_MS = 5 * 1000;
		run_server = true;
		bool server_started = false;
		std::mutex mtx;
		std::condition_variable cv;

		thread t([this, &server_started, &mtx, &cv](uint16_t port)
		{
			// Create the socket and begin listening

			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(INADDR_ANY);
			addr.sin_port = htons(port);

			int s = socket(addr.sin_family, SOCK_STREAM, 0);
			if(s < 0)
			{
				cerr << "Unable to create socket: " << s << endl;
				sock_err = s;
				return;
			}

			if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
			{
				cerr << "Unable to bind to address: " << s << endl;
				sock_err = s;
				close(s);
				return;
			}

			int ret = listen(s, 1);
			if(ret < 0)
			{
				cerr << "Unable to listen on socket: " << ret << endl;
				sock_err = ret;
				close(s);
				return;
			}

			sock_fd = s;
			std::unique_lock<std::mutex> lck(mtx);
			server_started = true;
			cv.notify_one(); // Let the parent function know the server is ready to roll
			lck.unlock();

			while(run_server)
			{
				struct sockaddr_in addr;
				uint32_t len = sizeof(addr);
				SSL* ssl = nullptr;

				int conn_fd = accept(sock_fd, (struct sockaddr*)&addr, &len);
				if(conn_fd < 0)
				{
					cerr << "Error while accepting incoming connection: " << conn_fd << endl;
					sock_err = conn_fd;
					run_server = false;
					continue;
				}

				ssl = SSL_new(ctx);
				SSL_set_fd(ssl, conn_fd);
				int ret = SSL_accept(ssl);

				if(ret <= 0)
				{
					cerr << "SSL error accepting incoming connection: " << ret << endl;
					ERR_print_errors_fp(stderr);
					run_server = false;
					continue;
				}
				else
				{
					char buf[128] =
					{};
					string response = "Goodbye from Sysdig test SSL server, signing off!";
					SSL_read(ssl, buf, sizeof(buf));
					SSL_write(ssl, buf, strlen(buf));
					SSL_write(ssl, response.c_str(), response.length());
					sleep(1);
				}

				SSL_free(ssl);
				close(conn_fd);
			}
		}, port);
		t.detach();

		// Wait for the server to actually start before returning
		std::unique_lock<std::mutex> guard(mtx);
		while(!server_started)
		{
			if(cv.wait_for(guard, std::chrono::milliseconds(MAX_WAIT_MS)) == cv_status::timeout)
			{
				cerr << "Never got notified that the server got started!" << endl;
				ASSERT(false);
			}
		}
	}

	void stop()
	{
		run_server = false;
		close(sock_fd);
		sock_fd = -1;
	}
};


//
// HTTP server stuff
//

///
/// Handle incoming HTTP requests
///
/// Implements a very simple request handler
///
class HTTPHandler : public Poco::Net::HTTPRequestHandler
{
public:
	virtual void handleRequest(HTTPServerRequest &request, HTTPServerResponse &response) override
	{
		response.setStatus(HTTPResponse::HTTP_OK);
		response.setContentType("text/html");

		ostream& out = response.send();
		out << "<html><body>"
		    << "<h1>Sysdig agent test</h1>"
		    << "<p>Request host = " << request.getHost() << "</p>"
		    << "<p>Request URI = "  << request.getURI()  << "</p>"
		    << "</body></html>"
		    << flush;
	}
};

///
/// Build a request handler when requested by the server
///
class HTTPRHFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
	static const uint16_t port = 9090;
	static const uint16_t secure_port = 443; // The proto analyzer will barf if it's a wonky port
	virtual HTTPHandler* createRequestHandler(const HTTPServerRequest &)
	{
		return new HTTPHandler();
	}
};

///
/// So that callers don't have to remember all the magic words to get the socket.
///
unique_ptr<SecureServerSocket> get_ssl_socket(uint16_t port)
{
	return unique_ptr<SecureServerSocket>(new SecureServerSocket(port, 64 /* backlog */));
}

///
/// Send an ssl request to the given localhost port.
///
/// This will establish an SSL connection, send a string over that connection,
/// and then continue reading replies until the socket is closed.
///
/// Yeah, I know all this OpenSSL API code is gross. But the Poco version
/// was crashing in mysterious ways.
///
/// @param[in]  port  The server port to connect to
///
/// @return  true  The request was made successfully and a response was received
/// @return false  The request encountered an error
///
bool localhost_ssl_request(uint16_t port)
{
    BIO* server = nullptr;
    SSL_CTX* ctx = nullptr;
    SSL *ssl = nullptr;

    // Build the context
    ctx = SSL_CTX_new(SSLv23_method());
    if(ctx == nullptr)
    {
        cerr << "Unable to build SSL context for client" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Set up the context
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);
    int res = SSL_CTX_load_verify_locations(ctx, "certificate.pem", nullptr);
    if(res != 1)
    {
        cerr << "Couldn't load certificate: " << res << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Create the server IO stream and SSL object
    server = BIO_new_ssl_connect(ctx);
    if(server == nullptr)
    {
        cerr << "Couldn't create SSL BIO object" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    stringstream ss;
	ss << "127.0.0.1:" << port;

    BIO_set_conn_hostname(server, ss.str().c_str());
    BIO_get_ssl(server, &ssl);

    if(ssl == nullptr)
    {
        cerr << "Couldn't create SSL object" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    SSL_set_tlsext_host_name(ssl, "127.0.0.1");

    // Connect the IO stream to the server
    res = BIO_do_connect(server);
    if(res != 1)
    {
        cerr << "Client connect failed: " << res << endl;
        return false;
    }

    res = BIO_do_handshake(server);
    if(res != 1)
    {
        cerr << "Client handshake failed: " << res << endl;
        return false;
    }

    // Send the payload
    BIO_puts(server, "Hello from Sysdig test SSL client!");

    // Read the responses until the socket is shut down
    int len = 0;
    char buf[256] = {};

    while(true)
    {
		len = BIO_read(server, buf, sizeof(buf));

		if(len <= 0)
		{
			break;
		}
    }

    // Cleanup
    if(server != nullptr)
    {
    	BIO_free_all(server);
    }

    if(ctx != nullptr)
    {
    	SSL_CTX_free(ctx);
    }

    return true;
}


///
/// Make an HTTP request to the built-in server
///
/// This function knows how to connect to the above server class and provides
/// a convenient interface for making a simple request (assuming we don't care
/// about the response).
///
/// It will block until the response is received.
///
/// @return  true   The request was made successfully
/// @return  false  The request failed before it could be made
///
bool localhost_http_request(uint16_t port)
{
	cerr << "Sending http request" << endl;
	try {
		NullOutputStream ostr;
		stringstream ss;

		Poco::Net::HTTPClientSession session("http://127.0.0.1", port);
		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET);
		Poco::Net::HTTPResponse response;
		session.sendRequest(request);
		session.receiveResponse(response);
	} catch (const Exception& ex) {
		cerr << "Exception: " << ex.displayText() << endl;
		return false;
	}
	return true;
}

TEST_F(sys_call_test, net_web_requests)
{
	int nconns = 0;
	int mytid = getpid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int sockfd, n, j, k;
		struct sockaddr_in serveraddr;
		struct hostent *server;
		char *hostname = (char*)SITE;
		int portno = 80;
		string reqstr;
		char reqbody[BUFSIZE] = "GET / HTTP/1.0\n\n";

		// get the server's DNS entry
		server = gethostbyname(hostname);
		ASSERT_TRUE(server) << "ERROR, no such host as " << hostname;

		for(j = 0; j < N_CONNECTIONS; j++)
		{
			// socket: create the socket
			sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (sockfd < 0)
			{
				error((char*)"ERROR opening socket");
			}

			// build the server's Internet address
			bzero((char *) &serveraddr, sizeof(serveraddr));
			serveraddr.sin_family = AF_INET;
			bcopy((char *)server->h_addr,
			  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
			serveraddr.sin_port = htons(portno);

			// create a connection with the server
			if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
			{
				error((char*)"ERROR connecting");
			}

			for(k = 0; k < N_REQS_PER_CONNECTION; k++)
			{
				reqstr = string("GET ") + "/dfw" + NumberFormatter::format(k) + " HTTP/1.0\n\n";

				// send the request
				n = write(sockfd, reqstr.c_str(), reqstr.length());
				if (n < 0)
				{
					error((char*)"ERROR writing to socket");
				}

				// get the server's reply
				bzero(reqbody, BUFSIZE);
				while(true)
				{
					n = read(sockfd, reqbody, BUFSIZE);
					if(n == 0)
					{
						break;
					}
					if(n < 0)
					{
						error((char*)"ERROR reading from socket");
					}
				}
				//printf("Echo from server: %s", reqbody);
			}

			close(sockfd);
		}

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					if(cit->second.m_stid == mytid && cit->first.m_fields.m_dport == 80)
					{
						SCOPED_TRACE(nconns);
						nconns++;
					}
				}
				SCOPED_TRACE("evaluating assertions");
				sinsp_threadinfo* ti = evt->get_thread_info();
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_in);
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in);
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_in);
				ASSERT_EQ((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_in);
				// Note: +1 is because of the DNS lookup
				ASSERT_GE(ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_out, (uint64_t) N_CONNECTIONS);
				ASSERT_LE(ti->m_ainfo->m_transaction_metrics.get_counter()->m_count_out, (uint64_t) N_CONNECTIONS + 1);
				ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_out);
				ASSERT_EQ((uint64_t) 1, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_count_out);
				ASSERT_NE((uint64_t) 0, ti->m_ainfo->m_transaction_metrics.get_max_counter()->m_time_ns_out);
			}
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);

	// Set DNS port, /etc/services is read only from dragent context
	// port 80 is not needed, because it's http protocol and is autodiscovered
	ports_set known_ports;
	known_ports.set(53);
	configuration.set_known_ports(known_ports);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(N_CONNECTIONS, nconns);
}

TEST_F(sys_call_test, net_ssl_requests)
{
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		return (tinfo != nullptr && tinfo->m_comm == "tests") || m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
	    ssl_socket sock;

	    sock.start(443);

	    if(!localhost_ssl_request(443))
	    {
	        cerr << "A bad thing happened attempting to connect to the SSL server." << endl;
	    }
	    sock.stop();

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);

		return 0;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E &&
		   NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
		{
			auto threadtable = param.m_inspector->m_thread_manager->get_threads();
			sinsp_transaction_counters transaction_metrics;
			transaction_metrics.clear();
			threadtable->loop([&] (sinsp_threadinfo& tinfo)
			{
				if(tinfo.m_comm == "tests")
				{
					transaction_metrics.add(&tinfo.m_ainfo->m_transaction_metrics);
				}
				return true;
			});

			EXPECT_EQ((uint64_t) 1, transaction_metrics.get_counter()->m_count_in);
			EXPECT_LT((uint64_t) 0, transaction_metrics.get_counter()->m_time_ns_in);
			EXPECT_EQ((uint64_t) 1, transaction_metrics.get_max_counter()->m_count_in);
			EXPECT_LT((uint64_t) 0, transaction_metrics.get_max_counter()->m_time_ns_in);

			EXPECT_EQ((uint64_t) 1, transaction_metrics.get_counter()->m_count_out);
			EXPECT_NE((uint64_t) 0, transaction_metrics.get_counter()->m_time_ns_out);
			EXPECT_EQ((uint64_t) 1, transaction_metrics.get_max_counter()->m_count_out);
			EXPECT_NE((uint64_t) 0, transaction_metrics.get_max_counter()->m_time_ns_out);
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);
	ports_set ports;
	ports.set(443);
	configuration.set_known_ports(ports);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
}

//
// This test checks the fact that connect can be called on a UDP socket
// so that read/write/send/recv can then be used on the socket, without the overhead
// of specifying the address with every IO operation.
//
TEST_F(sys_call_test, net_double_udp_connect)
{
	int nconns = 0;
	int mytid = getpid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int sockfd, n;
		struct sockaddr_in serveraddr;
		struct sockaddr_in serveraddr1;
		struct hostent *server;
		struct hostent *server1;
		char *hostname = (char*)SITE;
		char *hostname1 = (char*)SITE1;
		int portno = 80;
		string reqstr;

		// get the first server's DNS entry
		server = gethostbyname(hostname);
		if (server == NULL) {
		    fprintf(stderr,(char*)"ERROR, no such host as %s\n", hostname);
		    exit(0);
		}

		// get the second server's DNS entry
		server1 = gethostbyname(hostname1);
		if(server1 == NULL) {
		    fprintf(stderr,(char*)"ERROR, no such host as %s\n", hostname1);
		    exit(0);
		}

		// create the socket
		sockfd = socket(2, 2, 0);
		if (sockfd < 0)
		{
			error((char*)"ERROR opening socket");
		}

		// build the server's Internet address
		bzero((char *) &serveraddr, sizeof(serveraddr));
		serveraddr.sin_family = AF_INET;
		bcopy((char *)server->h_addr,
		  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
		serveraddr.sin_port = 0;

		// create a connection with google
		if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
		{
			error((char*)"ERROR connecting");
		}

		// create a SECOND connection with google
		if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
		{
			error((char*)"ERROR connecting");
		}

		// build the server's Internet address
		bzero((char *) &serveraddr1, sizeof(serveraddr1));
		serveraddr1.sin_family = AF_INET;
		bcopy((char *)server1->h_addr,
		  (char *)&serveraddr1.sin_addr.s_addr, server1->h_length);
		serveraddr1.sin_port = htons(portno);

		// create a connection with yahoo
		if(connect(sockfd, (struct sockaddr*)&serveraddr1, sizeof(serveraddr1)) < 0)
		{
			error((char*)"ERROR connecting");
		}

		//
		// Send a datagram
		//
		reqstr = "GET /dfw HTTP/1.0\n\n";

		// send the request
		n = write(sockfd, reqstr.c_str(), reqstr.length());
		if (n < 0)
		{
			error((char*)"ERROR writing to socket");
		}

		//
		// Close the socket
		//
		close(sockfd);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);

		return 0;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					if(cit->second.m_stid == mytid && cit->first.m_fields.m_dport == 80)
					{
						nconns++;
					}
				}
			}
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});

	ASSERT_EQ(1, nconns);
}

TEST_F(sys_call_test, net_connection_table_limit)
{
	int nconns = 0;
//	int mytid = getpid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		const int REQUESTS_TO_SEND = 5;
		int num_requests = 0;
		// Spin up a thread to run the HTTP server
	    std::thread ws_thread([&num_requests]
		{
			HTTPServer srv(new HTTPRHFactory, ServerSocket(HTTPRHFactory::port), new HTTPServerParams);

			srv.start();

			while (num_requests < REQUESTS_TO_SEND) {
				std::this_thread::sleep_for(chrono::milliseconds(250));
			}

			srv.stop();
		});

		try
		{
			HTTPStreamFactory::registerFactory();

			NullOutputStream ostr;

			URI uri("http://127.0.0.1:9090");

			// Sleep to give the server time to start up
			std::this_thread::sleep_for(chrono::milliseconds(500));

			std::unique_ptr<std::istream> pStrs[REQUESTS_TO_SEND];
			for (int i = 0; i < REQUESTS_TO_SEND; ++i) {
				pStrs[i] = std::move(std::unique_ptr<std::istream>(URIStreamOpener::defaultOpener().open(uri)));
				StreamCopier::copyStream(*pStrs[i].get(), ostr);
				++num_requests;
			}
			// We use a random call to tee to signal that we're done
			tee(-1, -1, 0, 0);
		}
		catch (Exception& exc)
		{
			std::cerr << exc.displayText() << std::endl;
			FAIL();
		}

		ws_thread.join();
		return;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					nconns++;
				}

				ASSERT_EQ(3, nconns);
			}
		}
	};

	//
	// Set a very long sample time, so we're sure no connection is removed
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(100 * ONE_SECOND_IN_NS);

	//
	// Set a very low connection table size
	//
	configuration.set_max_connection_table_size(3);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
}

TEST_F(sys_call_test, DISABLED_net_connection_aggregation)
{
	int nconns = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		try
		{
			HTTPStreamFactory::registerFactory();

			NullOutputStream ostr;

			URI uri1("http://www.google.com");
			std::unique_ptr<std::istream> pStr1(URIStreamOpener::defaultOpener().open(uri1));
			StreamCopier::copyStream(*pStr1.get(), ostr);

			URI uri2("http://www.yahoo.com");
			std::unique_ptr<std::istream> pStr2(URIStreamOpener::defaultOpener().open(uri2));
			StreamCopier::copyStream(*pStr2.get(), ostr);

			URI uri3("http://www.bing.com");
			std::unique_ptr<std::istream> pStr3(URIStreamOpener::defaultOpener().open(uri3));
			StreamCopier::copyStream(*pStr3.get(), ostr);

			// We use a random call to tee to signal that we're done
			tee(-1, -1, 0, 0);
//			sleep(5);
		}
		catch (Exception& exc)
		{
			std::cerr << exc.displayText() << std::endl;
			FAIL();
		}

		return;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
return;
		sinsp_evt *evt = param.m_evt;

		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
				for(cit = param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.begin();
					cit != param.m_inspector->m_analyzer->m_ipv4_connections->m_connections.end(); ++cit)
				{
					nconns++;
				}

				ASSERT_EQ(3, nconns);
			}
		}
	};

	//
	// Set a very low connection table size
	//
	sinsp_configuration configuration;
	configuration.set_analyzer_sample_len_ns(3 * ONE_SECOND_IN_NS);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
}

TEST(sinsp_protostate, test_zero)
{
	sinsp_protostate protostate;
	auto protos = make_unique<draiosproto::proto_info>();
	protostate.to_protobuf(protos.get(), 1, 20);
	EXPECT_FALSE(protos->has_http());
	EXPECT_FALSE(protos->has_mysql());
	EXPECT_FALSE(protos->has_postgres());
	EXPECT_FALSE(protos->has_mongodb());
}

// "standard" class can be used to access private members
class test_helper
{
public:
    static vector<unordered_map<string, sinsp_url_details>::iterator>* get_server_urls(sinsp_protostate_marker* spm)
    {
        return &spm->m_http.m_server_urls;
    }

    static vector<unordered_map<string, sinsp_url_details>::iterator>* get_client_urls(sinsp_protostate_marker* spm)
    {
        return &spm->m_http.m_client_urls;
    }

    static sinsp_http_parser::Result* get_result(sinsp_http_parser* parser)
    {
	    return &parser->m_result;
    }
};

// need 3 classes of URLs for this test
// -URLs which are in the top 15 in a stat
// -URLs which are not in the top 15, but are in a group and are top in that group
// -URLs which are not in the top 15, but are in a group and NOT top in that group
//
// we'll use 1 for our test...because easier
TEST(sinsp_protostate, test_url_groups)
{
    sinsp_protostate protostate;
    set<string> groups = {".*group.*"};
    protostate.set_url_groups(groups);

    for (int i = 0; i < 5; ++i)
    {
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://test");
	test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
	test_helper::get_result(http_parser)->status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1, false, 512);
    }

    for (int i = 0; i < 3; ++i)
    {
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://testgroup1");
	test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
	test_helper::get_result(http_parser)->status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1, false, 512);
    }

    auto transaction = make_unique<sinsp_partial_transaction>();
    auto http_parser = new sinsp_http_parser();
    auto url = string("http://testgroup2");
    test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
    test_helper::get_result(http_parser)->status_code = 200;
    http_parser->m_is_valid = true;
    transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
    transaction->m_protoparser = http_parser;
    protostate.update(transaction.get(), 1, false, 512);

    sinsp_protostate_marker marker;
    marker.add(&protostate);
    marker.mark_top(1);

    auto client_urls = test_helper::get_client_urls(&marker);
    EXPECT_EQ(client_urls->size(), 3);

    for (auto url = client_urls->begin(); url != client_urls->end(); ++url)
    {
        if ((*url)->first == "http://testgroup1")
        {
            EXPECT_GT((*url)->second.m_flags & SRF_INCLUDE_IN_SAMPLE, 0);
        }
        else
        {
            EXPECT_EQ((*url)->second.m_flags & SRF_INCLUDE_IN_SAMPLE, 0);
        }
    }

    delete sinsp_protostate::s_url_groups;
    sinsp_protostate::s_url_groups = NULL;
}



TEST(sinsp_protostate, test_per_container_distribution)
{
	std::array<sinsp_protostate, 80> protostates;
	for(auto& protostate : protostates)
	{
		for(auto j = 0; j < 100; ++j)
		{
			auto transaction = make_unique<sinsp_partial_transaction>();
			auto http_parser = new sinsp_http_parser();
			auto url = string("http://test") + to_string(j);
			http_parser->m_result.url = url.c_str();
			http_parser->m_result.status_code = 200;
			http_parser->m_is_valid = true;
			transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
			transaction->m_protoparser = http_parser;
			protostate.update(transaction.get(), j, false, 512);
		}
	}
	sinsp_protostate_marker marker;
	for(auto& protostate: protostates)
	{
		marker.add(&protostate);
	}
	marker.mark_top(15);
	auto has_urls = 0;
	for(auto& protostate : protostates)
	{
		auto protos = make_unique<draiosproto::proto_info>();
		protostate.to_protobuf(protos.get(), 1, 15);
		if(protos->has_http())
		{
			auto http = protos->http();

			if(http.client_urls().size() > 0)
			{
				has_urls += 1;
			}
		}
		EXPECT_FALSE(protos->has_mysql());
		EXPECT_FALSE(protos->has_postgres());
		EXPECT_FALSE(protos->has_mongodb());
	}
	EXPECT_EQ(15, has_urls);
}

TEST(sinsp_protostate, test_top_call_should_be_present)
{
	std::array<sinsp_protostate, 80> protostates;
	for(auto& protostate : protostates)
	{
		for(auto j = 0; j < 100; ++j)
		{
			auto transaction = make_unique<sinsp_partial_transaction>();
			auto http_parser = new sinsp_http_parser();
			auto url = string("http://test") + to_string(j);
			http_parser->m_result.url = url.c_str();
			http_parser->m_result.status_code = 200;
			http_parser->m_is_valid = true;
			transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
			transaction->m_protoparser = http_parser;
			protostate.update(transaction.get(), j, false, 512);
		}
	}
	{
		auto& protostate = protostates.at(0);
		auto transaction = make_unique<sinsp_partial_transaction>();
		auto http_parser = new sinsp_http_parser();
		auto url = string("http://test/url/slow");
		http_parser->m_result.url = url.c_str();
		http_parser->m_result.status_code = 200;
		http_parser->m_is_valid = true;
		transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
		transaction->m_protoparser = http_parser;
		protostate.update(transaction.get(), 1000, false, 512);
	}

	{
		auto& protostate = protostates.at(50);
		for(auto j = 0; j < 500; ++j)
		{
			auto transaction = make_unique<sinsp_partial_transaction>();
			auto http_parser = new sinsp_http_parser();
			auto url = string("http://test/url/topcall");
			http_parser->m_result.url = url.c_str();
			http_parser->m_result.status_code = 204;
			http_parser->m_is_valid = true;
			transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
			transaction->m_protoparser = http_parser;
			protostate.update(transaction.get(), 2, false, 512);
		}
	}

	sinsp_protostate_marker marker;
	for(auto& protostate: protostates)
	{
		marker.add(&protostate);
	}
	marker.mark_top(15);
	auto found_slow = false;
	auto found_top_call = false;
	auto top_ncalls = 0;
	for(auto& protostate : protostates)
	{
		auto protos = make_unique<draiosproto::proto_info>();
		protostate.to_protobuf(protos.get(), 1, 15);
		if(protos->has_http())
		{
			auto http = protos->http();

			if(http.client_urls().size() > 0)
			{
				for(auto url : http.client_urls())
				{
					if(url.url().find("slow") != string::npos)
					{
						found_slow = true;
					}
					if(url.url().find("topcall") != string::npos)
					{
						found_top_call = true;
					}
				}
			}
			for(auto status_code : http.client_status_codes())
			{
				if(status_code.status_code() == 204)
				{
					top_ncalls = status_code.ncalls();
				}
			}
		}
		EXPECT_FALSE(protos->has_mysql());
		EXPECT_FALSE(protos->has_postgres());
		EXPECT_FALSE(protos->has_mongodb());
	}
	EXPECT_TRUE(found_slow);
	EXPECT_TRUE(found_top_call);
	EXPECT_EQ(500, top_ncalls);
}

TEST(sinsp_procfs_parser, DISABLED_test_read_network_interfaces_stats)
{
	// cpu, mem, live, ttl cpu, ttl mem
	sinsp_procfs_parser parser(1, 1024, true, 0, 0);

	auto stats = parser.read_network_interfaces_stats();
	EXPECT_EQ(stats.first, 0U);
	EXPECT_EQ(stats.second, 0U);
	ASSERT_TRUE(system("curl https://google.com > /dev/null 2> /dev/null") == 0);
	stats = parser.read_network_interfaces_stats();
	EXPECT_GT(stats.first, 0U);
	EXPECT_GT(stats.second, 0U);
}

TEST(sinsp_procfs_parser, test_add_ports_from_proc_fs)
{
	const char *filename="resources/procfs.tcp";
	set<uint16_t> oldports = { 2379 };
	set<uint16_t> newports;
	// These inodes should match local ports 42602, 2379, 2380 and 59042
	// Port 59042 is a connection to a remote host and not a listening port
	set<uint64_t> inodes = { 17550, 18661, 18655, 128153, 12345 };

	// Since oldports already has 2379 the expected ports added in newports should be 42602 and 2380
	EXPECT_EQ(sinsp_procfs_parser::add_ports_from_proc_fs(filename, oldports, newports, inodes), 2);
	EXPECT_EQ(newports.size(), 2);
	EXPECT_TRUE(newports.find(42602) != newports.end());
	EXPECT_TRUE(newports.find(2380) != newports.end());
}

TEST(sinsp_procfs_parser, test_read_process_serverports)
{
	const uint16_t port = 999;
	set<uint16_t> oldports;
	set<uint16_t> newports;
	pid_t pid = getpid();

	// Populate oldports with current listening ports
	sinsp_procfs_parser::read_process_serverports(pid, newports, oldports);
	// Make sure we're not listening to our port yet
	ASSERT_TRUE(oldports.find(port) == oldports.end());
	// Create socket, bind and listen
	ServerSocket sock(port);

	// Check listening ports
	EXPECT_EQ(sinsp_procfs_parser::read_process_serverports(pid, oldports, newports), 1);
	// Should have found our new port
	EXPECT_EQ(newports.size(), 1);
	EXPECT_TRUE(newports.find(port) != newports.end());
}
