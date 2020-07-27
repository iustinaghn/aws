#include "aws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <sys/sendfile.h>

#include "util.h"
#include "debug.h"
#include "sock_util.h"
#include "w_epoll.h"
#include "http_parser.h"
#include <libaio.h>
#include <sys/eventfd.h>

#include <errno.h>

#define NR_EVENTS 1

enum connection_state {
	STATE_DATA_PARTIAL_RECEIVED, STATE_DATA_PARTIAL_SENT,
	STATE_DATA_RECEIVED, STATE_DATA_SENT,
	STATE_CONNECTION_CLOSED
};

/* structure acting as a connection handler */
struct connection {
	int sockfd;
	enum connection_state state;
	/* buffers used for receiving messages and then echoing them back */
	char recv_buffer[BUFSIZ], send_buffer[BUFSIZ];
	size_t recv_len, send_len;
	int fd, efd;
	size_t size;
	int states, nb_case;
	off_t offset;
	size_t got, sent, nr_sub, all_sent;
	size_t last_bytes, bytes_sent;
	void **send_buffers;
	io_context_t context;
	struct iocb **piocb, *iocb;
} connection =  {
	.state = 0,
	.nb_case = 0,
	.offset = 0,
	.recv_len = 0,
	.send_len = 0,
	.bytes_sent = 0,
	.got = 0,
	.nr_sub = 0,
	.all_sent = 0,
	.sent = 0,
	.last_bytes = 0,
};

static http_parser request_parser;
static char request_path[BUFSIZ];	/* storage for request_path */

/* server socket file descriptor */
static int listenfd;
/* epoll file descriptor */
static int epollfd;

/*
 * Callback is invoked by HTTP request parser when parsing request path.
 * Request path is stored in global request_path variable.
 */

static int on_path_cb(http_parser *p, const char *buf, size_t len)
{
	char path[BUFSIZ];

	assert(p == &request_parser);
	sscanf(buf, "%[^.]", path);

	sprintf(request_path, "%s%s.dat",AWS_DOCUMENT_ROOT, path + 1);
	return 0;
}


/*
 * Initialize connection structure on given socket.
 */

static struct connection *connection_create(int sockfd)
{
	struct connection *conn = malloc(sizeof(*conn));

	DIE(!conn, "[ERROR] malloc");

	memset(conn->recv_buffer, 0, BUFSIZ);
	memset(conn->send_buffer, 0, BUFSIZ);

	memset(&conn->context, 0, sizeof(io_context_t));
	conn->sockfd = sockfd;

	int rs = io_setup(NR_EVENTS, &conn->context);

	DIE(rs < 0, strerror(errno));

	conn->efd = eventfd(0, EFD_NONBLOCK);
	DIE(conn->efd < 0, "[ERROR] efd");

	return conn;
}

/*
 * Remove connection handler.
 */

static void connection_remove(struct connection *conn)
{
	conn->state = STATE_CONNECTION_CLOSED;
	close(conn->sockfd);
	free(conn);
}

/*
 * Handle a new connection request on the server socket.
 */

static void handle_new_connection(void)
{
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;

	/* accept new connection */
	int sockfd = accept(listenfd, (SSA *) &addr, &addrlen);

	DIE(sockfd < 0, "[ERROR] accept");

	int fcntl_flag = fcntl(sockfd, F_GETFL, 0);

	fcntl(sockfd, F_SETFL, fcntl_flag | O_NONBLOCK);

	/* instantiate new connection handler */
	struct connection *conn = connection_create(sockfd);

	/* add socket to epoll */
	int rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);

	DIE(rc < 0, "[ERROR] w_epoll_add_ptr_in");
}

static void removeConnection_send(int *rc, struct connection *conn)
{
	*rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "[ERROR] w_epoll_remove_ptr");

	close(conn->fd);
	connection_remove(conn);
}

static enum connection_state send_message(struct connection *conn)
{
	char abuffer[64];

	int rc = get_peer_address(conn->sockfd, abuffer, 64);

	if (rc < 0) {
		ERR("get_peer_address");
		removeConnection_send(&rc, conn);
		return STATE_CONNECTION_CLOSED;
	}

	const void *buf = conn->send_buffer + conn->bytes_sent;
	size_t len = conn->send_len - conn->bytes_sent;
	ssize_t bytes_sent = send(conn->sockfd,
				  buf,
				  len,
				  0);
	if (bytes_sent < 0) {
		removeConnection_send(&rc, conn);
		return STATE_CONNECTION_CLOSED;
	}

	conn->bytes_sent += bytes_sent;
	if (conn->bytes_sent < conn->send_len)
		return STATE_DATA_PARTIAL_SENT;

	if (bytes_sent == 0) {
		removeConnection_send(&rc, conn);
		return STATE_CONNECTION_CLOSED;
	}

	conn->state = STATE_DATA_SENT;

	return STATE_DATA_SENT;
}


/* Use mostly null settings except for on_path callback. */
static http_parser_settings settings_on_path = {
	/* on_message_begin */ 0,
	/* on_header_field */ 0,
	/* on_header_value */ 0,
	/* on_path */ on_path_cb,
	/* on_url */ 0,
	/* on_fragment */ 0,
	/* on_query_string */ 0,
	/* on_body */ 0,
	/* on_headers_complete */ 0,
	/* on_message_complete */ 0
};

static void removeConnection_receive(int *rc, struct connection *conn, int sk)
{
	/* close local socket */
	*rc = w_epoll_remove_ptr(epollfd, sk, conn);
	DIE(rc < 0, "[ERROR] w_epoll_remove_ptr");

	close(conn->sockfd);

	*rc = io_destroy(conn->context);
	DIE(rc < 0, "[ERROR] io_destroy");

	/* remove current connection */
	connection_remove(conn);
}

static enum connection_state receive_request(struct connection *conn)
{
	char abuffer[64];

	int rc = get_peer_address(conn->sockfd, abuffer, 64);

	if (rc < 0) {
		ERR("get_peer_address");
		removeConnection_receive(&rc, conn, conn->sockfd);
		return STATE_CONNECTION_CLOSED;
	}

	void *buf = conn->recv_buffer + conn->recv_len;
	size_t len = BUFSIZ - conn->recv_len;
	ssize_t bytes_recv = recv(conn->sockfd,
				  buf,
				  len,
				  0);
	if (bytes_recv <= 0) {
		removeConnection_receive(&rc, conn, conn->sockfd);
		return STATE_CONNECTION_CLOSED;
	}

	conn->recv_len += bytes_recv;
	conn->state = STATE_DATA_RECEIVED;

	conn->recv_buffer[conn->recv_len] = 0;

	int buff_endl = strcmp(conn->recv_buffer + conn->recv_len - sizeof(int),
				"\r\n\r\n");

	if (buff_endl != 0)
		return STATE_DATA_PARTIAL_RECEIVED;

	/* init HTTP_REQUEST parser */
	http_parser_init(&request_parser, HTTP_REQUEST);

	size_t bytes_parsed = http_parser_execute(&request_parser,
						  &settings_on_path,
						  conn->recv_buffer,
						  conn->recv_len);

	if (bytes_parsed == 0) {
		removeConnection_receive(&rc, conn, conn->sockfd);
		return STATE_CONNECTION_CLOSED;
	}

	return STATE_DATA_RECEIVED;
}

static void put_header(struct connection *conn)
{
	sprintf(conn->send_buffer, "HTTP/1.1 200 OK\r\n"
		"Date: Sun, 08 May 2011 09:26:16 GMT\r\n"
		"Server: Apache/2.2.9\r\n"
		"Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: %ld\r\n"
		"Vary: Accept-Encoding\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"\r\n", conn->size);
	conn->send_len = strlen(conn->send_buffer);
}

static void put_error(struct connection *conn)
{
	sprintf(conn->send_buffer,  "HTTP/1.1 404 Not Found\r\n"
		"Date: Sun, 08 May 2011 09:26:16 GMT\r\n"
		"Server: Apache/2.2.9\r\n"
		"Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: 153\r\n"
		"Vary: Accept-Encoding\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"\r\n");
	conn->send_len = strlen(conn->send_buffer);
}

/*
 * Handle a client request on a client connection.
 */

static void handle_client_request(struct connection *conn)
{
	enum connection_state ret_state = receive_request(conn);

	if (ret_state == STATE_CONNECTION_CLOSED)
		return;
	if (ret_state == STATE_DATA_PARTIAL_RECEIVED)
		return;

		/* add socket to epoll for out events */
	int rc = w_epoll_update_ptr_out(epollfd, conn->sockfd, conn);//inout

	DIE(rc < 0, "[ERROR] w_epoll_add_ptr_out");

	/* Open the input file. */
	conn->fd = open(request_path, O_RDONLY);
	if (conn->fd == -1) {
		conn->nb_case = 0;
		put_error(conn);
		return;
	}

	char static_prefix[BUFSIZ];

	sprintf(static_prefix, "%sstatic/", AWS_DOCUMENT_ROOT);

	char dynamic_prefix[BUFSIZ];

	sprintf(dynamic_prefix, "%sdynamic/", AWS_DOCUMENT_ROOT);

	struct stat stat_buf;

	/* Stat the input file to obtain its size. */
	fstat(conn->fd, &stat_buf);
	conn->size = stat_buf.st_size;
	conn->offset = 0;

	int static_request = strncmp(request_path,
				     static_prefix,
				     strlen(static_prefix));
	int dynamic_request = strncmp(request_path,
				      dynamic_prefix,
				      strlen(dynamic_prefix));

	if (static_request != 0 && dynamic_request != 0) {
		put_error(conn);
		conn->nb_case = 0;
		return;
	} else if (static_request == 0 || dynamic_request == 0) {
		conn->states = 0;
		put_header(conn);

		conn->nb_case = (static_request == 0) ? 1 : 2;
	}
}

static void send_file_aio(struct connection *conn)
{
	int i = 0;
	int nr_bytes, rc, n;

	n = (conn->size % BUFSIZ) ?
		(conn->size / BUFSIZ + 1) : (conn->size / BUFSIZ);

	conn->iocb = malloc(n * sizeof(struct iocb));
	if (!conn->iocb) {
		perror("iocb alloc");
		return;
	}
	conn->piocb = malloc(n * sizeof(struct iocb *));
	if (!conn->piocb) {
		perror("iocb alloc");
		return;
	}

	conn->send_buffers = malloc(n * sizeof(char *));
	DIE(!conn->send_buffers, "[ERROR] send_buffers malloc");

	for (; i < n; i++) {
		if (conn->size - conn->offset >= BUFSIZ)
			nr_bytes = BUFSIZ;
		else
			nr_bytes = conn->size - conn->offset;

		conn->piocb[i] = &conn->iocb[i];

		conn->send_buffers[i] = malloc(BUFSIZ * sizeof(char));
		DIE(!conn->send_buffers[i], "[ERROR] send_buffers malloc");

		io_prep_pread(&conn->iocb[i],
			      conn->fd,
			      conn->send_buffers[i],
			      nr_bytes,
			      conn->offset);

		conn->offset += nr_bytes;
		io_set_eventfd(&conn->iocb[i], conn->efd);

		conn->last_bytes = (i == n - 1) ? nr_bytes : conn->last_bytes;

	}
	long nr = n - conn->nr_sub;
	struct iocb **iocbpp = conn->piocb + conn->nr_sub;

	rc = io_submit(conn->context, nr, iocbpp);
	DIE(rc < 0, "[ERROR] io_submit");

	conn->nr_sub += rc;
	conn->all_sent = n;
	conn->states = 2;

	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "[ERROR] w_epoll_remove_conn");

	rc = w_epoll_add_efd(epollfd, conn->efd, conn);
	DIE(rc < 0, "[ERROR] w_epoll_add_efd");

}

void init(void)
{
	/* init multiplexing */
	epollfd = w_epoll_create();
	DIE(epollfd < 0, "[ERROR] w_epoll_create");

	/* create server socket */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT,
		DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "[ERROR] tcp_create_listener");

	int rc = w_epoll_add_fd_in(epollfd, listenfd);

	DIE(rc < 0, "[ERROR] w_epoll_add_fd_in");
}

void epollin(struct connection *conn, struct epoll_event rev)
{
	switch (conn->nb_case) {
	case 0:
		handle_client_request(rev.data.ptr);
		break;
	case 1:
		handle_client_request(rev.data.ptr);
		break;
	case 2:
		if (conn->states == 2) {
			u_int64_t efd_val;
			int rc = read(conn->efd, &efd_val, sizeof(u_int64_t));

			DIE(rc < 0, "[ERROR] read efd");
	
			struct io_event events[conn->nr_sub];

			rc = io_getevents(conn->context,
					  efd_val, 
					  efd_val, 
					  events, 
					  NULL);
			DIE(rc != efd_val, "[ERROR] io_getevents");

			conn->got += (size_t) efd_val;

			rc = w_epoll_add_ptr_out(epollfd, conn->sockfd, conn);
			DIE(rc < 0, "[ERROR] w_epoll_add_ptr_out");	
		}
	}
}

void wait_for_events(struct epoll_event *rev)
{
	int rc = w_epoll_wait_infinite(epollfd, rev);

	DIE(rc < 0, "[ERROR] w_epoll_wait_infinite");
}

int main(void)
{
	enum connection_state ret_state;

	init();

	/* server loop */
	for (;;) {
		struct epoll_event rev;
		struct connection *conn;
		
		wait_for_events(&rev);
		
		conn = rev.data.ptr;

		if (rev.data.fd == listenfd && (rev.events & EPOLLIN))
			handle_new_connection();
		else if (rev.events & EPOLLIN)
			epollin(conn, rev);
		else if (rev.events & EPOLLOUT) {
			int nr, nr_bytes, rc;

			switch (conn->nb_case) {
			case 0: 
				ret_state = send_message(conn);
				if (ret_state != STATE_CONNECTION_CLOSED) 
					break;
				else if (ret_state != STATE_DATA_PARTIAL_SENT)
					break;

				removeConnection_receive(&rc, conn, conn->sockfd);
				break;
			case 1:  
				switch (conn->states) {
				case 0: 
					ret_state = send_message(conn);
					if (ret_state == STATE_CONNECTION_CLOSED || ret_state == STATE_DATA_PARTIAL_SENT)
						continue;
					conn->bytes_sent = 0;
					conn->states = 1;
					break;
				case 1:
					nr_bytes = (conn->size - conn->offset <= BUFSIZ) ? (conn->size - conn->offset) : BUFSIZ;
	
					nr = sendfile(conn->sockfd, conn->fd, &conn->offset, nr_bytes);
					DIE(nr < 0, "eroare trimitere fisier");

					conn->bytes_sent += nr;

					if(nr == 0) {
						conn->states = 0;
						conn->bytes_sent = 0;
						removeConnection_receive(&rc, conn, conn->sockfd);
					}
					break;
				}
				break;
			case 2: 
				switch (conn->states) {
				case 0:
					ret_state = send_message(conn);
					if(ret_state == STATE_CONNECTION_CLOSED || ret_state == STATE_DATA_PARTIAL_SENT)
						continue;
					conn->states = 1;
					conn->bytes_sent = 0;
					break;
				case 1:
					send_file_aio(conn);
					break;
				case 2:
					if(conn->got < conn->sent)
						continue;
					else if(conn->got == conn->sent) {
						rc = w_epoll_remove_ptr(epollfd,
											    conn->sockfd, 
												conn);
						DIE(rc < 0, "[ERROR]w_epoll_remove_ptr");

						if(conn->nr_sub < conn->all_sent) {
							long nr = conn->all_sent - conn->nr_sub;
							struct iocb **iocbpp = conn->piocb + conn->nr_sub;
							int rc = io_submit(conn->context, nr, iocbpp);
							
							DIE(rc < 0, "[ERROR] io_submit");

							conn->nr_sub += rc;
						}
					} else if(conn->got > conn->sent) {
						memcpy(conn->send_buffer, conn->send_buffers[conn->sent], BUFSIZ);

						conn->send_len = (conn->sent == conn->nr_sub - 1) ? conn->last_bytes : BUFSIZ;
				
						ret_state = send_message(conn);
						if(ret_state == STATE_CONNECTION_CLOSED || ret_state == STATE_DATA_PARTIAL_SENT)
							continue;
						conn->bytes_sent = 0;
						++conn->sent;			
					}

					if(conn->sent == conn->all_sent) {
						int i = 0;

						for(; i < conn->nr_sub; i++)
							free(conn->send_buffers[i]);
						free(conn->send_buffers);

						removeConnection_receive(&rc, conn, conn->efd);
					}
					break;
				}
				break;
			}
		}		
	}

	return 0;
}
