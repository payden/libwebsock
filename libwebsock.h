//libwebsock Copyright 2012 Payden Sutherland

#define EPOLL_EVENTS 100
#define PORT_STRLEN 12
#define LISTEN_BACKLOG 10

typedef struct {
	unsigned int opcode;
	unsigned long long payload_len;
	char *payload;
} libwebsock_message;

typedef struct {
	int listen_fd;
	int epoll_fd;
	int (*received_callback)(int, libwebsock_message*);
	char port[PORT_STRLEN];
	struct epoll_event *events;
} libwebsock_context;

typedef struct {
	int sockfd;
	int in_fragment;
	int in_frame;
	char *data;
} libwebsock_client_state;

//function defs

void libwebsock_handle_client_event(libwebsock_context *ctx, libwebsock_client_state *state);
void libwebsock_wait(libwebsock_context *ctx);
void libwebsock_handshake(libwebsock_context *ctx, int sockfd);
void libwebsock_set_receive_cb(libwebsock_context *ctx, int (*cb)(int, libwebsock_message *msg));
libwebsock_context *libwebsock_init(char *port);
