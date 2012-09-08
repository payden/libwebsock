//libwebsock Copyright 2012 Payden Sutherland

#define EPOLL_EVENTS 100
#define PORT_STRLEN 12
#define LISTEN_BACKLOG 10
#define FRAME_CHUNK_LENGTH 1024
#define MASK_LENGTH 4

typedef struct _libwebsock_string {
	char *data;
	int length;
	int idx;
	int data_sz;
} libwebsock_string;

typedef struct _libwebsock_frame {
	unsigned int fin;
	unsigned int opcode;
	unsigned int mask_offset;
	unsigned int payload_offset;
	unsigned int rawdata_idx;
	unsigned int rawdata_sz;
	unsigned long long payload_len;
	char *rawdata;
	struct _libwebsock_frame *next_frame;
	struct _libwebsock_frame *prev_frame;
	unsigned char mask[4];
} libwebsock_frame;

typedef struct _libwebsock_message {
	unsigned int opcode;
	unsigned long long payload_len;
	char *payload;
} libwebsock_message;

typedef struct _libwebsock_client_state {
	int sockfd;
	int sent_close_frame;
	int should_close;
	int connecting;
	//need to throw these flags in a single flags variable
	void *data;
	libwebsock_frame *current_frame;
} libwebsock_client_state;

typedef struct _libwebsock_context {
	int listen_fd;
	int epoll_fd;
	int (*receive_callback)(libwebsock_client_state*, libwebsock_message*);
	int (*control_callback)(libwebsock_client_state*, libwebsock_frame*);
	int (*connect_callback)(libwebsock_client_state*);
	int (*close_callback)(libwebsock_client_state*);
	char port[PORT_STRLEN];
	struct epoll_event *events;
} libwebsock_context;





//function defs

int libwebsock_send_binary(int sockfd, char *in_data, unsigned long long datalen);
int libwebsock_send_text(int sockfd, char *strdata);
int libwebsock_complete_frame(libwebsock_frame *frame);
int libwebsock_default_close_callback(libwebsock_client_state *state);
int libwebsock_default_connect_callback(libwebsock_client_state *state);
int libwebsock_default_receive_callback(libwebsock_client_state *state, libwebsock_message *msg);
int libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame);
void libwebsock_shutdown(libwebsock_context *ctx);
void libwebsock_handle_control_frame(libwebsock_context *ctx, libwebsock_client_state *state, libwebsock_frame *ctl_frame);
void libwebsock_dispatch_message(libwebsock_context *ctx, libwebsock_client_state *state, libwebsock_frame *current);
void libwebsock_in_data(libwebsock_context *ctx, libwebsock_client_state *state, char byte);
void libwebsock_dump_frame(libwebsock_frame *frame);
void libwebsock_handle_recv(libwebsock_context *ctx, libwebsock_client_state *state, char *data, int datalen);
void libwebsock_handle_client_event(libwebsock_context *ctx, libwebsock_client_state *state);
void libwebsock_wait(libwebsock_context *ctx);
void libwebsock_handshake_finish(libwebsock_context *ctx, libwebsock_client_state *state);
void libwebsock_handshake(libwebsock_context *ctx, libwebsock_client_state *state, char *data, int datalen);
void libwebsock_set_close_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state*));
void libwebsock_set_receive_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state*, libwebsock_message *msg));
void libwebsock_set_receive_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state*, libwebsock_message *msg));
void libwebsock_set_connect_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state *state));
libwebsock_context *libwebsock_init(char *port);
