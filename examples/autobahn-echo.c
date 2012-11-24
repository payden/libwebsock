#include <stdio.h>
#include <stdlib.h>
#include <websock/websock.h>

int
onmessage(libwebsock_client_state *state, libwebsock_message *msg)
{
  switch (msg->opcode) {
    case WS_OPCODE_TEXT:
      libwebsock_send_text_with_length(state, msg->payload, msg->payload_len);
      break;
    case WS_OPCODE_BINARY:
      libwebsock_send_binary(state, msg->payload, msg->payload_len);
      break;
    default:
      fprintf(stderr, "Unknown opcode: %d\n", msg->opcode);
      break;
  }
  return 0;
}

int
onopen(libwebsock_client_state *state)
{
  fprintf(stderr, "onopen: %d\n", state->sockfd);
  return 0;
}

int
onclose(libwebsock_client_state *state)
{
  fprintf(stderr, "onclose: %d\n", state->sockfd);
  return 0;
}

int
main(int argc, char *argv[])
{
  libwebsock_context *ctx = NULL;
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port to listen on>\n\nNote: You must be root to bind to port below 1024\n", argv[0]);
    exit(0);
  }

  ctx = libwebsock_init();
  if (ctx == NULL ) {
    fprintf(stderr, "Error during libwebsock_init.\n");
    exit(1);
  }
  libwebsock_bind(ctx, "0.0.0.0", argv[1]);
  fprintf(stderr, "libwebsock listening on port %s\n", argv[1]);
  ctx->onmessage = onmessage;
  ctx->onopen = onopen;
  ctx->onclose = onclose;
  libwebsock_wait(ctx);
  //perform any cleanup here.
  fprintf(stderr, "Exiting.\n");
  return 0;
}
