#include <stdio.h>
#include <stdlib.h>
#include <websock/websock.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

struct upload_state {
  unsigned int started;
  unsigned int received;
  unsigned int size;
  FILE *fp;
};

char *
get_new_path(void)
{
  char *path;
  struct stat st;
  int i = 1;
  path = (char *)malloc(256);
  do {
    snprintf(path, 255, "%s%d", "uploads/upload", i++);
  } while (stat(path, &st) == 0);
  return path;
}


int 
onmessage(libwebsock_client_state *state, libwebsock_message *msg)
{
  struct upload_state *upstate;
  char *path;
  char sendbuf[256];
  if (state->data == NULL) {
    state->data = (struct upload_state *)malloc(sizeof(struct upload_state));
    memset(state->data, 0, sizeof(struct upload_state));
  }
  upstate = (struct upload_state *) state->data;
  if (upstate->started == 0) {
    if (*(unsigned int *)msg->payload != 0x42726965) {
      fprintf(stderr, "Magic number fail.\n");
      libwebsock_close_with_reason(state, 1000, "Bad magic number");
      free(state->data);
      return 0;
    }
    upstate->size = be32toh(*(unsigned int *)((char *)(msg->payload + 4)));
    fprintf(stderr, "Got size: %u\n", upstate->size);
    path = get_new_path();
    fprintf(stderr, "Got new path: %s\n", path);
    upstate->fp = fopen(path, "w");
    free(path);
    if (upstate->fp == NULL) {
      fprintf(stderr, "Unable to open file.\n");
      libwebsock_close_with_reason(state, 1000, "Can't open file for writing");
      free(state->data);
      return 0;
    }
    upstate->started = 1;
    return 0;
  }

  fwrite(msg->payload, msg->payload_len, 1, upstate->fp);
  upstate->received += msg->payload_len;
  snprintf(sendbuf, 255, "%.2f%% uploaded", (float) (((float)upstate->received / (float)upstate->size) * 100));
  fprintf(stderr, "Received so far: %d\n", upstate->received);
  libwebsock_send_text(state, sendbuf);
  if (upstate->received == upstate->size) {
    fprintf(stderr, "Received all bytes.  Closing file.\n");
    fclose(upstate->fp);
    free(state->data);
    libwebsock_close_with_reason(state, 1000, "Success");
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
  struct passwd *pwd;
  libwebsock_context *ctx = NULL;
  ctx = libwebsock_init_flags(WS_NONBLOCK);
  if(ctx == NULL) {
    fprintf(stderr, "Error during libwebsock_init.\n");
    exit(1);
  }
  libwebsock_bind_ssl_real(ctx, "0.0.0.0", "443", "ubiety.key", "ubiety.net.crt", "sf_bundle.crt");
  pwd = getpwnam("ubuntu");
  if (pwd == NULL) {
    fprintf(stderr, "Unable to find ubuntu user.  Can't drop privileges.  Dying.\n");
    exit(1);
  }
  if (setgid(pwd->pw_gid) != 0) {
    fprintf(stderr, "Unable to setgid, exiting.\n");
    exit(2);
  }
  if (setuid(pwd->pw_uid) != 0) {
    fprintf(stderr, "Unable to setuid, exiting.\n");
    exit(2);
  }
  ctx->onmessage = onmessage;
  ctx->onopen = onopen;
  ctx->onclose = onclose;
  while (1) {
    usleep(50000);
    libwebsock_wait(ctx);
  }
  //perform any cleanup here.
  fprintf(stderr, "Exiting.\n");
  return 0;
}
