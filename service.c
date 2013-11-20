/*
 * File: service.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "service.h"
#include "util.h"

extern const char *http_method_str[];

void handle_client(int socket) {
  int bytes, header_size;
  http_method method;
  char buffer[RECV_BUFFER_SIZE+1];
  const char *uri, *body;

  /* TODO Loop receiving requests and sending appropriate responses,
   *      until one of the conditions to close the connection is
   *      met.
   */
  printf("%s %u\n", __func__, __LINE__);
  bytes = recv(socket, buffer, RECV_BUFFER_SIZE, 0);
  printf("%s %u\n", __func__, __LINE__);
  buffer[RECV_BUFFER_SIZE] = 0;
  printf("%s %u\n", __func__, __LINE__);
  if (bytes != -1) {
    printf("read %i bytes\n", bytes);
    
    header_size = http_header_complete(buffer, RECV_BUFFER_SIZE);
    method = http_parse_method(buffer);
    uri = http_parse_uri(buffer);
    body = http_parse_body(buffer, RECV_BUFFER_SIZE);
    
    printf("header size %i\n", header_size);
    printf("uri %s\n", uri);
    printf("path %s\n", http_parse_path(uri));
    printf("body: %s\n", body);

    switch (method) {
      case METHOD_GET:
        break;
      case METHOD_POST:
        break;
      default:
        break;
    }
    printf("%s\n", buffer);
  }
  else {
    printf("fuck\n");
  }
  return;
}
