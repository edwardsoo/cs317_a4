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
#include <time.h>
#include <ctype.h>

#include "service.h"
#include "util.h"

extern const char *http_method_str[];
typedef enum {
  SERV_KNOCK, SERV_LOGIN, SERV_LOGOUT, SERV_GETFILE, SERV_PUTFILE, SERV_ADDCART,
  SERV_DELCART, SERV_CHECKOUT, SERV_UNKNOWN
} service;
const char* service_str[] = {
  "/knock", "/login", "/logout", "/getfile", "/putfile",
  "/addcart", "/delcart", "/checkout"
};
const char* status_str[] = {
  "200 OK", "403 Forbidden", "404 Not Found"
};
const char* connection_str[] = {
  "keep-alive", "close"
};
const char* cache_control_str[] = {
  "public", "no-cache"
};
const char* content_type_str[] = {
  "text/plain", "application/octet-stream"
};

void handle_client(int socket) {
  http_cookie *cookie;
  service cmd;
  http_method method;
  http_response resp;
  int bytes, header_size, s;
  char buffer[BUFFER_SIZE], request[BUFFER_SIZE];
  const char *path, *req_body, *cookie_val;

  /* TODO Loop receiving requests and sending appropriate responses,
   *      until one of the conditions to close the connection is
   *      met.
   */

  bytes = recv(socket, buffer, BUFFER_SIZE, 0);
  if (bytes != -1) {
    
    memcpy(request, buffer, BUFFER_SIZE);
    header_size = http_header_complete(buffer, BUFFER_SIZE);
    method = http_parse_method(buffer);
    path = http_parse_uri(buffer);
    path = http_parse_path(path);
    req_body = http_parse_body(buffer, BUFFER_SIZE);
    cookie_val = http_parse_header_field(buffer, bytes, "Cookie");

    printf("header size %i\n", header_size);
    printf("path %s\n", path);
    printf("req body %s\n", req_body);
    cookie = get_cookies(cookie_val, strlen(cookie_val));
    print_cookies(cookie);

    cmd = SERV_UNKNOWN;
    for (s= 0; s < SERV_UNKNOWN; s++) {
      if (strncasecmp(path, service_str[s], strlen(service_str[s])) == 0) {
        cmd = s;
        break;
      }
    }

    switch (method) {
      case METHOD_GET:
        if (cmd == SERV_KNOCK) {
          knock_handler(&resp);
        }
        break;
      case METHOD_POST:
        break;
      default:
        break;
    }
  
    send_response(socket, &resp);  
  }
  else {
    printf("fuck\n");
  }
  return;
}

void knock_handler(http_response* response) {
  response->status = OK;
  response->connection = KEEP_ALIVE;
  response->cache_control = PUBLIC;
  response->content_type = TEXT;
  response->content_length = strlen(KNOCK_RESP);
 
  sprintf(response->body, KNOCK_RESP); 
}

void ssend(int socket, const char* str) {
  send(socket, str, strlen(str), 0);
}

void send_response(int socket, http_response *resp) {
  char str[0x100];
  time_t timep;
  struct tm tm;
  
  ssend(socket, HTTP_VERSION);
  ssend(socket, status_str[resp->status]);
  ssend(socket, "\n");
  ssend(socket, HDR_CONNECTION);
  ssend(socket, connection_str[resp->connection]);
  ssend(socket, "\n");
  ssend(socket, HDR_CACHE_CTRL);
  ssend(socket, cache_control_str[resp->cache_control]);
  ssend(socket, "\n");
  ssend(socket, HDR_CONTENT_LEN);
  sprintf(str, "%u", resp->content_length);
  ssend(socket, str);
  ssend(socket, "\n");
  ssend(socket, HDR_CONTENT_TYPE);
  ssend(socket, content_type_str[resp->content_type]);
  ssend(socket, "\n");
  ssend(socket, HDR_DATE);
  time(&timep);
  gmtime_r(&timep, &tm);
  strftime(str, 0x100, "%a, %d %b %y %T %Z", &tm);
  ssend(socket, str);
  ssend(socket, "\n");
  ssend(socket, "\n");
  ssend(socket, resp->body);
}

http_cookie* get_cookies(const char *value, int length) {
  http_cookie *cookie, *other, *tmp;
  int name_len, value_len;
  char *eq, *sc;

  cookie = NULL;  

  // Skip leading space
  while (isspace(*value) && length > 0) {
    value++;
    length--;
  }
  
  // Find first occurrence of '=' and ';'
  eq = memchr(value, '=', length);

  while (eq) {
    name_len = eq - value;
    sc = memchr(eq + 1, ';', length - name_len - 1);
    value_len = sc - eq - 1;
    if (!sc) break;
    other = (http_cookie*) malloc(sizeof(http_cookie));
    strncpy(other->name, value, name_len);
    other->name[name_len] = 0;
    strncpy(other->value, eq + 1, value_len);
    other->value[value_len] = 0;
    other->next = cookie;
    cookie = other;

    value = sc + 1;
    length -= name_len + value_len + 2;

    // Skip space 
    while (isspace(*value) && length > 0) {
      value++;
      length--;
    }
    eq = memchr(value, '=', length);
  }
  // Reverse the cookie list so it is in the same order as in header value
  other = cookie;
  cookie = NULL;
  while (other) {
    tmp = other->next;
    other->next = cookie;
    cookie = other;
    other= tmp; 
  }
  return cookie; 
}

void print_cookies(http_cookie *cookie) {
  while (cookie) {
    printf("Cookie %s = %s\n", cookie->name, cookie->value);
    cookie = cookie->next;
  }
}
