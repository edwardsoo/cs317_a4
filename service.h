/*
 * File: service.h
 */

#ifndef _SERVICE_H_
#define _SERVICE_H_

#define BUFFER_SIZE 0x2000
#define COOKIE_SIZE 0x100

#define HDR_SET_COOKIE "Set-Cookie: " 
#define HDR_CONTENT_LEN "Content-Length: "
#define HDR_CONTENT_TYPE "Content-Type: "
#define HDR_CACHE_CTRL "Cache-Control: "
#define HDR_CONNECTION "Connection: "
#define HDR_XFER_ENCODE "Transfer-Encoding: "
#define HDR_IF_MOD_SINCE "If-Modified-Since: "
#define HDR_LAST_MOD "Last-Modified: "
#define HDR_DATE "Date: "

#define HTTP_VERSION "HTTP/1.1 "

#define KNOCK_RESP "Who's there?\n"

typedef struct http_cookie {
  struct http_cookie *next;
  char name[COOKIE_SIZE], value[COOKIE_SIZE];
} http_cookie;

typedef struct http_response {
  enum {OK, NOT_FOUND, FORBIDDEN} status;
  enum {KEEP_ALIVE, CLOSE} connection;
  enum {PUBLIC, NO_CACHE} cache_control;
  enum {TEXT, BINARY} content_type;
  int content_length;
  char body[BUFFER_SIZE];
} http_response;

void handle_client(int socket);
void knock_handler(http_response* header, http_cookie* cookie);
void send_response(int socket, http_response *response);
http_cookie* get_cookies_from_str(const char *value, int length);
char* get_cookie_value(http_cookie* cookie, char* name);


void print_cookies(http_cookie *cookie);
#endif
