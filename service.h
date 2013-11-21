/*
 * File: service.h
 */

#ifndef _SERVICE_H_
#define _SERVICE_H_

#define BUFFER_SIZE 0x2000
#define STR_SIZE 0x100
#define MAX_FILESIZE 0x40

#define HDR_ALLOW        "Allow: "
#define HDR_COOKIE       "Cookie: "
#define HDR_SET_COOKIE   "Set-Cookie: " 
#define HDR_CONTENT_LEN  "Content-Length: "
#define HDR_CONTENT_TYPE "Content-Type: "
#define HDR_CACHE_CTRL   "Cache-Control: "
#define HDR_CONNECTION   "Connection: "
#define HDR_XFER_ENCODE  "Transfer-Encoding: "
#define HDR_IF_MOD_SINCE "If-Modified-Since: "
#define HDR_LAST_MOD     "Last-Modified: "
#define HDR_DATE         "Date: "

#define OPT_LAST_MODIFIED  0x0001
#define OPT_CONTENT_LENGTH 0x0002

#define HTTP_VERSION "HTTP/1.1 "
#define METHODS_ALLOWED "GET, POST"
#define KNOCK_RESP "Who's there?\n"
#define RFC_822_FMT "%a, %d %b %Y %T %Z"

// List node for cookies and parameters
typedef struct node {
  struct node *next;
  char name[STR_SIZE];
  char value[STR_SIZE];
} node;

typedef struct http_response {
  enum {OK, NOT_MODIFIED, FORBIDDEN, NOT_FOUND, METHOD_NOT_ALLOWED} status;
  enum {KEEP_ALIVE, CLOSE} connection;
  enum {PUBLIC, NO_CACHE} cache_control;
  enum {TEXT, BINARY} content_type;
  int content_length;
  unsigned int opt_flags;
  time_t last_modified;
  char body[BUFFER_SIZE];
  node *cookie, *expire;
} http_response;

// Helper functions
char* get_query_str_from_path(const char* path);
node* get_cookies_from_header(char* value);
node* get_params_from_query(char* query);
char* RFC_822_to_time(char *str, time_t *time);

// Service handlers
void handle_client(int socket);
void knock_handler(http_response* header, node* cookie);
void login_handler(http_response*, node*);
void logout_handler(http_response* resp, node* cookie);
void getfile_handler(http_response* resp, node* param, time_t since);

void send_response(int socket, http_response *response);

// List functions
char* list_lookup(node* list, char* name);
char* list_lookup_nc(node* list, char* name);
node* reverse_list(node* list);
node* append_list(node* list, node* append);
void free_list(node* list);

void print_list(node *cookie);
#endif
