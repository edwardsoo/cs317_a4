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
#include <sys/stat.h>
#include <signal.h>
#define _GNU_SOURCE
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
  "200 OK", "304 Not Modified", "403 Forbidden", "404 Not Found", "405 Method Not Allowed"
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
  node *cookie, *param;
  service cmd;
  http_method method;
  http_response resp;
  int bytes, s;
  char req[BUFFER_SIZE], buf[BUFFER_SIZE];
  const char *path;
  char *cookie_val, *connection, *since;
  time_t since_time;
  struct tm tm;

  /* TODO Loop receiving requests and sending appropriate responses,
   *      until one of the conditions to close the connection is
   *      met.
   */
  resp.expire = resp.cookie = NULL;

  do {
    // New request
    memset(req, 0, BUFFER_SIZE);
    free_list(resp.cookie);
    free_list(resp.expire);
    resp.expire = resp.cookie = NULL;
    memset(resp.body, 0, BUFFER_SIZE);
    bytes = 0;

    // Wait for HTTP header to complete
    while (http_header_complete(req, bytes) == -1) {
      bytes += recv(socket, req + bytes, BUFFER_SIZE, 0);
    }

    // Get a copy for string manipulations
    memcpy(buf, req, bytes);

    // Get HTTP method
    method = http_parse_method(buf);

    // Get path
    path = http_parse_path(http_parse_uri(buf));

    // Parse cookies 
    if (strstr(req, HDR_COOKIE)) {
      cookie_val = http_parse_header_field(buf, bytes, HDR_COOKIE);
      cookie = get_cookies_from_header(cookie_val);
    } else {
      cookie = NULL;
    }

    // Match service command
    cmd = SERV_UNKNOWN;
    for (s= 0; s < SERV_UNKNOWN; s++) {
      if (strncasecmp(path, service_str[s], strlen(service_str[s])) == 0) {
        cmd = s;
        break;
      }
    }

    // Handle command
    switch (method) {
      case METHOD_GET:
        param = get_params_from_query(get_query_str_from_path(path));
        if (cmd == SERV_KNOCK) {
          knock_handler(&resp, cookie);
        } else if (cmd == SERV_LOGIN) {
          login_handler(&resp, param);
        } else if (cmd == SERV_LOGOUT) {
          logout_handler(&resp, cookie);
        } else if (cmd == SERV_GETFILE) {
          since_time = 0;
          if (strstr(req, HDR_IF_MOD_SINCE)) {
            since = http_parse_header_field(buf, bytes, HDR_IF_MOD_SINCE);
            if (!strptime(since, RFC_822_FMT, &tm)) {
              since_time = 0;
            } else {
              since_time = mktime(&tm);
            }
          }
          getfile_handler(&resp, param, since_time);
        } else {
          resp.status = NOT_FOUND;
          resp.connection = CLOSE;
        }
        break;
      case METHOD_POST:
        break;
      default:
        resp.status = METHOD_NOT_ALLOWED;
        resp.connection = CLOSE;        
        break;
    }

    // Check if client wants to close connection after completing request
    if (strstr(req, "Connection:")) {
      connection = http_parse_header_field(buf, bytes, "Connection");
      if (resp.connection == KEEP_ALIVE && strcmp(connection, "close") == 0) {
        resp.connection = CLOSE;
      }
    } 

    send_response(socket, &resp);  
  } while (resp.connection != CLOSE);
}

void knock_handler(http_response* resp, node* cookie) {
  char *username; 
  char body[BUFFER_SIZE];
  int bytes;
 
  resp->status = OK;
  resp->connection = KEEP_ALIVE;
  resp->cache_control = PUBLIC;
  resp->content_type = TEXT;

  bytes = 0;
  username = list_lookup(cookie, "username"); 
  if (username) {
    bytes = sprintf(body, "Username: %s\n", username);
  }
  sprintf(body + bytes, KNOCK_RESP);
  strcpy(resp->body, body);
  resp->content_length = strlen(resp->body);
}

void login_handler(http_response* resp, node* param) {
  char *username;
  node *cookie;

  username = list_lookup_nc(param, "username");
  if (username) {
    resp->status = OK;
    resp->connection = KEEP_ALIVE;
    sprintf(resp->body, "Username: %s\n", username);
    cookie = (node*) malloc(sizeof(node));
    strcpy(cookie->name, "username");
    strcpy(cookie->value, username);
    cookie->next = NULL;
    resp->cookie = append_list(resp->cookie, cookie);
    resp->content_length = strlen(resp->body);
    resp->opt_flags |= OPT_CONTENT_LENGTH;

  } else {
    resp->status = FORBIDDEN;
    resp->connection = CLOSE;
  }
  resp->cache_control = PUBLIC;
  resp->content_type = TEXT;
}

void logout_handler(http_response* resp, node* cookie) {
  char *username;
  node* expire;

  username = list_lookup(cookie, "username");
  if (username) {
    resp->status = OK;
    resp->connection = KEEP_ALIVE;
    sprintf(resp->body, "User %s was logged out.\n", username);
    expire = (node*) malloc(sizeof(node));
    strcpy(expire->name, "username");
    strcpy(expire->value, "0");
    expire->next = NULL;
    resp->expire = append_list(resp->expire, expire);
    resp->content_length = strlen(resp->body);
    resp->opt_flags |= OPT_CONTENT_LENGTH;

  } else {
    resp->status = FORBIDDEN;
    resp->connection = CLOSE;
  }
  resp->cache_control = PUBLIC;
  resp->content_type = TEXT;
}

void getfile_handler(http_response* resp, node* param, time_t since) {
  FILE *fp;
  char *filename;
  size_t read;
  struct stat filestat;

  filename = list_lookup(param, "filename");
  if (filename) {
      where();
    fp = fopen(filename, "r");
    if (fp) {
      stat(filename, &filestat);
      if (filestat.st_mtime <= since) {
        resp->status = NOT_MODIFIED;
        resp->connection = CLOSE;
      } else {
        resp->status = OK;
        resp->connection = KEEP_ALIVE;
        read = fread(resp->body, sizeof(char), MAX_FILESIZE, fp);
        resp->body[read] = 0;
        resp->content_type = BINARY;
        resp->content_length = strlen(resp->body);
        resp->opt_flags |= OPT_CONTENT_LENGTH;
        resp->last_modified = filestat.st_mtime;
        resp->opt_flags |= OPT_CONTENT_LENGTH;
      }
    } else {
      where();
      resp->status = NOT_FOUND;
      resp->connection = CLOSE;
      resp->content_type = TEXT;
    }

  } else {
      where();
      resp->status = FORBIDDEN;
      resp->status = CLOSE;
      resp->content_type = TEXT;
  }
  resp->cache_control = PUBLIC;
}
void ssend(int socket, const char* str) {
  send(socket, str, strlen(str), 0);
}

void send_response(int socket, http_response *resp) {
  char str[0x100], cookie_str[0x100];
  time_t now, day_from_now, epoch;
  struct tm tm;
  node *cookie;
   
  // Get time
  time(&now);
  day_from_now = now + (24*60*60);
  epoch = 0;

  /* Start of header */
  // Write HTTP version and status
  ssend(socket, HTTP_VERSION);
  ssend(socket, status_str[resp->status]);
  ssend(socket, "\n");
  if (resp->status == METHOD_NOT_ALLOWED) {
    ssend(socket, HDR_ALLOW);
    ssend(socket, METHODS_ALLOWED);
    ssend(socket, "\n");
  }
  
  // Write connection
  ssend(socket, HDR_CONNECTION);
  ssend(socket, connection_str[resp->connection]);
  ssend(socket, "\n");

  // Write new cookies
  if (resp->cookie) {
    gmtime_r(&day_from_now, &tm);
    strftime(str, 0x100, RFC_822_FMT, &tm);
    cookie = resp->cookie;
    while (cookie) {
      ssend(socket, HDR_SET_COOKIE);
      sprintf(cookie_str, "%s=%s;path=/;expires=%s;\n", cookie->name, cookie->value, str);
      ssend(socket, cookie_str);
      cookie = cookie->next;
    }
  }
  // Write cookies to be deleted
  if (resp->expire)   {
    gmtime_r(&epoch, &tm);
    strftime(str, 0x100, RFC_822_FMT, &tm);
    cookie = resp->expire;
    while (cookie) {
      ssend(socket, HDR_SET_COOKIE);
      sprintf(cookie_str, "%s=%s;path=/;expires=%s;\n", cookie->name, cookie->value, str);
      ssend(socket, cookie_str);
      cookie = cookie->next;
    }
  }

  // Write cache control
  ssend(socket, HDR_CACHE_CTRL);
  ssend(socket, cache_control_str[resp->cache_control]);
  ssend(socket, "\n");

  // Write content type
  ssend(socket, HDR_CONTENT_TYPE);
  ssend(socket, content_type_str[resp->content_type]);
  ssend(socket, "\n");

  // Write content length
  if (resp->opt_flags & OPT_CONTENT_LENGTH) {
    ssend(socket, HDR_CONTENT_LEN);
    sprintf(str, "%u", resp->content_length);
    ssend(socket, str);
    ssend(socket, "\n");
  }

  // Write last modified time
  if (resp->opt_flags & OPT_LAST_MODIFIED) {
    ssend(socket, HDR_LAST_MOD);
    gmtime_r(&resp->last_modified, &tm);
    strftime(str, 0x100, ".a, %d %b %y %T %Z", &tm);
    ssend(socket, str);
    ssend(socket, "\n");
  }

  // Timestamp
  ssend(socket, HDR_DATE);
  gmtime_r(&now, &tm);
  strftime(str, 0x100, RFC_822_FMT, &tm);
  ssend(socket, str);
  ssend(socket, "\n");
  ssend(socket, "\n");
  /* End of header */
  
  if (strlen(resp->body)) {
      ssend(socket, resp->body);
  }
}

// Find the first entry in a list that matches name, and return its value
char* list_lookup(node* list, char* name) {
  while (list) {
    if (strcmp(name, list->name) == 0) {
      return list->value;
    }
  }
  return NULL;
}

// Similiar to list_lookup, but ignore the case of name when matching
char* list_lookup_nc(node* list, char* name) {
  while (list) {
    if (strcasecmp(name, list->name) == 0) {
      return list->value;
    }
  }
  return NULL;
}

// Free nodes in list
void free_list(node* list) {
  node* next;
  if (!list) return;
  next = list->next;
  free(list);
  free_list(next);
}

// return NULL if no '?' or nothing after '?'
char* get_query_str_from_path(const char* path) {
  char* qm = memchr(path, '?', strlen(path));
  if (qm && (strlen(path) - (qm - path)) > 1) {
    return qm + 1;
  }
  return NULL;
}

node* get_list_from_token_str(char *str, char* delimiter) {
  char *name, *eq, *value;
  node *this, *prev;
  
  if (!str) return NULL;

  this = prev = NULL;
  name = strtok(str, delimiter);
  while (name) {
    eq = memchr(name, '=', strlen(name));
    if (!eq) break;
    value = eq + 1;
    *eq = 0;
    this = (node*) malloc(sizeof(node));
    strcpy(this->name, name);
    strcpy(this->value, value);
    this->next = prev;
    prev = this;
    name = strtok(NULL, delimiter);
  }
  return reverse_list(this);
}

// return a list of name-value parameter paris
node* get_params_from_query(char* query) {
  return get_list_from_token_str(query, "&");
}

node* get_cookies_from_header(char* value) {
  return get_list_from_token_str(value, "; ");
}

// Reverse a list and return new head
node* reverse_list(node* list) {
  node *reversed, *tmp;

  reversed = NULL;
  while (list) {
    tmp = list->next;
    list->next = reversed;
    reversed = list;
    list = tmp; 
  }
  return reversed;
}

node* append_list(node* list, node* append) {
  if (!list) return append;
  list->next = append_list(list->next, append);
  return list;
}

char* RFC_822_to_time(char *str, struct tm *tm) {
  // Thu, 21 Nov 13 09:50:55 GMT
  int length;
  char *ptr;

  if (strlen(str) < 27)
}

void print_list(node *node) {
  while (node) {
    printf("%s = %s\n", node->name, node->value);
    node = node->next;
  }
}
