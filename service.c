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
  "200 OK", "403 Forbidden", "404 Not Found", "405 Method Not Allowed"
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
  const char *path, *cookie_val;

  /* TODO Loop receiving requests and sending appropriate responses,
   *      until one of the conditions to close the connection is
   *      met.
   */

  bytes = recv(socket, req, BUFFER_SIZE, 0);
  if (bytes != -1) {

    // Get a copy for string manipulations
    memcpy(buf, req, bytes);

    // Get HTTP method
    method = http_parse_method(buf);

    // Get path
    path = http_parse_path(http_parse_uri(buf));
    printf("path %s\n", path);

    // Parse cookies 
    if (strstr(req, "Cookie:")) {
      cookie_val = http_parse_header_field(buf, bytes, "Cookie");
      cookie = get_cookies_from_str(cookie_val, strlen(cookie_val));
      print_list(cookie);
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
        print_list(param);
        if (cmd == SERV_KNOCK) {
          knock_handler(&resp, cookie);
        } else if (cmd == SERV_LOGIN) {
          login_handler(&resp, param);
        }
        break;
      case METHOD_POST:
        break;
      default:
        resp.status = METHOD_NOT_ALLOWED;
        resp.connection = CLOSE;        
        break;
    }
 
    send_response(socket, &resp);  
  }
  else {
    printf("fuck\n");
  }
  return;
}

void knock_handler(http_response* response, node* cookie) {
  char *username; 
  char body[BUFFER_SIZE];
  int bytes;
 
  response->status = OK;
  response->connection = KEEP_ALIVE;
  response->cache_control = PUBLIC;
  response->content_type = TEXT;

  bytes = 0;
  username = list_lookup(cookie, "username"); 
  if (username) {
    bytes = sprintf(body, "Username: %s\n", username);
  }
  sprintf(body + bytes, KNOCK_RESP);
  strcpy(response->body, body);
  response->content_length = strlen(response->body);
}

void login_handler(http_response* response, node* param) {
  char *username;

  username = list_lookup_nc(param, "username");
  if (username) {
    response->status = OK;
    response->connection = KEEP_ALIVE;
    sprintf(response->body, "Username: %s\n", username);
    response->content_length = strlen(response->body);
  } else {
    response->status = FORBIDDEN;
    response->connection = CLOSE;
    response->content_length = 0;
  }
  response->cache_control = PUBLIC;
  response->content_type = TEXT;
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
  if (resp->status == METHOD_NOT_ALLOWED) {
    ssend(socket, HDR_ALLOW);
    ssend(socket, METHODS_ALLOWED);
    ssend(socket, "\n");
  }
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
  // End of header
  
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
// return a pointer to everything in path after the first '?'

// return NULL if no '?' or nothing after '?'
char* get_query_str_from_path(const char* path) {
  char* qm = memchr(path, '?', strlen(path));
  if (qm && (strlen(path) - (qm - path)) > 1) {
    return qm + 1;
  }
  return NULL;
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

// return a list of name-value parameter paris
node* get_params_from_query(char* query) {
  char *name, *eq, *value;
  node *param, *prev;
  
  if (!query) return NULL;

  param = prev = NULL;
  name = strtok(query, "&");
  while (name) {
    eq = memchr(name, '=', strlen(name));
    if (!eq) break;
    value = eq + 1;
    *eq = 0;
    param = (node*) malloc(sizeof(node));
    strcpy(param->name, name);
    strcpy(param->value, value);
    param->next = prev;
    prev = param;
    name = strtok(NULL, "&");
  }
  return reverse_list(param);
}

node* get_cookies_from_str(const char *value, int length) {
  node *cookie, *prev;
  int name_len, value_len;
  char *eq, *sc;

  cookie = prev = NULL;  

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
    cookie = (node*) malloc(sizeof(node));
    strncpy(cookie->name, value, name_len);
    cookie->name[name_len] = 0;
    strncpy(cookie->value, eq + 1, value_len);
    cookie->value[value_len] = 0;
    cookie->next = prev;
    prev = cookie;

    value = sc + 1;
    length -= name_len + value_len + 2;

    // Skip space 
    while (isspace(*value) && length > 0) {
      value++;
      length--;
    }
    eq = memchr(value, '=', length);
  }
  return reverse_list(cookie);
}

void print_list(node *node) {
  while (node) {
    printf("%s = %s\n", node->name, node->value);
    node = node->next;
  }
}
