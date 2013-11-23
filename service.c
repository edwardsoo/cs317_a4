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
  int bytes, s, expected_len, header_len;
  char req[BUFFER_SIZE], buf[BUFFER_SIZE];
  const char *path;
  char *connection, *req_body_len;
  time_t since_time;

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
    resp.connection = KEEP_ALIVE;
    resp.opt_flags = 0;
    memset(resp.body, 0, BUFFER_SIZE);
    if (cookie) free_list(cookie);
    if (param) free_list(param);
    bytes = 0;

    // Wait for HTTP header to complete
    do {
      bytes += recv(socket, req + bytes, BUFFER_SIZE, 0);
      header_len = http_header_complete(req, bytes);
    } while (header_len == -1);
    
    // Receive body if there is content length
    if (strstr(req, HDR_CONTENT_LEN)) {
      strcpy(buf, req);
      req_body_len = get_header_value_from_req(buf, HDR_CONTENT_LEN);
      expected_len = atoi(req_body_len) + header_len;
      while (bytes < expected_len) {
         bytes += recv(socket, req + bytes, BUFFER_SIZE, 0);
      }
    }
    // printf("recv %i bytes\n", bytes);

    // Get HTTP method
    method = http_parse_method(req);

    // Get path
    strcpy(buf, req);
    path = http_parse_path(http_parse_uri(buf));
    printf("Request: %s\n", path);

    // Parse cookies 
    if (strstr(req, HDR_COOKIE)) {
      strcpy(buf, req);
      cookie = get_cookies_from_header(get_header_value_from_req(buf, HDR_COOKIE));
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
    switch(cmd) {
      case SERV_KNOCK:
      case SERV_LOGIN:
      case SERV_LOGOUT:
      case SERV_GETFILE:
      case SERV_ADDCART:
      case SERV_DELCART:
      case SERV_CHECKOUT:
        if (method == METHOD_GET) {
          param = get_params_from_query(get_query_str_from_path(path));
          if (cmd == SERV_KNOCK) {
            knock_handler(&resp, cookie);
          } else if (cmd == SERV_LOGIN) {
            login_handler(&resp, param);
          } else if (cmd == SERV_LOGOUT) {
            logout_handler(&resp, cookie);
          } else if (cmd == SERV_GETFILE) {
            since_time = 0;
            strcpy(buf, req);
            if (strstr(buf, HDR_IF_MOD_SINCE)) {
              if (!RFC_822_to_time(strstr(buf, HDR_IF_MOD_SINCE) + strlen(HDR_IF_MOD_SINCE), 
                    &since_time)) {
                since_time = 0;
              }
            }
            getfile_handler(&resp, param, since_time);
            where();
          } else if (cmd == SERV_ADDCART) {
            addcart_handler(&resp, param, cookie);
            printf("new cookie %s=%s.\n", resp.cookie->name, resp.cookie->value);
          } else {
            resp.status = NOT_FOUND;
          }
        } else {
          resp.allow = METHOD_GET;
          resp.status = METHOD_NOT_ALLOWED;
        }
        break;
      case SERV_PUTFILE:
        if (method == METHOD_POST) {
          strcpy(buf, req);
          param = get_params_from_query((char*) http_parse_body(buf, bytes));
          putfile_handler(&resp, cookie, param);
        } else {
          resp.allow = METHOD_POST;
          resp.status = METHOD_NOT_ALLOWED;
        }
        break;
      default:
        resp.status = NOT_FOUND;
        break;
    }

    // Check if status not ok or 
    // client wants to close connection after completing request
    if (resp.status != OK) {
      resp.connection = CLOSE;
    } else if (strstr(req, "Connection:")) {
      connection = http_parse_header_field(buf, bytes, "Connection");
      if (strcmp(connection, "close") == 0) {
        resp.connection = CLOSE;
      }
    }

    printf("new cookie %s=%s.\n", resp.cookie->name, resp.cookie->value);
    send_response(socket, &resp);  
  } while (resp.connection != CLOSE);
}

void knock_handler(http_response* resp, node* cookie) {
  char *username; 
  int bytes;
 
  resp->status = OK;
  resp->cache_control = PUBLIC;
  resp->content_type = TEXT;

  bytes = 0;
  username = list_lookup(cookie, "username"); 
  if (username) {
    bytes = sprintf(resp->body, "Username: %s\n", username);
  }
  sprintf(resp->body + bytes, KNOCK_RESP);
  resp->opt_flags |= OPT_CONTENT_LENGTH;
}

void login_handler(http_response* resp, node* param) {
  char *username;
  node *cookie;

  username = list_lookup(param, "username");
  if (username) {
    resp->status = OK;
    sprintf(resp->body, "Username: %s\n", username);
    cookie = (node*) malloc(sizeof(node));
    strcpy(cookie->name, "username");
    strcpy(cookie->value, username);
    cookie->next = NULL;
    resp->cookie = append_list(resp->cookie, cookie);
    resp->opt_flags |= OPT_CONTENT_LENGTH | OPT_COOKIE_EXPIRE;

  } else {
    resp->status = FORBIDDEN;
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
    sprintf(resp->body, "User %s was logged out.\n", username);
    expire = (node*) malloc(sizeof(node));
    strcpy(expire->name, "username");
    strcpy(expire->value, "0");
    expire->next = NULL;
    resp->expire = append_list(resp->expire, expire);
    resp->opt_flags |= OPT_CONTENT_LENGTH;

  } else {
    resp->status = FORBIDDEN;
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
    // printf("getfile: %s\n", filename);
    fp = fopen(filename, "r");
    if (fp) {
      stat(filename, &filestat);
      if (filestat.st_mtime <= since) {
        resp->status = NOT_MODIFIED;
      } else {
        read = fread(resp->body, sizeof(char), MAX_FILESIZE, fp);
        resp->body[read] = 0;
        resp->status = OK;
        resp->content_type = BINARY;
        resp->opt_flags |= OPT_CONTENT_LENGTH | OPT_LAST_MODIFIED;
        resp->last_modified = filestat.st_mtime;

      }
    } else {
      resp->status = NOT_FOUND;
      resp->content_type = TEXT;
    }

  } else {
      resp->status = FORBIDDEN;
      resp->content_type = TEXT;
  }
  resp->cache_control = PUBLIC;
}

void putfile_handler(http_response *resp, node *cookie, node* param) {
  FILE *fp;
  char *username, *filename, *content, decoded[MAX_FILESIZE+1];
  int bytes;
  size_t written;

  filename = list_lookup(param, "filename");
  content = list_lookup(param, "content");
  if (filename && content) {
    fp = fopen(filename, "w+");
    if (fp) {
      decode(content, decoded);
      written = fwrite(decoded, sizeof(char), strlen(decoded), fp);
      if (written == strlen(decoded)) {
        fclose(fp);
        bytes = 0;
        username = list_lookup(cookie, "username"); 
        if (username) {
          bytes = sprintf(resp->body, "Username: %s\n", username);
        }
        sprintf(resp->body + bytes, "%s has been saved successfully.", filename);
        resp->status = OK;
        resp->opt_flags |= OPT_CONTENT_LENGTH;
      } else {
        resp->status = FORBIDDEN;
      }
    } else {
      resp->status = FORBIDDEN;
    }
  } else {
    resp->status = FORBIDDEN;
  }
  resp->content_type = TEXT;
}

int max_item_nr(node* node) {
  int max_n, n;
  max_n = 0;
  while (node) {
    if (strncmp(node->name, "item", 4) == 0) {
      n = atoi(node->name + 4);
      if (n > max_n) {
        max_n = n;
      }
    }
    node = node->next;
  }
  return max_n;
}

void addcart_handler(http_response* resp, node* param, node* cookie) {
  char *item_name, *username;
  int max_n, n, bytes;
  node* node;
  char str[STR_SIZE];

  item_name = list_lookup(param, "item");
  if (item_name) {
    decode(item_name, str);
    where();
    max_n = max_item_nr(cookie);
    node = malloc(sizeof(node));
    sprintf(node->name, "item%i", max_n + 1);
    printf("strlen %i, %s.\n", (int) strlen(str), str);
    strcpy(node->value, str);
    node->next = NULL;
    resp->cookie = append_list(resp->cookie, node);

    bytes = 0;
    username = list_lookup(cookie, "username"); 
    if (username) {
      bytes = sprintf(resp->body, "Username: %s\n", username);
    }
    for (n = 1; n <= max_n; n++) {
      sprintf(str, "item%i", n);
      item_name = list_lookup(cookie, str);
      decode(item_name, str);
      bytes += sprintf(resp->body + bytes, "%i. %s\n", n, str);
    }
    sprintf(resp->body + bytes, "%i. %s", max_n + 1, node->value);
    resp->status = OK;
    resp->opt_flags |= OPT_CONTENT_LENGTH | OPT_COOKIE_EXPIRE;
    where();
    
  } else {
    resp->status = FORBIDDEN;
  }
  resp->content_type = TEXT;
  resp->cache_control = NO_CACHE;
}

void delcart_handler(http_response* resp, node* param, node* cookie) {
  char *itemnr, *item_name, *username;
  int bytes, max_n, n, del_n;
  node *node;
  char str[STR_SIZE];
  
  itemnr = list_lookup(param, "itemnr");
  if (itemnr) {
    node = cookie;
    sprintf(str, "item%s", itemnr);
    while (node) {
      if (strcmp(node->name, str) == 0) {
        break;
      }
      node = node->next;
    }
    if (node) {
      del_n = atoi(node->name + 4);
      max_n = max_item_nr(cookie);
      node = malloc(sizeof(node));
      sprintf(node->name, "item%i", max_n);
      strcpy(node->value, "0");
      node->next = NULL;
      resp->expire = append_list(resp->expire, node);
      for (n = del_n; n < max_n; n++) {
        sprintf(str, "item%i", n+1);
        item_name = list_lookup(cookie, str);
        node = malloc(sizeof(node));
        sprintf(node->name, "item%i", n);
        strcpy(node->value, item_name);
        node->next = NULL;
        resp->cookie = append_list(resp->cookie, node);
      }
      bytes = 0;
      username = list_lookup(cookie, "username"); 
      if (username) {
        bytes = sprintf(resp->body, "Username: %s\n", username);
      }
      for (n = 1; n < del_n; n++) {
        sprintf(str, "item%i", n);
        item_name = list_lookup(cookie, str);
        bytes += sprintf(resp->body + bytes, "%i. %s\n", n, item_name);
      }
      for (n = del_n; n < max_n; n++)   {
        sprintf(str, "item%i", n);
        item_name = list_lookup(resp->cookie, str);
        bytes += sprintf(resp->body + bytes, "%i. %s\n", n, item_name);
      }
      resp->body[bytes - 1] = 0;
      resp->status = OK;
      resp->opt_flags |= OPT_CONTENT_LENGTH;
      
    } else {
      resp->status = FORBIDDEN;
    }
  } else {
    resp->status = FORBIDDEN;
  }
  resp->content_type = TEXT;
}

void ssend(int socket, const char* str) {
  send(socket, str, strlen(str), 0);
}

void send_response(int socket, http_response *resp) {
  char str[STR_SIZE], cookie_str[STR_SIZE];
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

  // Write allowed methods
  if (resp->status == METHOD_NOT_ALLOWED) {
    ssend(socket, HDR_ALLOW);
    ssend(socket, http_method_str[resp->allow]);
    ssend(socket, "\n");
  }
  
  // Write connection
  ssend(socket, HDR_CONNECTION);
  ssend(socket, connection_str[resp->connection]);
  ssend(socket, "\n");

  // Write new cookies
  if (resp->cookie && resp->opt_flags & OPT_COOKIE_EXPIRE) {
    where(); 
    printf("new cookie %s=%s.\n", resp->cookie->name, resp->cookie->value);
    strftime(str, 0x100, RFC_822_FMT, gmtime(&day_from_now));
    printf("new cookie %s=%s.\n", resp->cookie->name, resp->cookie->value);
    cookie = resp->cookie;
    while (cookie) {
      ssend(socket, HDR_SET_COOKIE);
      printf("setting cookie %s=%s.\n", cookie->name, cookie->value);
      sprintf(cookie_str, "%s=%s;path=/;expires=%s;\n", cookie->name,
          cookie->value, str);
      ssend(socket, cookie_str);
      cookie = cookie->next;
    }
  } else if (resp->cookie) {
    cookie = resp->cookie;
    while (cookie) {
      ssend(socket, HDR_SET_COOKIE);
      sprintf(cookie_str, "%s=%s;path=/;\n", cookie->name, cookie->value);
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
      sprintf(cookie_str, "%s=%s;path=/;expires=%s;\n",
          cookie->name, cookie->value, str);
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
    sprintf(str, "%u", (unsigned int) strlen(resp->body));
    ssend(socket, str);
    ssend(socket, "\n");
  }

  // Write last modified time
  if (resp->opt_flags & OPT_LAST_MODIFIED) {
    ssend(socket, HDR_LAST_MOD);
    gmtime_r(&resp->last_modified, &tm);
    strftime(str, 0x100, RFC_822_FMT, &tm);
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
    list = list->next;
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
  char *qm, *nl;

  qm = memchr(path, '?', strlen(path));
  if (qm && (strlen(path) - (qm - path)) > 1) {
    nl = memchr(qm, ' ', strlen(qm));
    if (nl) *nl = 0;
    nl = memchr(qm, '\r', strlen(qm));
    if (nl) *nl = 0;
    nl = memchr(qm, '\n', strlen(qm));
    if (nl) *nl = 0;
    return qm + 1;
  }
  return NULL;
}

// Return string pointing to the value of a header, NULL terminate the original buffer
char* get_header_value_from_req(const char* req, const char* header_name) {
  char *value_str, *nl;
  value_str = strstr(req, header_name) + strlen(header_name);
  nl = memchr(value_str, '\r', strlen(value_str));
  if (nl) *nl = 0;
  nl = memchr(value_str, '\n', strlen(value_str));
  if (nl) *nl = 0;
  return value_str;
}

char* trim_space(char* str) {
  char *end;
  while(isspace(*str)) str++;
  end = str + strlen(str) - 1;
  while(end>str && isspace(*end)) end--;
  *(end+1) = 0;
  return str;
}

node* get_list_from_token_str(char *str, char* delimiter) {
  char *name, *eq, *value;
  node *this, *prev;
  
  if (!str) return NULL;

  this = prev = NULL;
  name = strtok(str, delimiter);

  while (name) {
    name = trim_space(name);
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
  return get_list_from_token_str(value, ";");
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

#define DATE_PART_DELIMITER " :,"
// Parse a RFC822 Date string into time_t
char* RFC_822_to_time(char *str, time_t *time) {
  char *ptr;
  struct tm tm;

  if (strlen(str) < 27) return NULL;

  // Weekday
  ptr = strtok(str, DATE_PART_DELIMITER);
  if (!strcmp(ptr, "Sun")) {
    tm.tm_wday = 0;
  } else if (!strcmp(ptr, "Mon")) {
    tm.tm_wday = 1;
  } else if (!strcmp(ptr, "Tue")) {
    tm.tm_wday = 2;
  } else if (!strcmp(ptr, "Wed")) {
    tm.tm_wday = 3;
  } else if (!strcmp(ptr, "Thu")) {
    tm.tm_wday = 4;
  } else if (!strcmp(ptr, "Fri")) {
    tm.tm_wday = 5;
  } else if (!strcmp(ptr, "Sat")) {
    tm.tm_wday = 6;
  }

  // Day 
  ptr = strtok(NULL, DATE_PART_DELIMITER);
  tm.tm_mday = atoi(ptr);

  // Month
  ptr = strtok(NULL, DATE_PART_DELIMITER);
  if (!strcmp(ptr, "Jan")) {
    tm.tm_mon = 0;
  } else if (!strcmp(ptr, "Feb")) {
    tm.tm_mon = 1;
  } else if (!strcmp(ptr, "Mar")) {
    tm.tm_mon = 2;
  } else if (!strcmp(ptr, "Apr")) {
    tm.tm_mon = 3;
  } else if (!strcmp(ptr, "May")) {
    tm.tm_mon = 4;
  } else if (!strcmp(ptr, "Jun")) {
    tm.tm_mon = 5;
  } else if (!strcmp(ptr, "Jul")) {
    tm.tm_mon = 6;
  } else if (!strcmp(ptr, "Aug")) {
    tm.tm_mon = 7;
  } else if (!strcmp(ptr, "Sep")) {
    tm.tm_mon = 8;
  } else if (!strcmp(ptr, "Oct")) {
    tm.tm_mon = 9;
  } else if (!strcmp(ptr, "Nov")) {
    tm.tm_mon = 10;
  } else if (!strcmp(ptr, "Dec")) {
    tm.tm_mon = 11;
  }

  // Year
  ptr = strtok(NULL, DATE_PART_DELIMITER);
  tm.tm_year = atoi(ptr) - 1900;

  // Hour
  ptr = strtok(NULL, DATE_PART_DELIMITER);
  tm.tm_hour = atoi(ptr);

  // Minute
  ptr = strtok(NULL, DATE_PART_DELIMITER);
  tm.tm_min = atoi(ptr);

  // Second
  ptr = strtok(NULL, DATE_PART_DELIMITER);
  tm.tm_sec = atoi(ptr);

  // Use tm with timezone GMT
  setenv("TZ", "GMT", 1);
  tzset();
  *time = mktime(&tm);  
  return strtok(NULL, DATE_PART_DELIMITER);
}

void print_list(node *node) {
  while (node) {
    printf("%s = %s\n", node->name, node->value);
    node = node->next;
  }
}
