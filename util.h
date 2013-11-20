/*
 * File: util.h
 */

#ifndef _UTIL_H_
#define _UTIL_H_

typedef enum {
    METHOD_GET, METHOD_POST, METHOD_HEAD, METHOD_OPTIONS, METHOD_PUT,
    METHOD_DELETE, METHOD_TRACE, METHOD_CONNECT, METHOD_UNKNOWN
} http_method;

extern const char *http_method_str[];

int http_header_complete(const char *request, int length);
http_method http_parse_method(const char *request);
char *http_parse_uri(char *request);
const char *http_parse_path(const char *uri);
char *http_parse_header_field(char *request, int length, const char *header_field);
const char *http_parse_body(const char *request, int length);
char *encode(const char *original, char *encoded);
char *decode(const char *original, char *decoded);

#endif
