#include <stdio.h>
#include <string.h>

#include "util.h"

int main(void) {
    
    char req[] = "Post http://www.example.com/test?name=value&name2=value2 HTTP/1.1\r\n"
        "Content-Length: 12345\r\n"
        "Host:   www.example.com  \r\n"
        "Pragma: no-cache\r\n"
        "Accept-Encoding: text/plain\r\n"
        "\r\nTHIS_IS_THE_BODY";
    int len = strlen(req);
    
    printf("Body: %s\n", http_parse_body(req, len));
    printf("Method: %d (%s)\n", http_parse_method(req), http_method_str[http_parse_method(req)]);
    printf("URI: '%s' (path is '%s')\n", http_parse_uri(req), http_parse_path(http_parse_uri(req)));
    printf("Pragma: '%s'\n", http_parse_header_field(req, len, "Pragma"));
    printf("Content-length: '%s'\n", http_parse_header_field(req, len, "Content-length"));
    printf("Accept-Encoding: '%s'\n", http_parse_header_field(req, len, "Accept-Encoding"));
    printf("Host: '%s'\n", http_parse_header_field(req, len, "Host"));
    
    printf("Body: %s\n", http_parse_body(req, len));
    printf("Method: %d (%s)\n", http_parse_method(req), http_method_str[http_parse_method(req)]);
    printf("URI: '%s' (path is '%s')\n", http_parse_uri(req), http_parse_path(http_parse_uri(req)));
    printf("Pragma: '%s'\n", http_parse_header_field(req, len, "Pragma"));
    printf("Content-length: '%s'\n", http_parse_header_field(req, len, "Content-length"));
    printf("Accept-Encoding: '%s'\n", http_parse_header_field(req, len, "Accept-Encoding"));
    printf("Host: '%s'\n", http_parse_header_field(req, len, "Host"));
    
    return 0;
}
