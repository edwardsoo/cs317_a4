/*
 * File: util.c
 */

#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "util.h"

const char *http_method_str[] = {"GET", "POST", "HEAD", "OPTIONS", "PUT",
    "DELETE", "TRACE", "CONNECT"};

/*
 * If the HTTP header found in the first 'length' bytes of 'request'
 * is a complete HTTP header (i.e. contains an empty line indicating
 * end of header), returns the size of this header (in
 * bytes). Otherwise, returns -1. This function supports both requests
 * with LF only and with CR-LF. This function is only expected to be
 * called during the request retrieval process, and should not be used
 * after a parse function has been called, since parse functions
 * change the request in a way that changes the behaviour of this
 * function.
 */
int http_header_complete(const char *request, int length) {
    
    const char *body = http_parse_body(request, length);
    if (body && !memchr(request, '\0', body - request))
        return body - request;
    else
        return -1;
}

/*
 * Returns the method of the HTTP request. If the method is not one of
 * the RFC supported methods, returns METHOD_UNKNOWN.
 */
http_method http_parse_method(const char *request) {
    
    http_method m;
    
    // Ignore spaces in the beginning of the request
    while (isspace(*request)) request++;
    
    for(m = 0; m < METHOD_UNKNOWN; m++)
        if (!strncasecmp(request, http_method_str[m], strlen(http_method_str[m])) &&
            isspace(request[strlen(http_method_str[m])]))
            return m;
    return METHOD_UNKNOWN;
}

/*
 * Returns a pointer to the URI of the HTTP request. The original
 * request is changed with a new NULL byte, so you should not use the
 * request as a regular string after this call.
 */
char *http_parse_uri(char *request) {
    
    char *start, *end;
    
    // Ignore spaces in the beginning of the request
    while (isspace(*request)) request++;
    
    // Skip the method and spaces after that
    for (start = request; !isspace(*start); start++);
    for (               ;  isspace(*start); start++);
    
    // Find the next space
    for (end = start; *end && !isspace(*end); end++);
    
    // Change it to NULL so that URI is a standalone string.
    *end = '\0';
    
    return start;
}

/*
 * Returns a pointer to the path component of a URI.
 */
const char *http_parse_path(const char *uri) {
    
    if (*uri == '/') return uri;
    
    char *s = strchr(uri, ':');
    if (!s || strncmp(s, "://", 3)) return uri;
    
    for(s += 3; *s && *s != '/'; s++);
    return s;
}

/*
 * Returns a pointer to the value of a specific header field in the
 * HTTP request. The original request is changed with a new NULL byte,
 * so you should not use the request as a regular string after this
 * call.
 */
char *http_parse_header_field(char *request, int length, const char *header_field) {
    
    char *oldlf, *newlf, *newnull, *start;
    int len = strlen(header_field);
    
    // Ignore spaces in the beginning of the request
    while (isspace(*request) && length > 0) request++, length--;
    
    for (oldlf = memchr(request, '\n', length); oldlf; oldlf = newlf) {
        
        newlf = memchr(oldlf + 1, '\n', request + length - 1 - oldlf);
        
        // If there is a null byte, it might be there from a previous call
        newnull = memchr(oldlf + 1, '\0', request + length - 1 - oldlf);
        if (newnull && newnull < newlf) newlf = newnull;
        
        // If the request header ended, field was not found.
        if (newlf == oldlf + 1) return NULL;
        if (newlf == oldlf + 2 && oldlf[1] == '\r') return NULL;
        
        for(start = oldlf + 1; isspace(*start); start++);
        if (!strncasecmp(start, header_field, len) && start[len] == ':') {
            // Remove initial spaces
            for(start += len + 1; isspace(*start); start++);
            // Remove trailing spaces
            for(; isspace(*newlf); newlf--) *newlf = '\0';
            // Return what is left.
            return start;
        } else if (!*newlf) {
            // If header line ends with nulls already, moves on to the
            // last (corresponding to the old '\n').
            for(; !newlf[1]; newlf++);
        }
    }
    
    return NULL;
}

/*
 * Returns the position of the first byte of the body. If there is no
 * body, returns the position of the end of the header. Returns NULL
 * if the body is not within the informed length. This function
 * supports both requests with LF only and with CR-LF, and can be
 * called after calls to other parse functions.
 */
const char *http_parse_body(const char *request, int length) {
    
    const char *oldlf, *newlf, *newnull;
    
    // Ignore spaces in the beginning of the request
    while (isspace(*request) && length > 0) request++, length--;
    
    for (oldlf = memchr(request, '\n', length);
         oldlf && (newlf = memchr(oldlf + 1, '\n', request + length - 1 - oldlf));
         oldlf = newlf) {
        
        // If there is a null byte, it might be there from a previous call to header_field
        newnull = memchr(oldlf + 1, '\0', request + length - 1 - oldlf);
        if (newnull && newnull < newlf) newlf = newnull;
        
        if (newlf == oldlf + 1) return newlf + 1;
        if (newlf == oldlf + 2 && oldlf[1] == '\r') return newlf + 1;
        
        if (!*newlf) {
            // If header line ends with nulls already, moves on to the
            // last (corresponding to the old '\n').
            for(; !newlf[1]; newlf++);
        }
    }
    
    return NULL;
}

/*
 * Encodes the string 'original' into 'encoded'. It is recommended
 * that 'encoded' has space for at least 3*strlen(original)+1. For
 * convenience, returns 'encoded'.
 */
char *encode(const char *original, char *encoded) {
    
    char *e = encoded;
    for(;*original; original++, encoded++) {
        if (isalnum(*original))
            *encoded = *original;
        else if (*original == ' ')
            *encoded = '+';
        else {
            sprintf(encoded, "%%%02X", *original);
            encoded += 2;
        }
    }
    *encoded = '\0';
    return e;
}

/*
 * Decodes the string 'original' into 'decoded'. It is recommended
 * that 'decoded' has space for at least strlen(original)+1. For
 * convenience, returns 'decoded'.
 */
char *decode(const char *original, char *decoded) {
    
    char *d = decoded;
    for(;*original; original++, decoded++) {
        if (*original == '+')
            *decoded = ' ';
        else if (*original == '%') {
            unsigned int nr;
            if (!sscanf(original, "%%%02X", &nr)) break;
            *decoded = nr;
            original += 2;
        } else
            *decoded = *original;
    }
    *decoded = '\0';
    return d;
}
