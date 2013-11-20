/*
 * File: service.h
 */

#ifndef _SERVICE_H_
#define _SERVICE_H_

#define RECV_BUFFER_SIZE 0x1000

#define CMD_KNOCK "knock"
#define CMD_LOGIN "login"
#define CMD_LOGOUT "logout"
#define CMD_GETFILE "getfile"
#define CMD_PUTFILE "putfile"
#define CMD_ADDCART "addcart"
#define CMD_DELCART "delcart"
#define CMD_CHECKOUT "checkout"

#define HDR_CONTENT_LEN "Content-Length"
#define HDR_CONTENT_TYPE "Content-Type"
#define HDR_CACHE_CTRL "Cache-Control"
#define HDR_CONNECTION "Connection"
#define HDR_XFER_ENCODE "Transfer-Encoding"
#define HDR_IF_MOD_SINCE "If-Modified-Since"
#define HDR_LAST_MOD "Last-Modified"

void handle_client(int socket);

#endif
