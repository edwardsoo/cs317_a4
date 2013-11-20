/*
 * File: cshttp.c
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

#include "service.h"

#define BACKLOG 10   // how many pending connections queue will hold

static void sigchld_handler(int s) {
    
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa) {
    
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    else
        return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static int create_server_socket(char *port) {
    
    int lst_socket;
    struct addrinfo hints, *servinfo, *p;
    int yes = 1;
    int rv;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((lst_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(lst_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(lst_socket, p->ai_addr, p->ai_addrlen) == -1) {
            close(lst_socket);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(2);
    }
    
    freeaddrinfo(servinfo); // all done with this structure
    
    if (listen(lst_socket, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    return lst_socket;
}

int main(int argc, char *argv[]) {
    
    int lst_socket, clt_socket;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    char s[INET6_ADDRSTRLEN];
    
    if (argc < 2) {
        fprintf(stderr, "Port was not specified. Usage:\n\t%s PORTNUMBER\n", argv[0]);
    }
    
    lst_socket = create_server_socket(argv[1]);
    if (lst_socket < 0) return 1;
    
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    
    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof(their_addr);
        clt_socket = accept(lst_socket, (struct sockaddr *) &their_addr, &sin_size);
        if (clt_socket == -1) {
            perror("accept");
            continue;
        }
        
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s));
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(lst_socket); // child doesn't need the listener
            handle_client(clt_socket);
            close(clt_socket);
            exit(0);
        }
        close(clt_socket);  // parent doesn't need this
    }

    return 0;
}
