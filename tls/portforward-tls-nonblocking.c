/* portforward-tls-nonblocking.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#define DEFAULT_PORT 11111
#define CONNECT_WAIT_SEC 2
#define SELECT_WAIT_SEC 1
#define CERT_FILE "../certs/ca-cert.pem"
#define MAX_INSTANCE 256

static int serverfd = -1;
static WOLFSSL_CTX* ctx = NULL;
static struct sockaddr_in clientAddr;

typedef enum {
    STATE_UNUSED = 0,
    STATE_ACCEPTED,
    STATE_TLS_CONNECTED,
} port_forward_state_t;

typedef struct {
    port_forward_state_t state; /* Current state of this connection */
    int plainfd; /* File descriptor for Plaintext Server side */
    int tlsfd; /* File descriptor for TLS Client side */
    WOLFSSL *ssl; /* wolfSSL object for TLS connection */
} port_forward_instance;

static port_forward_instance pf_instances[MAX_INSTANCE];

static void make_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_instance(int index)
{
    /* Implementation of closing and cleaning up an instance goes here */
    if (pf_instances[index].state == STATE_UNUSED)
        return;
    printf("Closing down connection at index %d\n", index);
    if (pf_instances[index].ssl) {
        wolfSSL_free(pf_instances[index].ssl);
        pf_instances[index].ssl = NULL;
    }
    if (pf_instances[index].plainfd != -1) {
        close(pf_instances[index].plainfd);
        pf_instances[index].plainfd = -1;
    }
    if (pf_instances[index].tlsfd != -1) {
        close(pf_instances[index].tlsfd);
        pf_instances[index].tlsfd = -1;
    }
    pf_instances[index].state = STATE_UNUSED;
}

static void establish_ssl(int index)
{
    int err, ret;
    /* Implementation of establishing SSL connection goes here */
    pf_instances[index].ssl = wolfSSL_new(ctx);
    if (pf_instances[index].ssl == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object for index %d\n", index);
        close_instance(index);
    } else {
        wolfSSL_set_fd(pf_instances[index].ssl, pf_instances[index].tlsfd);

        /* Connect to wolfSSL on the server side */
        if (((ret = wolfSSL_connect(pf_instances[index].ssl))) != WOLFSSL_SUCCESS) {
            err = wolfSSL_get_error(pf_instances[index].ssl, ret);
            if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
                fprintf(stderr, "ERROR: failed to connect to wolfSSL: %d\n", ret);
                close_instance(index);
            } else {
                /* Connection in progress, will complete later */
                printf("TLS connection in progress at index %d...\n", index);
            }
        } else {
            printf("TLS connection started at index %d!\n", index);
        }
    }
}

static void handle_new_connection(void)
{
    int x, ret;
    struct sockaddr_in peerAddr;
    socklen_t addrLen = sizeof(peerAddr);
    /* Implementation of accepting new connections goes here */
    int newfd = accept(serverfd, (struct sockaddr*)&peerAddr, &addrLen);
    int connfd = socket(AF_INET, SOCK_STREAM, 0);
    if (newfd > -1)
        make_non_blocking(newfd);
    if (connfd > -1)
        make_non_blocking(connfd); 
    if ((newfd > -1) && (connfd > -1)) {
        for (x=0; x<MAX_INSTANCE; x++) {
            if (pf_instances[x].state == STATE_UNUSED) {
                ret = connect(connfd, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
                if (ret == -1) {
                    if (errno != EINPROGRESS) {
                        fprintf(stderr, "ERROR: failed to connect to remote TLS server\n");
                        break;
                    }
                    /* Accept new connection and set up pf_instances[x] */
                    pf_instances[x].state = STATE_ACCEPTED;
                    printf("New Connection in progress to %s:%d at index %d...\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), x);
                } else if (ret == 0) {
                    /* Connection completed immediately, should be rare if ever */
                    pf_instances[x].state = STATE_TLS_CONNECTED;
                    printf("New Connection established to %s:%d at index %d!\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), x);
                }
                /* Additional setup code goes here */
                pf_instances[x].plainfd = newfd;
                pf_instances[x].tlsfd = connfd;
                if (pf_instances[x].state == STATE_TLS_CONNECTED)
                    establish_ssl(x);
                return;
            }
        }
    }
    if (newfd > -1)
        close(newfd);
    if (connfd > -1)
        close(connfd);
}

static int select_all_fds(void)
{
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    int maxfd = 0, ret, err, check;
    struct timeval timeout;
    int i, result;
    char buf[4096];
    char errstr[256];

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);

    /* Add server socket to read set */
    if (serverfd != -1) {
        FD_SET(serverfd, &readfds);
        if (serverfd > maxfd)
            maxfd = serverfd;
    }

    /* Add all instance fds to sets */
    for (i = 0; i < MAX_INSTANCE; i++) {
        if (pf_instances[i].state == STATE_UNUSED)
            continue;

        /* Plaintext server side */
        if (pf_instances[i].plainfd != -1) {
            /* We only care about reading from the client after we make the connection */
            if (pf_instances[i].state > STATE_ACCEPTED)
                FD_SET(pf_instances[i].plainfd, &readfds);
            FD_SET(pf_instances[i].plainfd, &exceptfds);
            if (pf_instances[i].plainfd > maxfd)
                maxfd = pf_instances[i].plainfd;
        }

        /* TLS client side */
        if (pf_instances[i].tlsfd != -1) {
            FD_SET(pf_instances[i].tlsfd, &readfds);
            /* Watch for writability when making outbound connection */
            if (pf_instances[i].state == STATE_ACCEPTED)
                FD_SET(pf_instances[i].tlsfd, &writefds);
            FD_SET(pf_instances[i].tlsfd, &exceptfds);
            if (pf_instances[i].tlsfd > maxfd)
                maxfd = pf_instances[i].tlsfd;
        }
    }

    /* Set timeout */
    timeout.tv_sec = SELECT_WAIT_SEC;
    timeout.tv_usec = 0;

    /* Perform select */
    result = select(maxfd + 1, &readfds, &writefds, &exceptfds, &timeout);


    if (result > 0) {
        /* Check server socket */
        if (serverfd != -1 && FD_ISSET(serverfd, &readfds)) {
            /* Handle new incoming connection */
            handle_new_connection();
        }

        /* Check all instance fds */
        for (i = 0; i < MAX_INSTANCE; i++) {
            if (pf_instances[i].state == STATE_UNUSED)
                continue;

            /* Check plaintext server side */
            if (pf_instances[i].plainfd != -1) {
                if (FD_ISSET(pf_instances[i].plainfd, &readfds)) {
                    /* Handle reading from plaintext server side */
                    ret = read(pf_instances[i].plainfd, buf, sizeof(buf));
                    if (ret > 0) {
                        /* Forward data to TLS client side */
                        if (pf_instances[i].ssl) {
                            check = wolfSSL_write(pf_instances[i].ssl, buf, ret);
                            if (check != ret) {
                                fprintf(stderr, "ERROR: failed to write to TLS side at index %d\n", i);
                                close_instance(i);
                            }
                        }
                    } else if ((ret == 0) || (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                        /* Connection closed by client */
                        printf("Plaintext connection closed at index %d ret %d, (%s)\n", i, ret, strerror(errno));
                        close_instance(i);
                    }
                }
                if (FD_ISSET(pf_instances[i].plainfd, &exceptfds)) {
                    /* Handle exception on plaintext server side */
                    printf("Exception on Plaintext side at index %d\n", i);
                    close_instance(i);
                }
            }

            /* Check TLS client side */
            if (pf_instances[i].tlsfd != -1) {
                if (FD_ISSET(pf_instances[i].tlsfd, &readfds)) {
                    /* Handle reading from TLS client side */
                    ret = wolfSSL_read(pf_instances[i].ssl, buf, sizeof(buf));
                    if (ret > 0) {
                        /* Forward data to plaintext server side */
                        if (pf_instances[i].plainfd != -1) {
                            check = write(pf_instances[i].plainfd, buf, ret);
                            if (check != ret) {
                                fprintf(stderr, "ERROR: failed to write to Plaintext side at index %d\n", i);
                                close_instance(i);
                            }
                        }
                    } else  {
                        err = wolfSSL_get_error(pf_instances[i].ssl, ret);
                        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
                            /* Connection closed by client */
                            printf("TLS connection closed at index %d ret %d, err %d (%s)\n", i, ret, err, wolfSSL_ERR_error_string(err, errstr));
                            close_instance(i);
                        }
                    }
                }
                if (FD_ISSET(pf_instances[i].tlsfd, &writefds)) {
                    /* Handle writability for TLS client side */
                    if (pf_instances[i].state == STATE_ACCEPTED) {
                        /* Complete TLS connection */
                        pf_instances[i].state = STATE_TLS_CONNECTED;
                        printf("TCP connection to server established at index %d!\n", i);
                        establish_ssl(i);
                    }
                }
                if (FD_ISSET(pf_instances[i].tlsfd, &exceptfds)) {
                    /* Handle exception on TLS client side */
                    printf("Exception on TLS side at index %d\n", i);
                    close_instance(i);
                }
            }
        }
    }

    return result;
}

int main(int argc, char *argv[])
{
    int ret = -1, x, on = 1;
    struct sockaddr_in servAddr;

    /* Check for proper calling convention */
    if (argc != 5) {
        printf("usage: %s <Local IPv4 Address> <Local Port> <Remote IPv4 Address> <Remote Port>\n", argv[0]);
        return 0;
    }

    /* Initialize instances */
    for (x=0; x<MAX_INSTANCE; x++) {
        pf_instances[x].state = STATE_UNUSED;
        pf_instances[x].plainfd = -1;
        pf_instances[x].tlsfd = -1;
        pf_instances[x].ssl = NULL;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));
    memset(&clientAddr, 0, sizeof(clientAddr));

    /* Get the server IPv4 address and port from the command line call */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid server (local) address\n");
        ret = -1;
        goto end;
    }

    if ((sscanf(argv[2], "%hu", (unsigned short*)&servAddr.sin_port) != 1) || (servAddr.sin_port < 1) || (servAddr.sin_port > 65535)) {
        fprintf(stderr, "ERROR: invalid server (local) port\n");
        ret = -1;
        goto end;
    } else
        servAddr.sin_port = htons(servAddr.sin_port);

    if (inet_pton(AF_INET, argv[3], &clientAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid client (remote) address\n");
        ret = -1;
        goto end;
    }

    if ((sscanf(argv[4], "%hu", (unsigned short*)&clientAddr.sin_port) != 1) || (clientAddr.sin_port < 1) || (clientAddr.sin_port > 65535)) {
        fprintf(stderr, "ERROR: invalid client (remote) port\n");
        ret = -1;
        goto end;
    } else
        clientAddr.sin_port = htons(clientAddr.sin_port);

    /* Fill in the server address */
    clientAddr.sin_family = servAddr.sin_family      = AF_INET;             /* using IPv4      */

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the server socket: %s\n", strerror(errno));
        ret = -1;
        goto end;
    }

     setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR,
            (char*)&on, (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEPORT,
               (char*)&on, (socklen_t)sizeof(on));
#endif

/* Bind the server socket to our port */
    if (bind(serverfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind: %s\n", strerror(errno));
        ret = -1;
        goto socket_cleanup;
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(serverfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen: %s\n", strerror(errno));
        ret = -1;
        goto socket_cleanup;
    }

    printf("Listening on %s:%d and forwarding to %s:%d\n",
           argv[1], ntohs(servAddr.sin_port),
           argv[3], ntohs(clientAddr.sin_port));

    make_non_blocking(serverfd);

    /* Initialize wolfSSL */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* Create and initialize Client WOLFSSL_CTX */
#ifdef USE_TLSV13
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        goto socket_cleanup;
    }
    printf("Initialized SSL CLient\n");
    /* Main loop */
    while (select_all_fds() >= 0) {
        /* Loop continues handling connections and data */
    }
    /* Cleanup and return */
    for (x=0; x<MAX_INSTANCE; x++)
        close_instance(x);
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(serverfd);          /* Close the connection to the server       */
end:
    return ret;               /* Return reporting a success               */
}