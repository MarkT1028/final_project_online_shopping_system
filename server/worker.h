#ifndef WORKER_H
#define WORKER_H

#include <openssl/ssl.h>

void worker_loop(int server_fd, SSL_CTX *ctx);

#endif