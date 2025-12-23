#ifndef WORKER_H
#define WORKER_H
#include <openssl/ssl.h>

void worker_main(int worker_id, int listen_fd, SSL_CTX *ctx);

#endif