#ifndef MASTER_H
#define MASTER_H
#include <openssl/ssl.h>

void master_init_system();
int master_create_socket(int port);
void master_fork_workers(int worker_count, int server_fd, SSL_CTX *ctx);
void master_wait_loop();
SSL_CTX *master_init_ssl();

#endif