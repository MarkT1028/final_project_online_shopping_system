#include "master.h"
#include <stdio.h>
#include "common.h"
int main() {
    printf("=== Server Starting ===\n");
    master_init_system(); // IPC & Signals
    SSL_CTX *ctx = master_init_ssl();
    int fd = master_create_socket(PORT);
    
    printf("[Main] Forking 4 workers...\n");
    master_fork_workers(4, fd, ctx);
    
    master_wait_loop(); // Block until SIGINT
    return 0;
}