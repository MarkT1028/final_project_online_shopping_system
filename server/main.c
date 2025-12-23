#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "../common/network_utils.h"
#include "shm_manager.h"
#include "db_manager.h"
#include "worker.h"

#define WORKER_COUNT 20
#define DB_FILE "server/data/shop.db"
#define CERT_FILE "certs/out/server.crt"
#define KEY_FILE  "certs/out/server.key"

pid_t workers[WORKER_COUNT];
int server_fd;

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\n[Master] Shutting down...\n");
        // Kill workers
        for (int i = 0; i < WORKER_COUNT; i++) {
            kill(workers[i], SIGKILL);
        }
        // Wait for them
        while (wait(NULL) > 0);
        
        // Cleanup resources
        shm_destroy();
        close(server_fd);
        printf("[Master] Goodbye.\n");
        exit(0);
    }
}

int main() {
    // 1. Setup Signal Handling
    signal(SIGINT, handle_signal);

    // 2. Initialize Resources
    init_openssl();
    SSL_CTX *ctx = create_server_context(CERT_FILE, KEY_FILE);
    if (!ctx) exit(EXIT_FAILURE);

    if (shm_init() < 0) exit(EXIT_FAILURE);
    if (db_init(DB_FILE) < 0) exit(EXIT_FAILURE);

    // 3. Setup Socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Allow port reuse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("[Master] Server listening on port %d with %d workers\n", PORT, WORKER_COUNT);

    // 4. Fork Workers (Preforking Model)
    for (int i = 0; i < WORKER_COUNT; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child (Worker)
            worker_loop(server_fd, ctx);
            exit(0);
        } else if (pid > 0) {
            // Parent (Master)
            workers[i] = pid;
        } else {
            perror("fork failed");
        }
    }

    // 5. Master Loop (Just wait)
    while (1) {
        pause(); // Wait for signal
    }

    return 0;
}