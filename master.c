#include "master.h"
#include "worker.h"
#include "common.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <signal.h>
#include <openssl/err.h>

static int g_server_fd = 0;
static int g_shm_id = 0;
static pid_t *g_worker_pids = NULL;
static int g_worker_count = 0;

// Graceful Shutdown Handler
void handle_sigint(int sig) {
    printf("\n[Master] Signal %d received. Cleaning up...\n", sig);
    
    // 1. Kill Workers
    if (g_worker_pids) {
        for(int i=0; i<g_worker_count; i++) if(g_worker_pids[i]>0) kill(g_worker_pids[i], SIGTERM);
        while(wait(NULL) > 0);
        free(g_worker_pids);
    }
    // 2. Remove IPC
    if (shm_ptr) shmdt(shm_ptr);
    if (g_shm_id > 0) shmctl(g_shm_id, IPC_RMID, NULL);
    if (sem_id > 0) semctl(sem_id, 0, IPC_RMID);
    // 3. Close Socket
    if (g_server_fd > 0) close(g_server_fd);
    
    printf("[Master] Cleanup done. Bye.\n");
    exit(0);
}

void master_init_system() {
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    // Setup Shared Memory
    g_shm_id = shmget(SHM_KEY, sizeof(SharedData), 0666 | IPC_CREAT);
    if (g_shm_id < 0) { perror("shmget"); exit(1); }
    shm_ptr = (SharedData *)shmat(g_shm_id, NULL, 0);
    
    // Init Data if empty
    if (shm_ptr->product_count == 0) {
        memset(shm_ptr, 0, sizeof(SharedData));
        shm_ptr->product_count = 3;
        // shm_ptr->products[0] = (Product){0, "iPhone 15", 30000, 50}; 
        // shm_ptr->products[1] = (Product){1, "PS5 Pro", 15000, 20};
        // shm_ptr->products[2] = (Product){2, "RTX 4090", 60000, 5};
        shm_ptr->products[0] = (Product){0, "iPhone 15", 30000, 10000}; 
        shm_ptr->products[1] = (Product){1, "PS5 Pro", 15000, 5000};
        shm_ptr->products[2] = (Product){2, "RTX 4090", 60000, 2000};
    }

    // Setup Semaphore (Mutex)
    sem_id = semget(SEM_KEY, 1, 0666 | IPC_CREAT);
    if (sem_id < 0) { perror("semget"); exit(1); }
    union semun { int val; struct semid_ds *buf; unsigned short *array; } arg;
    arg.val = 1;
    semctl(sem_id, 0, SETVAL, arg);
}

int master_create_socket(int port) {
    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    int opt = 1;
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("Bind"); exit(1); }
    if (listen(g_server_fd, 100) < 0) { perror("Listen"); exit(1); }
    return g_server_fd;
}

SSL_CTX *master_init_ssl() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) exit(1);
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    return ctx;
}

void master_fork_workers(int worker_count, int server_fd, SSL_CTX *ctx) {
    g_worker_count = worker_count;
    g_worker_pids = malloc(sizeof(pid_t) * worker_count);
    for (int i=0; i<worker_count; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_main(i, server_fd, ctx); // Child goes to worker logic
            exit(0);
        } else {
            g_worker_pids[i] = pid;
        }
    }
}

void master_wait_loop() {
    while(1) sleep(10); // Main thread just waits for signals
}