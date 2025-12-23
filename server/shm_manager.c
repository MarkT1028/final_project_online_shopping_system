#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <string.h>
#include <errno.h>
#include "shm_manager.h"

#define SHM_KEY 0x1234
#define SEM_KEY 0x5678

static int shm_id = -1;
static int sem_id = -1;
static SharedData *shared_mem = NULL;

// Semaphore P operation (Wait/Lock)
void shm_lock() {
    struct sembuf sb = {0, -1, 0};
    semop(sem_id, &sb, 1);
}

// Semaphore V operation (Signal/Unlock)
void shm_unlock() {
    struct sembuf sb = {0, 1, 0};
    semop(sem_id, &sb, 1);
}

int shm_init() {
    // 1. Create Shared Memory
    shm_id = shmget(SHM_KEY, sizeof(SharedData), IPC_CREAT | IPC_EXCL | 0666);
    int is_new = (shm_id >= 0);
    
    if (!is_new) {
        // Shared memory already exists, try to attach
        shm_id = shmget(SHM_KEY, sizeof(SharedData), 0666);
        if (shm_id < 0) { 
            perror("shmget failed"); 
            return -1; 
        }
    }

    // Attach to process
    shared_mem = (SharedData *)shmat(shm_id, NULL, 0);
    if (shared_mem == (void *)-1) { perror("shmat failed"); return -1; }

    // Initialize data only if we created new shared memory
    if (is_new) {
        memset(shared_mem, 0, sizeof(SharedData));
        shared_mem->count = 5;
        // Mock Data
        shared_mem->items[0] = (ItemInfo){1, "Apple", 8, 5};
        shared_mem->items[1] = (ItemInfo){2, "Banana", 5, 10};
        shared_mem->items[2] = (ItemInfo){3, "Orange", 2, 8};
        shared_mem->items[3] = (ItemInfo){4, "Laptop", 5000, 10};
        shared_mem->items[4] = (ItemInfo){5, "Headphones", 300, 25};
    }

    // 2. Create Semaphore
    sem_id = semget(SEM_KEY, 1, IPC_CREAT | IPC_EXCL | 0666);
    int sem_is_new = (sem_id >= 0);
    
    if (!sem_is_new) {
        // Semaphore already exists
        sem_id = semget(SEM_KEY, 1, 0666);
        if (sem_id < 0) { 
            perror("semget failed"); 
            return -1; 
        }
    }

    // Initialize Semaphore to 1 only if newly created (Binary Semaphore / Mutex)
    if (sem_is_new) {
        semctl(sem_id, 0, SETVAL, 1);
    }

    return 0;
}

SharedData* shm_get_data() {
    return shared_mem;
}

void shm_destroy() {
    if (shared_mem) shmdt(shared_mem);
    if (shm_id >= 0) shmctl(shm_id, IPC_RMID, NULL);
    if (sem_id >= 0) semctl(sem_id, 0, IPC_RMID);
}