#include "worker.h"
#include "common.h"
#include <sys/sem.h>
#include <sqlite3.h>
#include <openssl/err.h>
#include <errno.h>

sqlite3 *db;

void sem_lock() {
    struct sembuf sb = {0, -1, SEM_UNDO};
    semop(sem_id, &sb, 1);
}

void sem_unlock() {
    struct sembuf sb = {0, 1, SEM_UNDO};
    semop(sem_id, &sb, 1);
}

void handle_request(SSL *ssl, int worker_id) {
    MsgHeader header;
    char buffer[MAX_BUFFER];

    while (1) {
        if (recv_packet_header(ssl, &header) < 0){
            //ETIMEDOUT 判斷，並印出所有錯誤情況
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                printf("[Worker %d] Client Timed Out (5s). Closing connection.\n", worker_id);
            } else if (errno == 0) {
                // errno 為 0 通常代表 Client 主動優雅斷線 (Graceful Close)
                printf("[Worker %d] Client disconnected normally.\n", worker_id);
            } else {
                // 其他錯誤 (例如 Connection Reset)
                printf("[Worker %d] Read Error. errno=%d, msg=%s\n", worker_id, errno, strerror(errno));
            }
            fflush(stdout);
            break;
        } 
        if (header.length > MAX_BUFFER) break;
        if (header.length > 0) recv_n(ssl, buffer, header.length);

        PayloadResponse resp = {0, ""};
        
        switch (header.opcode) {
            case OP_LOGIN:
                // Demo: Always success
                resp.status = 0; strcpy(resp.message, "Login OK");
                send_packet(ssl, OP_LOGIN_RESP, &resp, sizeof(resp));
                break;

            case OP_LIST_ITEMS:
                // IPC Read (No lock needed for reading usually, or use reader-lock)
                send_packet(ssl, OP_LIST_RESP, shm_ptr, sizeof(SharedData));
                break;

            case OP_BUY_ITEM: {
                PayloadBuy *req = (PayloadBuy *)buffer;
                int pid = req->product_id;
            
            case OP_HEARTBEAT:
                // 收到心跳包，回傳一樣的空包當作 Pong
                // 這會重置 setsockopt 的 timeout 計時器 (因為有讀到資料)
                send_packet(ssl, OP_HEARTBEAT, NULL, 0);
                break;
                
                // === IPC CRITICAL SECTION ===
                sem_lock(); // Protect Shared Memory
                int success = 0;
                if (pid < shm_ptr->product_count && shm_ptr->products[pid].stock >= req->quantity) {
                    shm_ptr->products[pid].stock -= req->quantity;
                    shm_ptr->total_transactions++;
                    success = 1;
                }
                sem_unlock(); 
                // === END CRITICAL SECTION ===

                if (success) {
                    // Persistence to SQLite
                    char *err_msg = 0;
                    char sql[256];
                    sprintf(sql, "INSERT INTO orders (user_id, product_id, amount) VALUES (1, %d, %d);", pid, req->quantity);
                    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
                        // DB Fail -> Rollback Shared Memory (Optional reliability)
                        sem_lock();
                        shm_ptr->products[pid].stock += req->quantity;
                        sem_unlock();
                        resp.status = -1; strcpy(resp.message, "DB Error");
                    } else {
                        resp.status = 0; sprintf(resp.message, "Bought %s", shm_ptr->products[pid].name);
                    }
                } else {
                    resp.status = -1; strcpy(resp.message, "Out of Stock");
                }
                send_packet(ssl, OP_BUY_RESP, &resp, sizeof(resp));
                break;
            }
        }
    }
}

void worker_main(int worker_id, int listen_fd, SSL_CTX *ctx) {
    // Open DB per process
    if (sqlite3_open("ecommerce.db", &db) != SQLITE_OK) return;
    
    //設定 SQLite 等待鎖定的時間為 3000 毫秒 (3秒)
    sqlite3_busy_timeout(db, 3000);
    
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    while(1) {
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
        if (client_fd < 0) continue;

        // Timeout Setting
        struct timeval tv = {5, 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) > 0) handle_request(ssl, worker_id);
        
        SSL_shutdown(ssl); SSL_free(ssl); close(client_fd);
    }
    sqlite3_close(db);
}