#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sqlite3.h>
#include "worker.h"
#include "../common/protocol.h"
#include "../common/network_utils.h"
#include "db_manager.h"
#include "shm_manager.h"

#define TIMEOUT_SEC 25 // allow missing 1~2 heartbeats
#define DB_FILE "server/data/shop.db"

static sqlite3 *worker_db = NULL;

// --- Helper Functions ---

// 快速回傳基本回應 (利用 net_send_packet)
void send_basic_resp(SSL *ssl, int opcode, int status, const char *msg, int is_admin) {
    BasicResponse resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    resp.is_admin = is_admin;
    strncpy(resp.message, msg, sizeof(resp.message) - 1);
    
    net_send_packet(ssl, opcode, &resp, sizeof(BasicResponse));
}

int check_admin(SSL *ssl, int user_role) {
    if (user_role != 2) {
        send_basic_resp(ssl, OP_ERROR, -1, "Permission Denied: Admin only", 0);
        return 0;
    }
    return 1;
}

int check_login(SSL *ssl, int user_role) {
    if (user_role == 0) {
        send_basic_resp(ssl, OP_BUY_RESP, -1, "Please Login First", 0);
        return 0;
    }
    return 1;
}

// --- Business Logic Handlers ---

int handle_login(SSL *ssl, void *buffer) {
    LoginRequest *req = (LoginRequest *)buffer;
    // Ensure null termination
    req->username[MAX_NAME_LEN - 1] = '\0';
    req->password_hash[64] = '\0';
    
    printf("[Worker] Login attempt: %s\n", req->username);
    int role = db_validate_user(worker_db, req->username, req->password_hash);
    
    send_basic_resp(ssl, OP_LOGIN_RESP, (role > 0) ? 0 : -1, 
                    (role > 0) ? "Login Success" : "Invalid Credentials", (role == 2));
    return role;
}

void handle_list(SSL *ssl) {
    shm_lock();
    SharedData *shm = shm_get_data();
    net_send_packet(ssl, OP_LIST_RESP, shm->items, shm->count * sizeof(ItemInfo));
    shm_unlock();
}

void handle_buy(SSL *ssl, void *buffer) {
    BuyRequest *req = (BuyRequest *)buffer;
    char msg[128] = "Item not found or out of stock";
    int status = -1;

    // Validate input
    if (req->quantity <= 0 || req->quantity > 1000) {
        send_basic_resp(ssl, OP_BUY_RESP, -1, "Invalid quantity", 0);
        return;
    }

    shm_lock();
    SharedData *shm = shm_get_data();
    for (int i = 0; i < shm->count; i++) {
        if (shm->items[i].id == req->item_id) {
            if (shm->items[i].quantity >= req->quantity) {
                shm->items[i].quantity -= req->quantity;
                status = 0;
                snprintf(msg, sizeof(msg), "Bought %s x%d", shm->items[i].name, req->quantity);
            }
            break;
        }
    }
    shm_unlock();
    send_basic_resp(ssl, OP_BUY_RESP, status, msg, 0);
}

void handle_add_item(SSL *ssl, void *buffer) {
    AddItemRequest *req = (AddItemRequest *)buffer;
    char msg[128];
    int status = 0;

    // Ensure null termination and validate input
    req->name[MAX_NAME_LEN - 1] = '\0';
    if (req->price < 0 || req->quantity < 0) {
        send_basic_resp(ssl, OP_ADD_ITEM, -1, "Invalid price or quantity", 0);
        return;
    }

    shm_lock();
    SharedData *shm = shm_get_data();
    if (shm->count >= MAX_ITEMS_IN_LIST) {
        status = -1;
        strcpy(msg, "Inventory Full");
    } else {
        int max_id = 0;
        for (int i = 0; i < shm->count; i++) max_id = (shm->items[i].id > max_id) ? shm->items[i].id : max_id;
        
        int new_idx = shm->count++;
        shm->items[new_idx].id = max_id + 1;
        strncpy(shm->items[new_idx].name, req->name, MAX_NAME_LEN - 1);
        shm->items[new_idx].name[MAX_NAME_LEN - 1] = '\0';
        shm->items[new_idx].price = req->price;
        shm->items[new_idx].quantity = req->quantity;
        snprintf(msg, sizeof(msg), "Added Item ID %d: %s", max_id + 1, req->name);
    }
    shm_unlock();
    send_basic_resp(ssl, OP_ADD_ITEM, status, msg, 0);
}

void handle_remove_item(SSL *ssl, void *buffer) {
    RemoveItemRequest *req = (RemoveItemRequest *)buffer;
    char msg[128] = "Item ID not found";
    int status = -1;

    shm_lock();
    SharedData *shm = shm_get_data();
    for (int i = 0; i < shm->count; i++) {
        if (shm->items[i].id == req->item_id) {
            if (i != shm->count - 1) shm->items[i] = shm->items[shm->count - 1];
            shm->count--;
            status = 0;
            snprintf(msg, sizeof(msg), "Item ID %d removed", req->item_id);
            break;
        }
    }
    shm_unlock();
    send_basic_resp(ssl, OP_REMOVE_ITEM, status, msg, 0);
}

// --- Main Handler ---

void handle_client(SSL *ssl) {
    PacketHeader header;
    int is_running = 1;
    int user_role = 0; 
    int heartbeat_streak = 0;

    while (is_running) {
        // Read Header
        int ret = ssl_recv_all(ssl, &header, sizeof(PacketHeader));
        
        if (ret < 0) {
            int ssl_err = SSL_get_error(ssl, ret);
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("[Worker] Client timed out due to no heartbeat.\n");
                if (net_send_packet(ssl, OP_HEARTBEAT, NULL, 0) < 0) break;
                continue;
            }


            if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                printf("[Worker] Client disconnected gracefully.\n");
                break;
            }

            if (ssl_err == SSL_ERROR_SYSCALL) {
                printf("[Worker] Client disconnected unexpectedly.\n");
                break;
            }

            printf("[Worker] Connection Error/Closed (SSL Error: %d, ret: %d)\n", ssl_err, ret);
            break; 
        }

        int payload_len = header.length - sizeof(PacketHeader);
        char buffer[MAX_PAYLOAD_SIZE];

        if (payload_len > 0) {
            if (payload_len > MAX_PAYLOAD_SIZE || ssl_recv_all(ssl, buffer, payload_len) < 0) break;
        }

        switch (header.opcode) {
            case OP_LOGIN_REQ: 
                user_role = handle_login(ssl, buffer); 
                break;
            
            case OP_LIST_REQ:  
                handle_list(ssl); 
                break;
            
            case OP_BUY_REQ:
                heartbeat_streak = 0; 
                if (check_login(ssl, user_role)) handle_buy(ssl, buffer); 
                break;
            
            case OP_ADD_ITEM:
                if (check_admin(ssl, user_role)) handle_add_item(ssl, buffer); 
                break;
            
            case OP_REMOVE_ITEM: 
                if (check_admin(ssl, user_role)) handle_remove_item(ssl, buffer); 
                break;
            
            case OP_HEARTBEAT:
                heartbeat_streak++;
                printf("[Worker] Heartbeat received. Streak: %d\n", heartbeat_streak);
                
                if (heartbeat_streak > 5) {
                    printf("[Worker] Kick Client: Too many heartbeats without buying.\n");
                    send_basic_resp(ssl, OP_ERROR, -1, "Kicked: Buy something!", 0);
                    is_running = 0; // 結束迴圈 -> 斷開連線
                }
                break;

            default:
                is_running = 0;
        }
    }
}

void worker_loop(int server_fd, SSL_CTX *ctx) {
    int rc = sqlite3_open(DB_FILE, &worker_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Worker] Cannot open database: %s\n", sqlite3_errmsg(worker_db));
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) continue;

        net_set_timeout(client_fd, TIMEOUT_SEC);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) > 0) handle_client(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    sqlite3_close(worker_db);
}