#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <signal.h>
#include "../common/network_utils.h"
#include "../common/protocol.h"

#define CA_CERT_FILE "certs/out/ca.crt"
#define SERVER_IP "127.0.0.1"
#define HEARTBEAT_INTERVAL 10

// State
int sock = -1;
SSL_CTX *ctx = NULL;
SSL *ssl = NULL;
int is_logged_in = 0, is_admin_user = 0, app_running = 1;
char current_user[MAX_NAME_LEN];
pthread_t hb_tid;
pthread_mutex_t ssl_lock = PTHREAD_MUTEX_INITIALIZER;

// --- Helper: Thread-Safe Network Wrapper ---

int send_packet_safe(int opcode, void *payload, int payload_len) {
    pthread_mutex_lock(&ssl_lock);
    int ret = net_send_packet(ssl, opcode, payload, payload_len);
    pthread_mutex_unlock(&ssl_lock);
    return ret;
}

int recv_packet_safe(void *buffer, int max_len, int *out_len) {
    PacketHeader header;
    pthread_mutex_lock(&ssl_lock);
    
    if (ssl_recv_all(ssl, &header, sizeof(PacketHeader)) < 0) {
        pthread_mutex_unlock(&ssl_lock);
        return -1;
    }

    int payload_len = header.length - sizeof(PacketHeader);
    if (out_len) *out_len = payload_len;

    if (payload_len > 0) {
        if (payload_len > max_len) {
            pthread_mutex_unlock(&ssl_lock);
            return -1; 
        }
        if (ssl_recv_all(ssl, buffer, payload_len) < 0) {
            pthread_mutex_unlock(&ssl_lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&ssl_lock);
    return header.opcode;
}

// --- Heartbeat ---

void *heartbeat_loop(void *arg) {
    (void)arg;
    while (app_running) {
        sleep(HEARTBEAT_INTERVAL);
        if (!app_running) break;
        if (send_packet_safe(OP_HEARTBEAT, NULL, 0) < 0) {
            fprintf(stderr, "\n\n[System] Connection lost!\n");
            fprintf(stderr, "[System] Reason: You were likely kicked for idling too long without buying.\n");
            fprintf(stderr, "[System] Press Ctrl+C to exit...\n");
            app_running = 0;
            break;
        }
    }
    return NULL;
}

// --- Logic ---

void do_login() {
    char username[32], password[32];
    
    printf("Enter Username: "); fflush(stdout); 
    scanf("%20s", username);
    
    printf("Enter Password: "); fflush(stdout);
    scanf("%20s", password);

    LoginRequest req;
    memset(&req, 0, sizeof(req));
    strncpy(req.username, username, MAX_NAME_LEN - 1);
    sha256_string(password, req.password_hash);

    if (send_packet_safe(OP_LOGIN_REQ, &req, sizeof(LoginRequest)) < 0) return;

    BasicResponse resp;
    if (recv_packet_safe(&resp, sizeof(BasicResponse), NULL) == OP_LOGIN_RESP) {
        if (resp.status == 0) {
            printf("\n[✔ Success] %s\n", resp.message);
            is_logged_in = 1;
            strcpy(current_user, username);
            if ((is_admin_user = resp.is_admin)) printf("[System] Admin Privileges Granted.\n");
        } else {
            printf("\n[✘ Error] %s\n", resp.message);
        }
    }
}

void do_list_items() {
    if (send_packet_safe(OP_LIST_REQ, NULL, 0) < 0) return;

    ItemInfo items[MAX_ITEMS_IN_LIST];
    int bytes_received = 0;
    if (recv_packet_safe(items, sizeof(items), &bytes_received) == OP_LIST_RESP) {
        int count = bytes_received / sizeof(ItemInfo);
        printf("\n=== Product List ===\n");
        printf("%-5s %-20s %-10s %-5s\n", "ID", "Name", "Price", "Qty");
        printf("--------------------------------------------\n");
        for (int i = 0; i < count; i++) {
            printf("%-5d %-20s $%-9d %-5d\n", items[i].id, items[i].name, items[i].price, items[i].quantity);
        }
        printf("--------------------------------------------\n");
        if (count == 0) printf("(No items available)\n");
    }
}

void do_buy_item() {
    if (!is_logged_in) { printf("\n[!] Please Login first.\n"); return; }
    int id, qty;
    
    printf("Enter Item ID to buy: "); fflush(stdout);
    if (scanf("%d", &id) != 1) { while(getchar()!='\n'); return; }
    
    printf("Enter Quantity: "); fflush(stdout);
    if (scanf("%d", &qty) != 1) { while(getchar()!='\n'); return; }

    BuyRequest req = {id, qty};
    if (send_packet_safe(OP_BUY_REQ, &req, sizeof(BuyRequest)) < 0) return;

    BasicResponse resp;
    if (recv_packet_safe(&resp, sizeof(BasicResponse), NULL) == OP_BUY_RESP) {
        if (resp.status == 0) {
            printf("\n[✔ Purchase Successful] %s\n", resp.message);
        } else {
            printf("\n[✘ Purchase Failed] %s\n", resp.message);
        }
    }
}

void do_admin_action(int opcode) {
    char name[32] = {0}; int price=0, qty=0, id=0;
    if (opcode == OP_ADD_ITEM) {
        printf("Enter Item Name: "); fflush(stdout);
        scanf("%20s", name);
        printf("Enter Price: "); fflush(stdout);
        scanf("%d", &price);
        printf("Enter Quantity: "); fflush(stdout);
        scanf("%d", &qty);
        
        AddItemRequest req; memset(&req, 0, sizeof(req));
        strncpy(req.name, name, 31); req.price = price; req.quantity = qty;
        send_packet_safe(OP_ADD_ITEM, &req, sizeof(req));
    } else {
        printf("Enter Item ID to remove: "); fflush(stdout);
        scanf("%d", &id);
        RemoveItemRequest req = {id};
        send_packet_safe(OP_REMOVE_ITEM, &req, sizeof(req));
    }
    
    BasicResponse resp;
    recv_packet_safe(&resp, sizeof(BasicResponse), NULL);
    
    if (resp.status == 0) {
        printf("\n[✔ Admin Action Success] %s\n", resp.message);
    } else {
        printf("\n[✘ Admin Action Failed] %s\n", resp.message);
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    init_openssl();
    if (!(ctx = create_client_context(CA_CERT_FILE))) exit(1);

    printf("[System] Connecting to %s:%d...\n", SERVER_IP, PORT);
    if (connect_to_server_tls(SERVER_IP, PORT, ctx, &ssl, &sock) < 0) exit(1);
    
    pthread_create(&hb_tid, NULL, heartbeat_loop, NULL);

    int choice;
    while (app_running) {
        printf("\n--- User: %s ---\n", is_logged_in ? current_user : "Guest");
        printf("1. Login\n");
        printf("2. List\n");
        printf("3. Buy\n");
        printf("4. Exit\n");
        
        if (is_admin_user) {
            printf("5. Add\n");
            printf("6. Del\n");
        }
        
        printf("Select > "); fflush(stdout);
        
        if (scanf("%d", &choice) != 1) { while(getchar() != '\n'); continue; }

        switch (choice) {
            case 1: do_login(); break;
            case 2: do_list_items(); break;
            case 3: do_buy_item(); break;
            case 4: app_running = 0; break;
            case 5: if(is_admin_user) do_admin_action(OP_ADD_ITEM); break;
            case 6: if(is_admin_user) do_admin_action(OP_REMOVE_ITEM); break;
            default: printf("\n[!] Invalid Option\n");
        }
    }

    pthread_join(hb_tid, NULL);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (sock >= 0) close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}