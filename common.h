#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

// --- Config ---
#define PORT 8888
#define MAX_PRODUCTS 20
#define SHM_KEY 0x1234
#define SEM_KEY 0x5678
#define MAX_BUFFER 4096

// TLS Certs
#define CERT_FILE "certs/server.crt"
#define KEY_FILE  "certs/server.key"

// --- Protocol OpCodes ---
#define OP_HEARTBEAT    0x0001
#define OP_LOGIN        0x0010
#define OP_LOGIN_RESP   0x0011
#define OP_LIST_ITEMS   0x0020
#define OP_LIST_RESP    0x0021
#define OP_BUY_ITEM     0x0030
#define OP_BUY_RESP     0x0031
#define OP_ERROR        0xFFFF

// --- Protocol Header ---
typedef struct {
    uint32_t length;
    uint16_t opcode;
    uint16_t checksum;
} __attribute__((packed)) MsgHeader;

// --- Shared Memory Data ---
typedef struct {
    int id;
    char name[32];
    int price;
    int stock;
} Product;

typedef struct {
    Product products[MAX_PRODUCTS];
    int product_count;
    int total_transactions; // 統計指標
} SharedData;

// --- Payloads ---
typedef struct {
    char username[32];
    char password[32];
} PayloadLogin;

typedef struct {
    int product_id;
    int quantity;
} PayloadBuy;

typedef struct {
    int status; // 0=OK, -1=Fail
    char message[128];
} PayloadResponse;

// --- Globals (Extern) ---
extern SharedData *shm_ptr;
extern int sem_id;

// --- Functions ---
uint16_t calculate_checksum(void *data, size_t len);
int send_packet(SSL *ssl, uint16_t opcode, void *payload, uint32_t payload_len);
int recv_packet_header(SSL *ssl, MsgHeader *header);
int recv_n(SSL *ssl, void *buf, int n);

#endif