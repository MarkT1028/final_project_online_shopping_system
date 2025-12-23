/**
 * This header file is shared between the Server and Client.
 * It enforces a strict packet format: [Length][OpCode][Checksum][Data]
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

// --- System Constants ---
#define PORT 8888               // Default server port
#define MAX_PAYLOAD_SIZE 4096   // Max size for the data part
#define MAX_NAME_LEN 32         // Max length for username/item name
#define MAX_ITEMS_IN_LIST 50    // Limit items per list request to avoid huge packets

// --- Operation Codes (OpCodes) ---
// These define what action the packet represents.
typedef enum {
    OP_LOGIN_REQ    = 0x0001,   // Client -> Server: Login attempt
    OP_LOGIN_RESP   = 0x0002,   // Server -> Client: Login result

    OP_LIST_REQ     = 0x0003,   // Client -> Server: Request item list
    OP_LIST_RESP    = 0x0004,   // Server -> Client: Return item list

    OP_BUY_REQ      = 0x0005,   // Client -> Server: Attempt to buy item
    OP_BUY_RESP     = 0x0006,   // Server -> Client: Buy result

    OP_ADD_ITEM     = 0x0007,   // Admin -> Server: Add new item
    OP_REMOVE_ITEM  = 0x0008,   // Admin -> Server: Remove item

    OP_HEARTBEAT    = 0x0099,   // Client <-> Server: Keep-alive signal
    OP_ERROR        = 0xFFFF    // Server -> Client: General error
} OpCode;

// --- Packet Header Structure ---
// __attribute__((packed)) ensures the compiler does not add padding bytes.
// This is crucial for network transmission to match exact byte layouts.
typedef struct {
    uint32_t length;    // Total length of the packet (Header + Data)
    uint16_t opcode;    // Operation Code (from enum OpCode)
    uint16_t checksum;  // Simple XOR checksum of the Data part
} __attribute__((packed)) PacketHeader;

// --- Payload Structures (Data Content) ---

// Payload for OP_LOGIN_REQ
typedef struct {
    char username[MAX_NAME_LEN];
    char password_hash[65]; // SHA-256 hex string + null terminator
} LoginRequest;

// Payload for OP_LOGIN_RESP and OP_BUY_RESP
typedef struct {
    int status;             // 0 = Success, -1 = Fail
    char message[128];      // Human readable message
    int is_admin;           // 1 if admin, 0 if user (only for Login Resp)
} BasicResponse;

// Structure representing a single item (used in shared memory and network)
typedef struct {
    int id;
    char name[MAX_NAME_LEN];
    int price;
    int quantity;
} ItemInfo;

// Payload for OP_BUY_REQ
typedef struct {
    int item_id;
    int quantity;
} BuyRequest;

// Payload for OP_ADD_ITEM
typedef struct {
    char name[MAX_NAME_LEN];
    int price;
    int quantity;
} AddItemRequest;

typedef struct {
    int item_id;
} RemoveItemRequest;

#endif