#include "common.h"

// 定義全域變數 (實際記憶體配置在這裡)
SharedData *shm_ptr = NULL;
int sem_id = 0;

uint16_t calculate_checksum(void *data, size_t len) {
    uint16_t checksum = 0;
    uint8_t *ptr = (uint8_t *)data;
    for (size_t i = 0; i < len; i++) checksum ^= (uint16_t)ptr[i];
    return checksum;
}

int send_n(SSL *ssl, void *buf, int n) {
    int total = 0;
    while (total < n) {
        int ret = SSL_write(ssl, (char*)buf + total, n - total);
        if (ret <= 0) return -1;
        total += ret;
    }
    return total;
}

int recv_n(SSL *ssl, void *buf, int n) {
    int total = 0;
    while (total < n) {
        int ret = SSL_read(ssl, (char*)buf + total, n - total);
        if (ret <= 0) return -1;
        total += ret;
    }
    return total;
}

int send_packet(SSL *ssl, uint16_t opcode, void *payload, uint32_t payload_len) {
    MsgHeader header;
    header.length = payload_len;
    header.opcode = opcode;
    header.checksum = (payload && payload_len > 0) ? calculate_checksum(payload, payload_len) : 0;

    if (send_n(ssl, &header, sizeof(MsgHeader)) < 0) return -1;
    if (payload_len > 0 && payload) {
        if (send_n(ssl, payload, payload_len) < 0) return -1;
    }
    return 0;
}

int recv_packet_header(SSL *ssl, MsgHeader *header) {
    return recv_n(ssl, header, sizeof(MsgHeader));
}