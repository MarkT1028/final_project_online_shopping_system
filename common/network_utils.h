#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "protocol.h"

/**
 * @brief Initialize OpenSSL library (Load algorithms, error strings).
 * Call this once at the beginning of the program.
 */
void init_openssl();

/**
 * @brief Create and configure an SSL Context for the SERVER.
 * * @param cert_file Path to the server's certificate file (.crt).
 * @param key_file Path to the server's private key file (.key).
 * @return SSL_CTX* Pointer to the created context, or NULL on failure.
 */
SSL_CTX* create_server_context(const char *cert_file, const char *key_file);

/**
 * @brief Create and configure an SSL Context for the CLIENT.
 * * @param ca_file Path to the CA certificate to verify the server (optional, can be NULL).
 * @return SSL_CTX* Pointer to the created context, or NULL on failure.
 */
SSL_CTX* create_client_context(const char *ca_file);

/**
 * @brief Cleanup OpenSSL resources.
 */
void cleanup_openssl();

/**
 * @brief Calculates a simple XOR checksum (Same as before).
 */
uint16_t calculate_checksum(const void *data, size_t len);

/**
 * @brief Securely sends exact number of bytes over TLS.
 * Handles partial writes internally using SSL_write.
 * * @param ssl Pointer to the SSL structure.
 * @param buf Pointer to data to send.
 * @param len Number of bytes to send.
 * @return int 0 on success, -1 on failure.
 */
int ssl_send_all(SSL *ssl, const void *buf, size_t len);

/**
 * @brief Securely receives exact number of bytes over TLS.
 * Loops until all requested bytes are read using SSL_read.
 * * @param ssl Pointer to the SSL structure.
 * @param buf Buffer to store received data.
 * @param len Number of bytes expected.
 * @return int 0 on success, -1 on failure/closed connection.
 */
int ssl_recv_all(SSL *ssl, void *buf, size_t len);

/**
 * @brief Helper to print OpenSSL errors to stderr.
 * @param msg Custom message to prefix the error log.
 */
void show_ssl_error(const char *msg);

/**
 * @brief Establishes a TCP connection and performs TLS handshake.
 * * @param ip Server IP address (e.g., "127.0.0.1")
 * @param port Server Port (e.g., 8888)
 * @param ctx Initialized SSL_CTX
 * @param out_ssl Pointer to store the resulting SSL structure
 * @param out_sock Pointer to store the resulting socket FD
 * @return int 0 on success, -1 on failure
 */
int connect_to_server_tls(const char *ip, int port, SSL_CTX *ctx, SSL **out_ssl, int *out_sock);


/**
 * @brief Computes SHA-256 hash of a string.
 * @param str Input string (null-terminated).
 * @param output Buffer to store the hex string (must be at least 65 bytes).
 */
void sha256_string(const char *str, char *output);

/**
 * @brief Set socket receive timeout.
 */
void net_set_timeout(int sockfd, int seconds);

/**
 * @brief automatically send a packet with header and payload over SSL.
 * @param ssl Pointer to the SSL structure
 * @param opcode operation code
 * @param payload Pointer to the data to send (can be NULL if payload_len is 0)
 * @param payload_len Length of the payload in bytes (can be 0)
 * @return 0 on success, -1 on failure
 */
int net_send_packet(SSL *ssl, uint16_t opcode, const void *payload, size_t payload_len);

#endif