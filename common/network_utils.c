#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "network_utils.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <sys/time.h>

// --- OpenSSL Initialization ---

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

void show_ssl_error(const char *msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
}

// --- Context Creation ---

SSL_CTX* create_server_context(const char *cert_file, const char *key_file) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Use general TLS method (auto-negotiate highest version)
    method = TLS_server_method(); 

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        show_ssl_error("Unable to create SSL context");
        return NULL;
    }

    // Load Server Certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        show_ssl_error("Failed to load certificate file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load Private Key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
        show_ssl_error("Failed to load private key");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify Private Key matches Certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

SSL_CTX* create_client_context(const char *ca_file) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        show_ssl_error("Unable to create SSL context");
        return NULL;
    }

    // If a CA file is provided, load it to verify the server
    if (ca_file) {
        if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
            show_ssl_error("Failed to load CA file");
            SSL_CTX_free(ctx);
            return NULL;
        }
        // Enforce verification
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        // DANGER: No verification (Self-signed certs might need this for testing)
        // In production, always verify!
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

// --- Checksum (Unchanged) ---
uint16_t calculate_checksum(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint16_t checksum = 0;
    for (size_t i = 0; i < len; i++) {
        checksum ^= bytes[i];
        checksum = (checksum << 1) | (checksum >> 15);
    }
    return checksum;
}

// --- Reliable SSL Send ---
int ssl_send_all(SSL *ssl, const void *buf, size_t len) {
    const char *ptr = (const char *)buf;
    size_t total_sent = 0;
    
    while (total_sent < len) {
        // SSL_write works like send(), but handles encryption
        int sent = SSL_write(ssl, ptr + total_sent, len - total_sent);
        
        if (sent <= 0) {
            int err = SSL_get_error(ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                // Non-blocking socket needs to wait, but for blocking socket just retry?
                // For this project (Blocking I/O), this usually implies an issue unless handled carefully.
                // We'll treat it as error for simplicity unless we implement select().
                continue; 
            }
            show_ssl_error("SSL_write error");
            return -1;
        }
        total_sent += sent;
    }
    return 0; // Success
}

// --- Reliable SSL Receive ---
int ssl_recv_all(SSL *ssl, void *buf, size_t len) {
    char *ptr = (char *)buf;
    size_t total_received = 0;

    while (total_received < len) {
        // SSL_read works like recv()
        int received = SSL_read(ssl, ptr + total_received, len - total_received);
        
        if (received <= 0) {
            int err = SSL_get_error(ssl, received);
            if (err == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly by peer (TLS shutdown)
                return -1; 
            }
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            // Real error
            // Don't print error here to avoid spamming logs on client disconnect
            return -1; 
        }
        total_received += received;
    }
    return 0; // Success
}

int connect_to_server_tls(const char *ip, int port, SSL_CTX *ctx, SSL **out_ssl, int *out_sock) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address/ Address not supported \n");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        return -1;
    }

    // SSL Wrap
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        show_ssl_error("SSL_new failed");
        close(sock);
        return -1;
    }
    SSL_set_fd(ssl, sock);

    // SSL Handshake
    if (SSL_connect(ssl) <= 0) {
        // Handshake failed
        SSL_free(ssl);
        close(sock);
        return -1;
    }

    // Return the successful objects
    *out_sock = sock;
    *out_ssl = ssl;
    return 0;
}

void sha256_string(const char *str, char *output) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL) {
        perror("EVP_MD_CTX_new failed");
        return;
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(context);
        return;
    }

    if (EVP_DigestUpdate(context, str, strlen(str)) != 1) {
        EVP_MD_CTX_free(context);
        return;
    }

    if (EVP_DigestFinal_ex(context, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(context);
        return;
    }

    EVP_MD_CTX_free(context);

    // Convert to hex string
    for(unsigned int i = 0; i < length_of_hash; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0; // Null terminator
}

void net_set_timeout(int sockfd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
}

int net_send_packet(SSL *ssl, uint16_t opcode, const void *payload, size_t payload_len) {
    PacketHeader header;
    header.length = sizeof(PacketHeader) + payload_len;
    header.opcode = opcode;

    header.checksum = calculate_checksum(payload, payload_len);

    // send header and payload
    if (ssl_send_all(ssl, &header, sizeof(PacketHeader)) < 0) {
        return -1;
    }

    if (payload_len > 0 && payload != NULL) {
        if (ssl_send_all(ssl, payload, payload_len) < 0) {
            return -1;
        }
    }
    return 0;
}