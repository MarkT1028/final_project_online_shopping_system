#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <signal.h>
#include "../common/network_utils.h"
#include "../common/protocol.h"

// Stress Test Configuration
#define THREAD_COUNT 100 
#define SERVER_IP "127.0.0.1"
#define CA_CERT_FILE "certs/out/ca.crt"

#define TEST_USER "user"
#define TEST_PASS "user"

// --- Shared Statistics ---
long total_success = 0;
long failed_requests = 0;
long items_bought = 0;
long out_of_stock = 0;
double total_latency_ms = 0;

double latency_samples[THREAD_COUNT]; 

pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

SSL_CTX *ctx = NULL;

// Helper: Get current time in milliseconds
double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

// Helper: qsort comparison function
int compare_doubles(const void *a, const void *b) {
    double arg1 = *(const double *)a;
    double arg2 = *(const double *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

// Helper: Receive packet
int recv_packet(SSL *ssl, void *buf, int max_len) {
    PacketHeader header;
    if (ssl_recv_all(ssl, &header, sizeof(PacketHeader)) < 0) return -1;
    
    int payload_len = header.length - sizeof(PacketHeader);
    if (payload_len > 0) {
        if (payload_len > max_len) return -1;
        if (ssl_recv_all(ssl, buf, payload_len) < 0) return -1;
    }
    return header.opcode;
}

// Worker Thread Function
void *stress_worker(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)pthread_self(); 
    int sock = -1;
    SSL *ssl = NULL;
    int success_flow = 0;
    int buy_status = -1;
    double start = get_time_ms();

    if (connect_to_server_tls(SERVER_IP, PORT, ctx, &ssl, &sock) < 0) {
        pthread_mutex_lock(&stats_lock);
        failed_requests++;
        pthread_mutex_unlock(&stats_lock);
        return NULL;
    }

    BasicResponse resp;

    // LOGIN
    LoginRequest login_req;
    memset(&login_req, 0, sizeof(login_req));
    strncpy(login_req.username, TEST_USER, MAX_NAME_LEN - 1);
    sha256_string(TEST_PASS, login_req.password_hash);

    if (net_send_packet(ssl, OP_LOGIN_REQ, &login_req, sizeof(LoginRequest)) == 0) {
        if (recv_packet(ssl, &resp, sizeof(BasicResponse)) == OP_LOGIN_RESP) {
            if (resp.status == 0) {
                // BUY
                int item_id = (rand_r(&seed) % 5) + 1; 
                int quantity = (rand_r(&seed) % 3) + 1;
                BuyRequest buy_req = {item_id, quantity};
                printf("[Thread %lu] Buying Item ID %d, Qty %d\n", pthread_self(), item_id, quantity);

                if (net_send_packet(ssl, OP_BUY_REQ, &buy_req, sizeof(BuyRequest)) == 0) {
                    if (recv_packet(ssl, &resp, sizeof(BasicResponse)) == OP_BUY_RESP) {
                        success_flow = 1; 
                        buy_status = resp.status;
                    }
                }
            }
        }
    }

    double end = get_time_ms();
    double latency = end - start;

    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (sock >= 0) close(sock);

    pthread_mutex_lock(&stats_lock);
    if (success_flow) {
        latency_samples[total_success] = latency;
        total_success++;
        total_latency_ms += latency;

        if (buy_status == 0) {
            items_bought++;
        } else {
            out_of_stock++;
        }
    } else {
        failed_requests++;
    }
    pthread_mutex_unlock(&stats_lock);

    return NULL;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL)); // Init Random

    printf("=== Online Shop Stress Tester (Concurrent Buying) ===\n");
    printf("Target: %s:%d\n", SERVER_IP, PORT);
    printf("Threads: %d\n", THREAD_COUNT);
    printf("---------------------------------------------------\n");

    init_openssl();
    ctx = create_client_context(CA_CERT_FILE);
    if (!ctx) exit(EXIT_FAILURE);

    pthread_t threads[THREAD_COUNT];
    double start_time = get_time_ms();

    printf("[*] Spawning threads...\n");
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, stress_worker, NULL);
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    double end_time = get_time_ms();
    double duration_sec = (end_time - start_time) / 1000.0;

    // --- 計算統計數據 ---
    double p95 = 0, p99 = 0, max_lat = 0, min_lat = 0;
    
    if (total_success > 0) {
        // 排序延遲數據
        qsort(latency_samples, total_success, sizeof(double), compare_doubles);
        
        min_lat = latency_samples[0];
        max_lat = latency_samples[total_success - 1];
        
        // 計算索引
        int idx_p95 = (int)(total_success * 0.95);
        int idx_p99 = (int)(total_success * 0.99);
        if (idx_p95 >= total_success) idx_p95 = total_success - 1;
        if (idx_p99 >= total_success) idx_p99 = total_success - 1;
        
        p95 = latency_samples[idx_p95];
        p99 = latency_samples[idx_p99];
    }

    printf("\n=== Test Results ===\n");
    printf("Total Time:      %.3f sec\n", duration_sec);
    printf("Throughput:      %.2f TPS (Transactions/sec)\n", total_success / duration_sec);
    printf("Success Rate:    %.1f %%\n", (double)total_success / THREAD_COUNT * 100.0);
    printf("\n--- Flow Breakdown ---\n");
    printf("Total Completed: %ld (Flow OK)\n", total_success);
    printf("  -> [Business OK] Bought Item:  %ld\n", items_bought);
    printf("  -> [Business Fail] Out of Stock: %ld\n", out_of_stock);
    printf("Total Failed:    %ld (Network/Crash)\n", failed_requests);
    
    if (total_success > 0) {
        printf("\n--- Latency Stats (ms) ---\n");
        printf("Avg: %.2f ms\n", total_latency_ms / total_success);
        printf("Min: %.2f ms\n", min_lat);
        printf("Max: %.2f ms\n", max_lat);
        printf("P95: %.2f ms (95%% requests faster than this)\n", p95);
        printf("P99: %.2f ms (99%% requests faster than this)\n", p99);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}