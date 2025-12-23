#include "common.h"
#include <pthread.h>
#include <sys/time.h>
#include <openssl/err.h>

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_ctx() {
    return SSL_CTX_new(TLS_client_method());
}

// --- Stress Test Stats ---
typedef struct {
    int id;
    int success;
    int fail;
    double latency_sum;
    int fail_hb;      // Heartbeat 失敗 (Server 死掉)
} ThreadStats;

void *stress_task(void *arg) {
    ThreadStats *stats = (ThreadStats*)arg;
    SSL_CTX *ctx = create_ctx();
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    // [修正] 使用 memset 歸零，再逐一賦值，解決 macOS 結構相容性問題
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) > 0) {
            for(int k=0; k<10; k++) { // 每個 thread 買 10 次

                if (k % 2 == 0) {
                    if (send_packet(ssl, OP_HEARTBEAT, NULL, 0) < 0) {
                        printf("[Thread %d] Heartbeat Send Failed!\n", stats->id);
                        stats->fail_hb++; break;
                    }
                MsgHeader hb_h;
                    if (recv_packet_header(ssl, &hb_h) < 0 || hb_h.opcode != OP_HEARTBEAT) {
                        printf("[Thread %d] Heartbeat No Response (Server Dead?)\n", stats->id);
                        stats->fail_hb++; break;
                    }
                }

                PayloadBuy req = {0, 1}; // Buy product 0
                struct timeval start, end;
                gettimeofday(&start, NULL);
                
                send_packet(ssl, OP_BUY_ITEM, &req, sizeof(req));
                MsgHeader h; recv_packet_header(ssl, &h);
                PayloadResponse r; recv_n(ssl, &r, h.length);
                
                gettimeofday(&end, NULL);
                stats->latency_sum += (end.tv_sec - start.tv_sec)*1000.0 + (end.tv_usec - start.tv_usec)/1000.0;
                
                if(r.status == 0) stats->success++; else stats->fail++;
            }
        }
        SSL_shutdown(ssl); SSL_free(ssl);
    }
    close(sock); SSL_CTX_free(ctx);
    return NULL;
}

void run_stress_test() {
    int T = 100; // 100 threads
    pthread_t threads[T];
    ThreadStats stats[T];
    struct timeval t1, t2;
    
    printf("Starting Stress Test (100 threads)...\n");
    gettimeofday(&t1, NULL);
    
    for(int i=0; i<T; i++) {
        // [修正] 這裡也使用明確初始化，避免警告
        stats[i].id = i;
        stats[i].success = 0;
        stats[i].fail = 0;
        stats[i].latency_sum = 0.0;
        pthread_create(&threads[i], NULL, stress_task, &stats[i]);
    }
    
    int total_ok=0, total_fail=0;
    double total_lat=0;
    for(int i=0; i<T; i++) {
        pthread_join(threads[i], NULL);
        total_ok += stats[i].success;
        total_fail += stats[i].fail;
        total_lat += stats[i].latency_sum;
    }
    
    gettimeofday(&t2, NULL);
    double duration = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec)/1000000.0;
    
    printf("=== Report ===\nTime: %.2fs\nOK: %d, Fail: %d\nAvg Latency: %.2f ms\nTPS: %.2f\n",
           duration, total_ok, total_fail, 
           (total_ok+total_fail > 0) ? total_lat/(total_ok+total_fail) : 0, 
           (duration > 0) ? (total_ok+total_fail)/duration : 0);
}

void interactive_mode() {
    SSL_CTX *ctx = create_ctx();
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    // [修正] 使用 memset 歸零，再逐一賦值
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) { 
        perror("Connect failed"); 
        return; 
    }
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    
    // [修正] 增加連線錯誤檢查
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }
    
    printf("Connected. 1:List, 2:Buy, 3:Exit\n");
    while(1) {
        printf("> "); 
        int c; 
        if (scanf("%d", &c) != 1) break; // [修正] 防止輸入非數字導致無限迴圈
        
        if (c==3) break;
        if (c==1) {
            send_packet(ssl, OP_LIST_ITEMS, NULL, 0);
            MsgHeader h; 
            if (recv_packet_header(ssl, &h) < 0) break;
            SharedData d; 
            recv_n(ssl, &d, h.length);
            for(int i=0; i<d.product_count; i++) 
                printf("#%d %s Stock:%d\n", d.products[i].id, d.products[i].name, d.products[i].stock);
        }
        if (c==2) {
            int pid; 
            printf("PID: "); scanf("%d", &pid);
            PayloadBuy req = {pid, 1};
            send_packet(ssl, OP_BUY_ITEM, &req, sizeof(req));
            MsgHeader h; 
            if (recv_packet_header(ssl, &h) < 0) break;
            PayloadResponse r; 
            recv_n(ssl, &r, h.length);
            printf("[%s] %s\n", r.status==0?"OK":"ERR", r.message);
        }
    }
    SSL_shutdown(ssl); close(sock); SSL_CTX_free(ctx);
}

int main(int argc, char **argv) {
    init_openssl();
    if(argc>1 && strcmp(argv[1], "stress")==0) run_stress_test();
    else interactive_mode();
}