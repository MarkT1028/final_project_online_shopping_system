# 線上購物系統 - 期末專案報告（精簡版）

**學期**: 2024 Fall | **日期**: 2024/12/24

---

## 一、專案概述

本專案實作了一個基於 C 語言的高效能線上購物系統，採用 **Client-Server 架構**，整合了系統程式設計的核心技術。

### 核心技術棧
- **多進程架構**: Preforking Model (20 Worker Processes)
- **加密通訊**: TLS/SSL (OpenSSL)
- **進程間通訊**: System V Shared Memory + Semaphore
- **資料庫**: SQLite3 (使用者認證)
- **多執行緒**: Pthread (客戶端心跳機制)
- **自定義協定**: Binary Protocol (Header + Payload)

---

## 二、系統架構

```
┌─────────────┐
│   Client    │ ← Heartbeat Thread (每 10 秒)
└──────┬──────┘
       │ TLS/SSL (Port 8888)
       │
┌──────▼───────────────────────────────┐
│  Master Process                      │
│  - Signal Handling (SIGINT)          │
│  - Resource Initialization           │
└──────┬───────────────────────────────┘
       │ fork() × 20
┌──────▼───────────────────────────────┐
│  Worker Processes × 20               │
│  - accept() & SSL_accept()           │
│  - Handle Client Requests            │
│  - Per-Worker DB Connection          │
└──────┬───────────────┬───────────────┘
       │               │
   ┌───▼────┐    ┌─────▼─────┐
   │Shared  │    │SQLite3 DB │
   │Memory  │    │(users)    │
   │+Sem    │    └───────────┘
   └────────┘
```

---

## 三、核心功能實作

### 3.1 網路協定設計

**封包格式**:
```c
PacketHeader (8 bytes):
  - length (4 bytes):   封包總長度
  - opcode (2 bytes):   操作碼
  - checksum (2 bytes): XOR 校驗和
```

**主要 OpCode**:
- `0x0001` - 登入請求
- `0x0003` - 商品列表請求
- `0x0005` - 購買請求
- `0x0007/0x0008` - 新增/刪除商品 (Admin)
- `0x0099` - 心跳訊號

### 3.2 安全機制

1. **TLS/SSL 加密**: 所有網路傳輸經 OpenSSL 加密
2. **密碼雜湊**: SHA-256 雜湊儲存
3. **防 SQL Injection**: Prepared Statement
4. **連線超時**: 25 秒未收到心跳自動斷線

### 3.3 併發控制

```c
// 使用 Semaphore 保護共享記憶體
shm_lock();    // P Operation
// ... 修改商品庫存 ...
shm_unlock();  // V Operation
```

**關鍵設計**:
- Binary Semaphore (初始值 = 1)
- Critical Section 最小化
- 每個 Worker 獨立 DB 連線

---

## 四、測試結果

### 壓力測試 (100 併發連線)

| 指標 | 結果 | 說明 |
|------|------|------|
| **TPS** | 81.04 | 每秒處理交易數 |
| **成功率** | 100% | 無網路錯誤或 Crash |
| **平均延遲** | 15.23 ms | 表現良好 |
| **P95 延遲** | 28.34 ms | 95% 請求完成時間 |
| **P99 延遲** | 38.91 ms | 99% 請求完成時間 |

**結論**: 系統在高併發負載下表現穩定，無 Race Condition。

---

## 五、關鍵問題與解決

### 問題 1: macOS OpenSSL 路徑
**解決**: 在 Makefile 加入 Homebrew OpenSSL 路徑
```makefile
OPENSSL_PATH = /opt/homebrew/opt/openssl@3
CFLAGS += -I$(OPENSSL_PATH)/include
LIBS += -L$(OPENSSL_PATH)/lib
```

### 問題 2: SQLite3 登入失敗
**根本原因**: SQLite3 連線不能跨 `fork()` 共享

**解決方案** (macos 分支):
1. 移除主程序的 `db_init()` 呼叫
2. 每個 Worker 在 `worker_loop()` 開啟獨立連線
3. 啟用 WAL 模式提升並發效能

```c
// server/worker.c
void worker_loop(int server_fd, SSL_CTX *ctx) {
    sqlite3 *worker_db = NULL;
    sqlite3_open(DB_FILE, &worker_db);  // 獨立連線
    // ... 處理客戶端 ...
}
```

---

## 六、技術亮點

### 6.1 Preforking 架構優勢
- ✅ 減少 `fork()` 開銷
- ✅ 作業系統自動負載平衡
- ✅ Worker 隔離，提升穩定性

### 6.2 心跳機制 (Heartbeat)
- **客戶端**: Pthread 每 10 秒發送 `OP_HEARTBEAT`
- **伺服器**: 超過 25 秒無回應 → 斷線
- **防呆**: 連續 5 次心跳未購買 → 踢出

### 6.3 資料持久化
- **使用者資料**: SQLite3 (支援新增帳號)
- **商品庫存**: Shared Memory (重啟會重置)

---

## 七、效能優化方向

| 優化項目 | 當前狀態 | 改進方案 |
|---------|---------|---------|
| **鎖粒度** | 整個 SharedData 一個鎖 | Per-Item 細粒度鎖 |
| **資料庫** | 預設模式 | WAL 模式 (macos 分支已實作) |
| **連線** | 短連線 | 連線池 (避免重複 TLS Handshake) |
| **架構** | Multi-Process | Event-Driven (epoll/kqueue) |

---

## 八、開發心得

### 技術收穫
1. **系統程式設計**: 深入理解多進程架構、IPC、Signal 處理
2. **網路程式設計**: 熟悉 Socket API、TLS/SSL、二進位協定設計
3. **併發控制**: 實際處理 Race Condition、Deadlock 預防
4. **除錯技巧**: 多進程環境下的系統性除錯方法

### 最大挑戰
**SQLite3 跨進程問題**: 花費最多時間，最終透過建立獨立測試程式、參考社群資源找到根本原因。

**最大收穫**: 「紙上得來終覺淺，絕知此事要躬行」—— 只有親手實作、除錯，才能真正掌握系統程式設計的精髓。

---

## 九、快速開始

```bash
# 1. 編譯
make all

# 2. 啟動伺服器
make run-server

# 3. 啟動客戶端 (新終端)
make run-client

# 4. 登入測試
Username: admin
Password: admin

# 5. 壓力測試
make run-stress
```

---

## 十、檔案結構

```
final_project_online_shopping_system/
├── common/          # 共用函式庫 (network_utils, protocol)
├── server/          # 伺服器 (main, worker, db_manager, shm_manager)
├── client/          # 客戶端 (main_cli, stress_tester)
├── certs/           # TLS/SSL 憑證生成
├── bin/             # 可執行檔
├── Makefile         # 主 Makefile
├── README.md        # 使用者手冊
└── REPORT.md        # 完整技術報告
```

---

## 附錄：預設帳號

| 使用者 | 密碼 | 權限 |
|--------|------|------|
| admin | admin | 管理員 (可新增/刪除商品) |
| user | user | 一般使用者 (瀏覽/購買) |

---

**報告完成**: 2024/12/24  
**總程式碼行數**: ~1,500 行 (不含註解)  
**測試通過**: ✅ 功能測試 | ✅ 壓力測試 | ✅ 併發安全性測試

---

**[精簡版報告結束]**

完整技術細節請參閱 `REPORT.md`

