# 線上購物系統 (Online Shopping System)

一個基於 C 語言實作的高效能、安全的線上購物系統，採用 Client-Server 架構，支援多使用者並發操作、TLS/SSL 加密通訊、共享記憶體管理等進階技術。

---

## 專案簡介

本專案是一個完整的線上購物系統，展示了系統程式設計的核心技術：
- ✅ **多進程架構 (Preforking Model)**: 伺服器採用 20 個預先 fork 的 worker 進程處理客戶端請求
- ✅ **TLS/SSL 加密通訊**: 所有網路傳輸經過 OpenSSL 加密保護
- ✅ **共享記憶體 (Shared Memory)**: 使用 System V IPC 管理商品庫存
- ✅ **自定義網路協定**: 二進位協定支援 Header + Payload，包含 Checksum 驗證
- ✅ **使用者認證**: 密碼經 SHA-256 雜湊儲存於 SQLite3 資料庫
- ✅ **心跳機制 (Heartbeat)**: 自動偵測連線狀態與防止閒置
- ✅ **壓力測試工具**: 內建併發壓力測試程式，支援效能分析

---

## 系統架構圖

```
┌─────────────────────┐
│   Client (CLI)      │
│  - main_cli.c       │
│  - Heartbeat Thread │
└──────────┬──────────┘
           │ TLS/SSL (Port 8888)
           │
┌──────────▼──────────────────────────────────────┐
│         Server (Preforking Model)                │
│  ┌────────────────────────────────────────────┐ │
│  │  Master Process (main.c)                   │ │
│  │  - Signal Handling                         │ │
│  │  - Resource Initialization                 │ │
│  └──────┬─────────────────────────────────────┘ │
│         │ fork() x 20                           │
│  ┌──────▼─────────────────────────────────────┐ │
│  │  Worker Processes (worker.c)               │ │
│  │  - Accept & SSL_accept                     │ │
│  │  - Handle Client Requests                  │ │
│  └──────┬─────────────────────────────────────┘ │
└─────────┼─────────────────────────────────────┬─┘
          │                                     │
┌─────────▼────────────┐         ┌─────────────▼──────────┐
│  Shared Memory       │         │  SQLite3 Database      │
│  (shm_manager.c)     │         │  (db_manager.c)        │
│  - Item Inventory    │         │  - User Authentication │
│  - Semaphore Lock    │         │  - users table         │
└──────────────────────┘         └────────────────────────┘
```

---

## 功能特色

### 使用者功能
1. **登入系統** (`admin:admin` 或 `user:user`)
2. **瀏覽商品列表** (即時庫存資訊)
3. **購買商品** (自動扣除庫存)
4. **心跳連線維持** (每 10 秒自動發送)

### 管理員功能
5. **新增商品** (Admin Only)
6. **刪除商品** (Admin Only)

### 系統特性
- **並發安全**: Semaphore 保護共享記憶體
- **連線超時**: 25 秒未收到心跳自動斷線
- **防呆機制**: 連續 5 次心跳未購買將被踢出
- **優雅關閉**: Ctrl+C 觸發 SIGINT 正確清理資源

---

## 環境需求

### macOS (Homebrew)
```bash
# 安裝 OpenSSL 與 SQLite3
brew install openssl@3 sqlite3

# 確認安裝路徑 (應為 /opt/homebrew/opt/openssl@3)
brew --prefix openssl@3
```

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install build-essential libssl-dev libsqlite3-dev
```

---

## 快速開始

### 1️⃣ 編譯專案

```bash
# 完整編譯 (包含憑證生成、Server、Client、壓力測試工具)
make all
```

編譯完成後，可執行檔將位於 `bin/` 目錄：
- `bin/server` - 伺服器程式
- `bin/client_app` - 客戶端 CLI
- `bin/stress_tester` - 壓力測試工具

### 2️⃣ 啟動伺服器

```bash
make run-server

# 或直接執行
./bin/server
```

預期輸出：
```
[Master] Server listening on port 8888 with 20 workers
```

### 3️⃣ 啟動客戶端

**開啟新的終端視窗**，執行：

```bash
make run-client

# 或直接執行
./bin/client_app
```

### 4️⃣ 登入與操作

#### 預設帳號
- **管理員**: `admin` / `admin` (擁有新增/刪除商品權限)
- **一般使用者**: `user` / `user` (僅能瀏覽與購買)

#### 操作示範

```
--- User: Guest ---
1. Login
2. List
3. Buy
4. Exit
Select > 1

Enter Username: admin
Enter Password: admin

[✔ Success] Login Success
[System] Admin Privileges Granted.

--- User: admin ---
1. Login
2. List
3. Buy
4. Exit
5. Add
6. Del
Select > 2

=== Product List ===
ID    Name                 Price      Qty
--------------------------------------------
1     Apple                $8         5
2     Banana               $5         10
3     Orange               $2         8
4     Laptop               $5000      10
5     Headphones           $300       25
--------------------------------------------

Select > 3
Enter Item ID to buy: 1
Enter Quantity: 2

[✔ Purchase Successful] Bought Apple x2
```

---

## 壓力測試

### 執行壓力測試

```bash
make run-stress

# 或直接執行
./bin/stress_tester
```

### 測試說明
- **併發連線數**: 100 個執行緒同時連線
- **測試帳號**: `user:user`
- **操作流程**: 登入 → 隨機購買商品 (ID 1~5, 數量 1~3)
- **測量指標**: TPS、成功率、延遲 (平均/最小/最大/P95/P99)

### 範例輸出

```
=== Online Shop Stress Tester (Concurrent Buying) ===
Target: 127.0.0.1:8888
Threads: 100
---------------------------------------------------
[*] Spawning threads...
[Thread 123145441234944] Buying Item ID 3, Qty 2
...

=== Test Results ===
Total Time:      1.234 sec
Throughput:      81.04 TPS (Transactions/sec)
Success Rate:    100.0 %

--- Flow Breakdown ---
Total Completed: 100 (Flow OK)
  -> [Business OK] Bought Item:  87
  -> [Business Fail] Out of Stock: 13
Total Failed:    0 (Network/Crash)

--- Latency Stats (ms) ---
Avg: 15.23 ms
Min: 8.45 ms
Max: 45.67 ms
P95: 28.34 ms (95% requests faster than this)
P99: 38.91 ms (99% requests faster than this)
```

---

## Makefile 指令一覽

| 指令 | 說明 |
|------|------|
| `make all` | 編譯所有模組 (Common、Certs、Server、Client) |
| `make clean` | 清除所有編譯產物與輸出目錄 |
| `make run-server` | 啟動伺服器 |
| `make run-client` | 啟動客戶端 CLI |
| `make run-stress` | 執行壓力測試 |
| `make remove-shm` | 手動移除共享記憶體段 (除錯用) |

---

## 專案結構

```
final_project_online_shopping_system/
│
├── bin/                    # 可執行檔輸出目錄
│   ├── server
│   ├── client_app
│   └── stress_tester
│
├── lib/                    # 靜態函式庫
│   └── libcommon.a
│
├── certs/                  # TLS/SSL 憑證生成
│   ├── Makefile
│   └── out/
│       ├── ca.crt          # CA 根憑證
│       ├── ca.key
│       ├── server.crt      # 伺服器憑證
│       └── server.key
│
├── common/                 # 共用模組
│   ├── protocol.h          # 協定定義 (OpCode、Packet 結構)
│   ├── network_utils.h     # 網路工具函式
│   ├── network_utils.c     # SSL 封裝、SHA-256、Checksum
│   └── Makefile
│
├── server/                 # 伺服器端程式
│   ├── main.c              # 主程式 (Master Process)
│   ├── worker.c            # Worker 處理邏輯
│   ├── worker.h
│   ├── db_manager.c        # SQLite3 資料庫管理
│   ├── db_manager.h
│   ├── shm_manager.c       # 共享記憶體管理
│   ├── shm_manager.h
│   ├── data/               # 資料庫檔案目錄
│   │   └── shop.db         # SQLite3 資料庫
│   └── Makefile
│
├── client/                 # 客戶端程式
│   ├── main_cli.c          # CLI 主程式
│   ├── stress_tester.c     # 壓力測試工具
│   └── Makefile
│
├── Makefile                # 主 Makefile
└── README.md               # 本文件
```

---

## 技術細節

### 網路協定格式

```
Packet Structure:
┌─────────────────────────────────────────┐
│ PacketHeader (8 bytes)                  │
├─────────────┬───────────┬───────────────┤
│ length (4)  │ opcode (2) │ checksum (2) │
├─────────────┴───────────┴───────────────┤
│ Payload (Variable Length)               │
│ - LoginRequest                          │
│ - BuyRequest                            │
│ - ItemInfo[]                            │
│ - BasicResponse                         │
└─────────────────────────────────────────┘
```

### OpCode 定義

| OpCode | 方向 | 說明 |
|--------|------|------|
| `0x0001` | C→S | 登入請求 |
| `0x0002` | S→C | 登入回應 |
| `0x0003` | C→S | 商品列表請求 |
| `0x0004` | S→C | 商品列表回應 |
| `0x0005` | C→S | 購買請求 |
| `0x0006` | S→C | 購買回應 |
| `0x0007` | C→S | 新增商品 (Admin) |
| `0x0008` | C→S | 刪除商品 (Admin) |
| `0x0099` | C↔S | 心跳訊號 |
| `0xFFFF` | S→C | 錯誤訊息 |

### 密碼儲存格式

使用者密碼經過 **SHA-256** 雜湊後儲存於資料庫：

```sql
-- 預設使用者
admin:admin -> 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
user:user   -> 04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb
```

---

## 常見問題 (FAQ)

### Q1: 編譯時出現 `fatal error: openssl/ssl.h: No such file or directory`

**解決方法 (macOS)**:
```bash
# 確認 OpenSSL 安裝路徑
brew --prefix openssl@3

# 若路徑不同，修改 Makefile 中的 OPENSSL_PATH
# 例如: OPENSSL_PATH = /usr/local/opt/openssl@3
```

### Q2: 伺服器關閉後，重新啟動失敗 (`Address already in use`)

**原因**: 共享記憶體段未正確清除

**解決方法**:
```bash
# 手動清除共享記憶體
make remove-shm

# 或手動執行
ipcrm -M 0x1234  # 清除 Shared Memory
ipcrm -S 0x5678  # 清除 Semaphore
```

### Q3: 客戶端連線後無回應

**檢查步驟**:
1. 確認伺服器正在運行
2. 確認憑證檔案存在於 `certs/out/` 目錄
3. 檢查防火牆是否阻擋 Port 8888
4. 查看伺服器終端的錯誤訊息

### Q4: 登入失敗 (`Invalid Credentials`)

**可能原因**:
- 資料庫檔案 `server/data/shop.db` 損壞
- 資料庫連線問題

**解決方法**:
```bash
# 刪除舊資料庫，重新初始化
rm server/data/shop.db
./bin/server  # 重新啟動伺服器會自動建立新資料庫
```

### Q5: 壓力測試出現大量失敗

**可能原因**:
- Worker 進程數量不足 (預設 20)
- 商品庫存耗盡
- 系統資源限制 (檔案描述符上限)

**解決方法**:
```bash
# 增加檔案描述符上限 (macOS)
ulimit -n 4096

# 修改 server/main.c 中的 WORKER_COUNT 增加 worker 數量
```

---

## 除錯與開發

### 編譯單一模組

```bash
make -C common    # 只編譯 common 函式庫
make -C server    # 只編譯 Server
make -C client    # 只編譯 Client
make -C certs     # 只生成憑證
```

### 檢視共享記憶體狀態

```bash
# 列出所有共享記憶體段
ipcs -m

# 列出所有 Semaphore
ipcs -s
```

### 資料庫檢視

```bash
# 使用 SQLite3 命令列工具
sqlite3 server/data/shop.db

sqlite> SELECT * FROM users;
sqlite> .schema users
sqlite> .exit
```

---

## 已知限制

1. **資料庫並發問題**: 目前每個 worker 開啟獨立的 SQLite3 連線，但原始設計存在 `db_init` 立即關閉連線的問題，可能導致登入驗證失敗。(已在 `macos` 分支修復，採用 WAL 模式 + 獨立連線)

2. **商品資料持久化**: 商品資料儲存在共享記憶體，伺服器重啟後會重置為預設的 5 件商品。

3. **單機限制**: 伺服器綁定 `INADDR_ANY`，但客戶端預設連線 `127.0.0.1`，若需遠端連線需修改 `client/main_cli.c` 的 `SERVER_IP`。

4. **密碼明文輸入**: CLI 介面使用 `scanf` 讀取密碼，輸入過程可見。(可使用 `getpass()` 改進)

---

## 授權條款

本專案為教學用途，採用 **MIT License**。

---

## 作者

系統程式設計期末專案 - 2024

---

## 參考資源

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [SQLite3 C API](https://www.sqlite.org/c3ref/intro.html)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [Linux IPC: Shared Memory](https://man7.org/linux/man-pages/man7/shm_overview.7.html)

---

**祝您使用愉快！**

如有任何問題或建議，歡迎開啟 Issue 討論。
