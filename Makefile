CC = gcc
# 自動偵測 OpenSSL 與 SQLite 的路徑 (Homebrew)
OPENSSL_DIR = $(shell brew --prefix openssl)
SQLITE_DIR = $(shell brew --prefix sqlite)

# 在 CFLAGS 加入 -I (Include Path)
CFLAGS = -Wall -g -pthread -I$(OPENSSL_DIR)/include -I$(SQLITE_DIR)/include

# 在 LDFLAGS 加入 -L (Library Path)
LDFLAGS = -L$(OPENSSL_DIR)/lib -L$(SQLITE_DIR)/lib -lssl -lcrypto -lsqlite3

# 目標檔案 (.o)
OBJS = server_main.o master.o worker.o common.o

# 主要目標
all: server client

# 編譯 Server
server: $(OBJS)
	$(CC) $(CFLAGS) -o server $(OBJS) $(LDFLAGS)

# 編譯 Client
client: client.c common.o
	$(CC) $(CFLAGS) -o client client.c common.o $(LDFLAGS)

# 個別模組編譯
server_main.o: server_main.c master.h
	$(CC) $(CFLAGS) -c server_main.c

master.o: master.c master.h worker.h common.h
	$(CC) $(CFLAGS) -c master.c

worker.o: worker.c worker.h common.h
	$(CC) $(CFLAGS) -c worker.c

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c

# 自動產生測試憑證
certs:
	mkdir -p certs
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout certs/server.key -out certs/server.crt \
		-subj "/C=TW/ST=Taipei/L=Daan/O=MySchool/CN=localhost" 2>/dev/null

clean:
	rm -f server client *.o
	rm -rf certs