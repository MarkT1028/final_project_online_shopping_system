# Compiler and Flags
CC = gcc
# macOS OpenSSL path
OPENSSL_PATH = /opt/homebrew/opt/openssl@3
CFLAGS = -Wall -Wextra -g -I../common -I$(OPENSSL_PATH)/include
# Links against common lib, SSL, and Pthread
LIBS = -L../lib -L$(OPENSSL_PATH)/lib -lcommon -lssl -lcrypto -lpthread

# Directories
BIN_DIR = ../bin
OBJ_DIR = obj

# Targets
TARGET_CLI = $(BIN_DIR)/client_app
TARGET_STRESS = $(BIN_DIR)/stress_tester

# Source files
SRCS = main_cli.c stress_tester.c
OBJS = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS))

# Default Rule
all: create_dirs $(TARGET_CLI) $(TARGET_STRESS)

create_dirs:
	mkdir -p $(BIN_DIR) $(OBJ_DIR)

# Link CLI App
$(TARGET_CLI): $(OBJ_DIR)/main_cli.o
	@echo "Linking Client App..."
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Link Stress Tester
$(TARGET_STRESS): $(OBJ_DIR)/stress_tester.o
	@echo "Linking Stress Tester..."
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Compile Objects
$(OBJ_DIR)/%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET_CLI) $(TARGET_STRESS)

.PHONY: all clean create_dirs