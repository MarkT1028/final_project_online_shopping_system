# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -g -I../common
LIBS = -L../lib -lcommon -lssl -lcrypto -lsqlite3 -lpthread

# Directories
BIN_DIR = ../bin
OBJ_DIR = obj
DATA_DIR = data

# Output binary
TARGET = $(BIN_DIR)/server

# Source files
SRCS = main.c worker.c db_manager.c shm_manager.c
OBJS = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS))

# Default Rule
all: create_dirs $(TARGET)

# Create Output Directories
create_dirs:
	mkdir -p $(BIN_DIR) $(OBJ_DIR) $(DATA_DIR)

# Link Object files into Executable
$(TARGET): $(OBJS)
	@echo "Linking server..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Compile Source files into Object files
$(OBJ_DIR)/%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean create_dirs