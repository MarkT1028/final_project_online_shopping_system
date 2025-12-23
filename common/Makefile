# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -I.
AR = ar
ARFLAGS = rcs

# !!! LINKER FLAGS for OpenSSL (Needed if we were building an executable here, 
# but for static lib, we just compile object files. 
# The final Server/Client Makefile MUST include -lssl -lcrypto) !!!

# Directories
LIB_DIR = ../lib
OBJ_DIR = obj

# Target Library Name
TARGET = $(LIB_DIR)/libcommon.a

# Source and Object files
SRCS = network_utils.c
OBJS = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS))

# Default Rule
all: create_dirs $(TARGET)

create_dirs:
	mkdir -p $(LIB_DIR) $(OBJ_DIR)

$(TARGET): $(OBJS)
	@echo "Creating static library: $@"
	$(AR) $(ARFLAGS) $@ $^

$(OBJ_DIR)/%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean create_dirs