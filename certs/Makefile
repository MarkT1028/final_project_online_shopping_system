# Output directory for generated files
OUT_DIR = out

# Target file (The final goal)
TARGET = $(OUT_DIR)/server.crt

# Default rule
all: $(TARGET)

# 0. Create the output directory if it doesn't exist
$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# 1. Generate CA Private Key and Certificate
# Output: out/ca.key, out/ca.crt
$(OUT_DIR)/ca.crt: | $(OUT_DIR)
	@echo "Generating CA..."
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout $(OUT_DIR)/ca.key \
		-out $(OUT_DIR)/ca.crt \
		-days 365 \
		-subj "/CN=MyRootCA"

# 2. Generate Server Private Key and CSR
# Output: out/server.key, out/server.csr
$(OUT_DIR)/server.csr: | $(OUT_DIR)
	@echo "Generating Server Key & CSR..."
	openssl req -newkey rsa:2048 -nodes \
		-keyout $(OUT_DIR)/server.key \
		-out $(OUT_DIR)/server.csr \
		-subj "/CN=localhost"

# 3. Sign the Server Certificate using CA
# Input: out/server.csr, out/ca.crt, out/ca.key
# Output: out/server.crt
$(TARGET): $(OUT_DIR)/server.csr $(OUT_DIR)/ca.crt
	@echo "Signing Server Certificate..."
	openssl x509 -req -in $(OUT_DIR)/server.csr \
		-CA $(OUT_DIR)/ca.crt \
		-CAkey $(OUT_DIR)/ca.key \
		-CAcreateserial \
		-out $(TARGET) \
		-days 365
	@echo "Done! Files are in '$(OUT_DIR)/'"

# Clean up the output directory
clean:
	rm -rf $(OUT_DIR)

.PHONY: all clean