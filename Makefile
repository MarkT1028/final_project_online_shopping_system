# --- Master Makefile for Online Shopping System ---

.PHONY: all clean common certs server client run-server run-client run-stress

all: common certs server client
	@echo "=========================================="
	@echo " Build Complete! "
	@echo " Executables are in 'bin/' directory."
	@echo "=========================================="

common:
	@echo ">>> Building Common Library..."
	$(MAKE) -C common

certs:
	@echo ">>> Checking/Generating Certificates..."
	$(MAKE) -C certs

server: common
	@echo ">>> Building Server..."
	$(MAKE) -C server

client: common
	@echo ">>> Building Client Apps..."
	$(MAKE) -C client

clean:
	@echo ">>> Cleaning Everything..."
	$(MAKE) -C common clean
	$(MAKE) -C certs clean
	$(MAKE) -C server clean
	$(MAKE) -C client clean
	rm -rf bin lib
	@echo ">>> Clean complete."


run-server: server
	@echo ">>> Starting Server..."
	./bin/server

run-client: client
	@echo ">>> Starting Client CLI..."
	./bin/client_app

run-stress: client
	@echo ">>> Starting Stress Tester..."
	./bin/stress_tester

remove-shm:
	@echo ">>> Removing Shared Memory Segments..."
	ipcrm -M 0x1234 || true
	ipcrm -S 0x5678 || true
	@echo ">>> Shared Memory Segments Removed."