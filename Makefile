# Makefile
.PHONY: all build clean ebpf generate deps test install fmt lint help

SERVICE_BINARY=kernelgatekeeper-service
CLIENT_BINARY=kernelgatekeeper-client
BPF_C_SRC=$(wildcard pkg/ebpf/bpf/*.c)
BPF_HEADER_DIR=pkg/ebpf/bpf
BPF_OUTPUT_DIR=pkg/ebpf/bpf
CLANG ?= clang
# Update CFLAGS for includes relative to the BPF dir
CFLAGS ?= -O2 -g -Wall -Werror -target bpf -I./ -I/usr/include/bpf -I/usr/include
DESTDIR ?= bin
GO_CMD=go
GOLANGCILINT = $(shell command -v golangci-lint 2> /dev/null)

all: fmt lint test generate build

build: build-service build-client

$(DESTDIR):
	mkdir -p $(DESTDIR)

build-service: $(DESTDIR) generate
	@echo "Building service application..."
	$(GO_CMD) build -ldflags="-s -w" -v -o $(DESTDIR)/$(SERVICE_BINARY) ./cmd/service

build-client: $(DESTDIR)
	@echo "Building client application..."
	$(GO_CMD) build -ldflags="-s -w" -v -o $(DESTDIR)/$(CLIENT_BINARY) ./cmd/client

# generate target now handles BPF compilation via bpf2go
generate: $(BPF_HEADER_DIR)/bpf_shared.h $(BPF_C_SRC)
	@echo "Generating Go wrappers and compiling eBPF C code..."
	$(GO_CMD) generate ./pkg/ebpf/...

# ebpf target is now just a dependency check
ebpf: $(BPF_HEADER_DIR)/bpf_shared.h $(BPF_C_SRC)
	@echo "Ensuring BPF source and header files exist..."
	@if [ ! -f "$(BPF_HEADER_DIR)/bpf_shared.h" ]; then echo "Error: $(BPF_HEADER_DIR)/bpf_shared.h not found"; exit 1; fi
	@if [ -z "$$(ls $(BPF_C_SRC))" ]; then echo "Error: No BPF C source files found in $(BPF_HEADER_DIR)"; exit 1; fi


deps:
	@echo "Tidying dependencies..."
	$(GO_CMD) mod tidy
	$(GO_CMD) mod verify

test:
	@echo "Running tests..."
	$(GO_CMD) test -v -race ./...

fmt:
	@echo "Formatting code..."
	$(GO_CMD) fmt ./...

lint:
ifeq ($(GOLANGCILINT),)
	@echo "Skipping lint: golangci-lint not found."
else
	@echo "Running linter..."
	$(GOLANGCILINT) run ./...
endif

clean:
	@echo "Cleaning up..."
	rm -rf $(DESTDIR)
	rm -f $(BPF_OUTPUT_DIR)/bpf_bpfel.go $(BPF_OUTPUT_DIR)/bpf_bpfeb.go $(BPF_OUTPUT_DIR)/*.o
	$(GO_CMD) clean

install-dirs:
	@echo "Creating installation directories..."
	mkdir -p $(DESTDIR) /etc/kernelgatekeeper /etc/systemd/system /usr/lib/systemd/user /var/log

install: build install-dirs
	@echo "Installing..."
	install -m 755 $(DESTDIR)/$(SERVICE_BINARY) /usr/local/bin/
	install -m 755 $(DESTDIR)/$(CLIENT_BINARY) /usr/local/bin/

	@if [ -f "config.yaml" ]; then \
		if [ ! -f "/etc/kernelgatekeeper/config.yaml" ]; then \
			echo "Installing default config..."; \
			install -m 640 config.yaml /etc/kernelgatekeeper/config.yaml; \
		else \
			echo "Config file /etc/kernelgatekeeper/config.yaml exists, skipping."; \
		fi \
	else \
		echo "Warning: Default config.yaml not found."; \
	fi

	@echo "Installing systemd service files..."
	install -m 644 deploy/kernelgatekeeper.service /etc/systemd/system/
	install -m 644 deploy/kernelgatekeeper-client.service /usr/lib/systemd/user/

	@echo "Setting up log file..."
	touch /var/log/kernelgatekeeper.log
	chmod 640 /var/log/kernelgatekeeper.log
	# Consider chown root:adm /var/log/kernelgatekeeper.log

	@echo "Installation complete!"
	@echo "To enable system service: sudo systemctl daemon-reload && sudo systemctl enable --now kernelgatekeeper.service"
	@echo "To enable user service (run as user): systemctl --user daemon-reload && systemctl --user enable --now kernelgatekeeper-client.service"
	@echo "Check service logs: sudo journalctl -u kernelgatekeeper.service -f"
	@echo "Check client logs: journalctl --user -u kernelgatekeeper-client.service -f"

run-service: build-service
	@echo "Running service application (requires sudo)..."
	sudo ./$(DESTDIR)/$(SERVICE_BINARY) -config=./config.yaml

run-client: build-client
	@echo "Running client application..."
	./$(DESTDIR)/$(CLIENT_BINARY)

help:
	@echo "Makefile Help:"
	@echo "  make all          - Format, lint, test, generate BPF, build Go (default)"
	@echo "  make build        - Build Go applications"
	@echo "  make generate     - Compile BPF C code and generate Go wrappers"
	@echo "  make deps         - Tidy dependencies"
	@echo "  make test         - Run tests"
	@echo "  make fmt          - Format Go code"
	@echo "  make lint         - Run linter"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make install      - Build and install system-wide"
	@echo "  make run-service  - Build and run service (sudo required)"
	@echo "  make run-client   - Build and run client"