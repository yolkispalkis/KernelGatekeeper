# Makefile
.PHONY: all build clean ebpf generate deps test install fmt lint help deb

# --- Переменные ---
SERVICE_BINARY=kernelgatekeeper-service
CLIENT_BINARY=kernelgatekeeper-client
VERSION ?= 0.1.0
ARCH ?= $(shell dpkg --print-architecture)
DEB_ROOT=debian_pkg
DEB_PACKAGE_NAME=kernelgatekeeper
DEB_FILENAME=$(DEB_PACKAGE_NAME)_$(VERSION)_$(ARCH).deb
# Путь к исходным файлам для DEB
DEB_SCRIPTS_SRC=deploy/debian_scripts

# BPF related
BPF_C_SRC=$(wildcard pkg/ebpf/bpf/*.c)
BPF_HEADER_DIR=pkg/ebpf/bpf
# Output files go directly into pkg/ebpf/ by bpf2go
CLANG ?= clang
# Include local bpf dir and system bpf include dir
# Remove -I/usr/include if it causes issues, usually not needed for standard headers
CFLAGS ?= -O2 -g -Wall -Werror -target bpf -DDEBUG -I./pkg/ebpf/bpf -I/usr/include/bpf
DESTDIR ?= bin
GO_CMD=go
GOLANGCILINT = $(shell command -v golangci-lint 2> /dev/null)

# --- Основные цели ---
all: fmt lint test generate build

build: build-service build-client

$(DESTDIR):
	mkdir -p $(DESTDIR)

build-service: $(DESTDIR) generate
	@echo "Building service application..."
	$(GO_CMD) build -ldflags="-s -w" -v -o $(DESTDIR)/$(SERVICE_BINARY) ./cmd/service

build-client: $(DESTDIR) generate
	@echo "Building client application..."
	$(GO_CMD) build -ldflags="-s -w" -v -o $(DESTDIR)/$(CLIENT_BINARY) ./cmd/client

# generate target depends on source files to ensure regeneration if they change.
# Ensure all relevant C and Go files influencing generation are listed.
generate: $(BPF_HEADER_DIR)/bpf_shared.h $(BPF_C_SRC) pkg/ebpf/program.go
	@echo "Generating Go wrappers and compiling eBPF C code (via go generate)..."
	$(GO_CMD) generate ./pkg/ebpf/...

# --- Вспомогательные цели ---
deps:
	@echo "Tidying dependencies..."
	$(GO_CMD) mod tidy
	$(GO_CMD) mod verify

test: generate # Ensure BPF code is generated before running tests that might use it
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

# MODIFIED clean target to include all generated BPF Go files
clean:
	@echo "Cleaning up..."
	rm -rf $(DESTDIR) $(DEB_ROOT) $(DEB_FILENAME)
	# Remove generated Go files and BPF object files from pkg/ebpf/
	rm -f pkg/ebpf/bpf_connect4_bpf.go pkg/ebpf/bpf_skmsg_bpf.go pkg/ebpf/bpf_sockops_bpf.go pkg/ebpf/*.o
	$(GO_CMD) clean

# --- Установка (ручная, для разработки) ---
install: build
	@echo "Manual installation (for development)..."
	sudo install -D -m 755 $(DESTDIR)/$(SERVICE_BINARY) /usr/local/bin/
	sudo install -D -m 755 $(DESTDIR)/$(CLIENT_BINARY) /usr/local/bin/
	# Install config if not exists
	sudo install -D -m 640 config.yaml /etc/kernelgatekeeper/config.yaml || echo "Config exists, skipping"
	sudo install -D -m 644 deploy/kernelgatekeeper.service /etc/systemd/system/
	sudo install -D -m 644 deploy/kernelgatekeeper-client.service /usr/lib/systemd/user/
	# Create log file with permissions
	sudo touch /var/log/kernelgatekeeper.log
	sudo chmod 640 /var/log/kernelgatekeeper.log
	# Consider chown root:adm /var/log/kernelgatekeeper.log
	@echo "Manual installation complete! Reload systemd:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  systemctl --user daemon-reload"
	@echo "Then enable services:"
	@echo "  sudo systemctl enable --now kernelgatekeeper.service"
	@echo "  systemctl --user enable --now kernelgatekeeper-client.service"


# --- Сборка DEB пакета ---
deb: clean generate build # Ensure generate runs before build for deb
	@echo "Building DEB package..."
	# --- Создание каталогов ---
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/local/bin
	mkdir -p $(DEB_ROOT)/etc/kernelgatekeeper
	mkdir -p $(DEB_ROOT)/etc/systemd/system
	mkdir -p $(DEB_ROOT)/usr/lib/systemd/user
	mkdir -p $(DEB_ROOT)/var/log
	mkdir -p $(DEB_ROOT)/etc/profile.d

	# --- Копирование файлов приложения ---
	cp $(DESTDIR)/$(SERVICE_BINARY) $(DEB_ROOT)/usr/local/bin/
	cp $(DESTDIR)/$(CLIENT_BINARY) $(DEB_ROOT)/usr/local/bin/
	cp config.yaml $(DEB_ROOT)/etc/kernelgatekeeper/config.yaml.example # Install as example, postinst copies if main is missing
	cp deploy/kernelgatekeeper.service $(DEB_ROOT)/etc/systemd/system/
	cp deploy/kernelgatekeeper-client.service $(DEB_ROOT)/usr/lib/systemd/user/

	# --- Копирование скриптов пакета ---
	cp $(DEB_SCRIPTS_SRC)/conffiles $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/postinst $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/prerm $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/postrm $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/99-kernelgatekeeper-client-enabler.sh $(DEB_ROOT)/etc/profile.d/

	# --- Генерация DEBIAN/control (с переменными) ---
	@echo "Generating DEBIAN/control..."
	@echo "Package: $(DEB_PACKAGE_NAME)" > $(DEB_ROOT)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Section: net" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Architecture: $(ARCH)" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Depends: libc6, adduser" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Maintainer: Karim Zabbarov <me@w3h.su>" >> $(DEB_ROOT)/DEBIAN/control # Update maintainer if needed
	@echo "Description: Transparent Kerberos proxy using eBPF sockops." >> $(DEB_ROOT)/DEBIAN/control
	@echo " Provides transparent proxying for user applications by leveraging" >> $(DEB_ROOT)/DEBIAN/control
	@echo " eBPF connect4/sockops/skmsg hooks to redirect traffic and performing Kerberos" >> $(DEB_ROOT)/DEBIAN/control # Updated description slightly
	@echo " authentication via a user-specific client process." >> $(DEB_ROOT)/DEBIAN/control

	# --- Установка прав на выполнение ---
	@echo "Setting script permissions..."
	chmod +x $(DEB_ROOT)/DEBIAN/postinst $(DEB_ROOT)/DEBIAN/prerm $(DEB_ROOT)/DEBIAN/postrm
	chmod 755 $(DEB_ROOT)/etc/profile.d/99-kernelgatekeeper-client-enabler.sh

	# --- Сборка пакета ---
	@echo "Building the package..."
	dpkg-deb --build $(DEB_ROOT) $(DEB_FILENAME)
	@echo "DEB package created: $(DEB_FILENAME)"

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
	@echo "  make generate     - Compile BPF C code and generate Go wrappers (via go generate)"
	@echo "  make deps         - Tidy dependencies"
	@echo "  make test         - Run tests"
	@echo "  make fmt          - Format Go code"
	@echo "  make lint         - Run linter"
	@echo "  make clean        - Remove build artifacts, generated BPF files, and deb package"
	@echo "  make install      - Manual installation (for development)"
	@echo "  make deb          - Build the Debian (.deb) package"
	@echo "  make run-service  - Build and run service (sudo required)"
	@echo "  make run-client   - Build and run client"
	@echo "  make help         - Show this help message"