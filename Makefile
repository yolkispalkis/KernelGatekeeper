.PHONY: all build clean generate deps test install fmt lint help deb

SERVICE_BINARY=kernelgatekeeper-service
CLIENT_BINARY=kernelgatekeeper-client
VERSION ?= 0.1.1
ARCH ?= $(shell dpkg --print-architecture)
DEB_ROOT=debian_pkg
DEB_PACKAGE_NAME=kernelgatekeeper
DEB_FILENAME=$(DEB_PACKAGE_NAME)_$(VERSION)_$(ARCH).deb
DEB_SCRIPTS_SRC=deploy/debian_scripts

BPF_C_SRC=$(wildcard pkg/ebpf/bpf/*.c)
BPF_HEADER_DIR=pkg/ebpf/bpf
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror -target bpf -DDEBUG -I./pkg/ebpf/bpf -I/usr/include/bpf
DESTDIR ?= bin
GO_CMD=go
GOLANGCILINT = $(shell command -v golangci-lint 2> /dev/null)

all: fmt lint test generate build

build: build-service build-client

$(DESTDIR):
	mkdir -p $(DESTDIR)

build-service: $(DESTDIR) generate
	@echo "Building service application..."
	$(GO_CMD) build -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD || echo 'unknown') -X main.date=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')" -v -o $(DESTDIR)/$(SERVICE_BINARY) ./cmd/service

build-client: $(DESTDIR) generate
	@echo "Building client application..."
	$(GO_CMD) build -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD || echo 'unknown') -X main.date=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')" -v -o $(DESTDIR)/$(CLIENT_BINARY) ./cmd/client

generate: $(BPF_HEADER_DIR)/bpf_shared.h $(BPF_C_SRC) pkg/ebpf/manager.go
	@echo "Generating Go wrappers and compiling eBPF C code (via go generate)..."
	$(GO_CMD) generate ./pkg/ebpf/...

deps:
	@echo "Tidying dependencies..."
	$(GO_CMD) mod tidy
	$(GO_CMD) mod verify

test: generate
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
	rm -rf $(DESTDIR) $(DEB_ROOT) $(DEB_FILENAME)
	rm -f pkg/ebpf/*_bpf*.go pkg/ebpf/*.o
	$(GO_CMD) clean

install: build
	@echo "Manual installation (for development)..."
	sudo install -D -m 755 $(DESTDIR)/$(SERVICE_BINARY) /usr/local/bin/
	sudo install -D -m 755 $(DESTDIR)/$(CLIENT_BINARY) /usr/local/bin/
	sudo install -D -m 640 config.yaml /etc/kernelgatekeeper/config.yaml || echo "Config exists, skipping"
	sudo install -D -m 644 deploy/kernelgatekeeper.service /etc/systemd/system/
	sudo install -D -m 644 deploy/kernelgatekeeper-client.service /usr/lib/systemd/user/
	sudo touch /var/log/kernelgatekeeper.log
	sudo chmod 640 /var/log/kernelgatekeeper.log
	@echo "Manual installation complete! Reload systemd:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  systemctl --user daemon-reload"
	@echo "Then enable services:"
	@echo "  sudo systemctl enable --now kernelgatekeeper.service"
	@echo "  systemctl --user enable --now kernelgatekeeper-client.service"

deb: clean generate build
	@echo "Building DEB package..."
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/local/bin
	mkdir -p $(DEB_ROOT)/etc/kernelgatekeeper
	mkdir -p $(DEB_ROOT)/etc/systemd/system
	mkdir -p $(DEB_ROOT)/usr/lib/systemd/user
	mkdir -p $(DEB_ROOT)/var/log
	mkdir -p $(DEB_ROOT)/etc/profile.d
	cp $(DESTDIR)/$(SERVICE_BINARY) $(DEB_ROOT)/usr/local/bin/
	cp $(DESTDIR)/$(CLIENT_BINARY) $(DEB_ROOT)/usr/local/bin/
	cp config.yaml $(DEB_ROOT)/etc/kernelgatekeeper/config.yaml
	cp deploy/kernelgatekeeper.service $(DEB_ROOT)/etc/systemd/system/
	cp deploy/kernelgatekeeper-client.service $(DEB_ROOT)/usr/lib/systemd/user/
	cp $(DEB_SCRIPTS_SRC)/conffiles $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/postinst $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/prerm $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/postrm $(DEB_ROOT)/DEBIAN/
	cp $(DEB_SCRIPTS_SRC)/99-kernelgatekeeper-client-enabler.sh $(DEB_ROOT)/etc/profile.d/
	@echo "Generating DEBIAN/control..."
	@echo "Package: $(DEB_PACKAGE_NAME)" > $(DEB_ROOT)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Section: net" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Architecture: $(ARCH)" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Depends: libc6, adduser" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Maintainer: Yolki Spalkis <yolkispalkis@w3h.su>" >> $(DEB_ROOT)/DEBIAN/control
	@echo "Description: Transparent Kerberos proxy using eBPF sockops." >> $(DEB_ROOT)/DEBIAN/control
	@echo " Provides transparent proxying for user applications by leveraging" >> $(DEB_ROOT)/DEBIAN/control
	@echo " eBPF connect4/sockops/skmsg hooks to redirect traffic and performing Kerberos" >> $(DEB_ROOT)/DEBIAN/control
	@echo " authentication via a user-specific client process." >> $(DEB_ROOT)/DEBIAN/control
	@echo "Setting script permissions..."
	chmod +x $(DEB_ROOT)/DEBIAN/postinst $(DEB_ROOT)/DEBIAN/prerm $(DEB_ROOT)/DEBIAN/postrm
	chmod 755 $(DEB_ROOT)/etc/profile.d/99-kernelgatekeeper-client-enabler.sh
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