# =========================================
#  AAFKeygen Makefile
#  CLI encryption tool (C + OpenSSL)
#  Compatible with Linux / Debian packaging
# =========================================

# --- Project info ---
NAME        := aafkeygen
VERSION     := $(shell cat VERSION)
DEB_VERSION := $(shell echo $(VERSION) | sed 's/^v//')
DEB_DIR_VERSION := $(VERSION)

BINARY      := $(NAME)

SRC_DIR     := src
INC_DIR     := include
BUILD_DIR   := build

ARCH ?= $(shell uname -m)

# Normalize architecture names used for .deb naming
DEB_ARCH := $(ARCH)
ifeq ($(ARCH),x86_64)
DEB_ARCH := amd64
endif
ifeq ($(ARCH),aarch64)
DEB_ARCH := arm64
endif

DEB_DIR 	:= $(NAME)_$(DEB_DIR_VERSION)_$(DEB_ARCH)
PREFIX  	:= /usr/local

CC ?= gcc

# Add include directory + auto header dependency
CFLAGS      := -Wall -O2 -I$(INC_DIR) -MMD -MP
LIBS        := -lcrypto

# --- Source files ---
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

# Static library for crypto engine to be reused by other projects
LIB_OBJS := $(BUILD_DIR)/crypto.o $(BUILD_DIR)/header.o $(BUILD_DIR)/kdf.o $(BUILD_DIR)/aead.o $(BUILD_DIR)/cipher.o

# Build static library
libaafcrypto.a: $(LIB_OBJS)
	@echo "Creating static library $@"
	@ar rcs $@ $^

# --- Default rule ---
all: $(BINARY)

# --- Build binary ---
$(BINARY): $(OBJS)
	@echo "Linking $(BINARY)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# --- Object build rule ---
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling $< ..."
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

# --- Install binary ---
install: $(BINARY)
	@echo "Installing $(BINARY) to $(PREFIX)/bin ..."
	sudo install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	sudo install -Dm644 VERSION $(PREFIX)/share/$(BINARY)/VERSION


# --- Uninstall binary ---
uninstall:
	@echo "Removing $(BINARY) from system..."
	sudo rm -f $(PREFIX)/bin/$(BINARY)
	sudo rm -rf $(PREFIX)/share/$(BINARY)

# --- Clean build ---
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(BINARY) $(DEB_DIR) *.deb

# --- Build .deb package ---

deb: $(BINARY)
	@echo "Building .deb for $(DEB_ARCH)..."
	# ensure binary is built (explicit recursive make is clearer in CI)
	@if [ ! -f "$(BINARY)" ]; then \
		echo "Binary '$(BINARY)' not found, attempting to build..."; \
		$(MAKE) $(BINARY) || { echo "Failed to build $(BINARY)"; exit 1; }; \
	fi
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/bin
	mkdir -p $(DEB_DIR)/usr/share/$(NAME)

	sed -e "s/@VERSION@/$(DEB_VERSION)/" \
        -e "s/@ARCH@/$(DEB_ARCH)/" \
        debian/control > $(DEB_DIR)/DEBIAN/control

	cp $(BINARY) $(DEB_DIR)/usr/bin/
	cp VERSION $(DEB_DIR)/usr/share/$(NAME)/VERSION
	cp debian/postinst $(DEB_DIR)/DEBIAN/ 2>/dev/null || true
	cp debian/prerm $(DEB_DIR)/DEBIAN/ 2>/dev/null || true

	chmod 755 $(DEB_DIR)/DEBIAN/postinst || true
	dpkg-deb --build $(DEB_DIR)
	@echo "✅ Package built: $(DEB_DIR).deb"

.PHONY: deb-arch
deb-arch: $(BINARY)
	@echo "Building .deb for ARCH=$(ARCH) (DEB_ARCH=$(DEB_ARCH))"
	$(MAKE) deb

.PHONY: deb-docker
deb-docker:
	@echo "Building .deb via Docker for ARCH=$(ARCH) (DEB_ARCH=$(DEB_ARCH))"
	@if [ "$(DEB_ARCH)" = "arm64" ]; then \
		docker run --rm --platform linux/arm64 -v "$$PWD":/src -w /src ubuntu:24.04 bash -lc "set -euo pipefail; apt-get update; apt-get install -y build-essential libssl-dev dpkg-dev ca-certificates; make clean || true; make ARCH=aarch64; mkdir -p /src/$(DEB_DIR)/usr/bin; cp aafkeygen /src/$(DEB_DIR)/usr/bin/; cp -r debian /src/$(DEB_DIR)/DEBIAN || true; dpkg-deb --build /src/$(DEB_DIR)"; \
	else \
		$(MAKE) deb-arch; \
	fi

# --- Help menu ---
help:
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Compile project"
	@echo "  install     - Install binary to system"
	@echo "  uninstall   - Remove binary from system"
	@echo "  clean       - Remove build artifacts"
	@echo "  deb         - Build .deb package"
	@echo "  help        - Show this help message"
	@echo ""

.PHONY: all install uninstall clean deb help
