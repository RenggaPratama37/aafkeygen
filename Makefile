# =========================================
#  AAFKeygen Makefile
#  CLI encryption tool (C + OpenSSL)
#  Compatible with Linux / Debian packaging
# =========================================

# --- Project info ---
NAME        := aafkeygen
BERSION     := 1.4.4
BINARY      := $(NAME)
SRC_DIR     := src
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

BINARY      := $(NAME)
SRC_DIR     := src
BUILD_DIR   := build
DEB_DIR     := $(NAME)_$(VERSION)_$(DEB_ARCH)
PREFIX      := /usr/local
CC ?= gcc
CFLAGS      := -Wall -O2
LIBS        := -lcrypto

# --- Source files ---
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# --- Default rule ---
all: $(BINARY)

# --- Build binary ---
$(BINARY): $(OBJS)
	@echo "Linking $(BINARY)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling $< ..."
	$(CC) $(CFLAGS) -c $< -o $@

# --- Install binary to system ---
install: $(BINARY)
	@echo "Installing $(BINARY) to $(PREFIX)/bin ..."
	sudo install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)

# --- Uninstall binary ---
uninstall:
	@echo "Removing $(BINARY) from system..."
	sudo rm -f $(PREFIX)/bin/$(BINARY)

# --- Clean build artifacts ---
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(BINARY) $(DEB_DIR) *.deb

# --- Build .deb package ---
deb: $(BINARY)
	@echo "Building Debian package for arch: $(DEB_ARCH)"
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/bin
	cp $(BINARY) $(DEB_DIR)/usr/bin/
	cp debian/* $(DEB_DIR)/DEBIAN/
	chmod 755 $(DEB_DIR)/DEBIAN/postinst || true
	dpkg-deb --build $(DEB_DIR)
	@echo "✅ Package built: $(DEB_DIR).deb"

.PHONY: deb-arch
deb-arch: $(BINARY)
	@echo "Building .deb for ARCH=$(ARCH) (DEB_ARCH=$(DEB_ARCH))"
	$(MAKE) deb

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
