# =========================================
#  AAFKeygen Makefile
#  CLI encryption tool (C + OpenSSL)
#  Compatible with Linux / Debian packaging
# =========================================

# --- Project info ---
NAME        := aafkeygen
VERSION     := $(shell cat VERSION 2>/dev/null || echo 1.5.4)
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

DEB_DIR     := $(NAME)_$(VERSION)_$(DEB_ARCH)
PREFIX      := /usr/local

CC ?= clang

# Add include directory + auto header dependency
CFLAGS      := -Wall -O2 -I$(INC_DIR) -MMD -MP
LIBS        := -lcrypto

# --- Source files ---
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

# Generate a C header from the top-level VERSION file so C code can
# reference the project version via a single source of truth.
include/version.h: VERSION
	@mkdir -p include
	@printf '#ifndef VERSION_H\n#define VERSION_H\n\n#define VERSION "%s"\n\n#endif\n' "$(VERSION)" > include/version.h


# --- Default rule ---
all: $(BINARY)

# --- Build binary ---
$(BINARY): $(OBJS)
	@echo "Linking $(BINARY)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


# Ensure version header exists before compiling any C sources
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c include/version.h
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling $< ..."
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

# --- Install binary ---
install: $(BINARY)
	@echo "Installing $(BINARY) to $(PREFIX)/bin ..."
	sudo install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)

# --- Uninstall binary ---
uninstall:
	@echo "Removing $(BINARY) from system..."
	sudo rm -f $(PREFIX)/bin/$(BINARY)

# --- Clean build ---
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(BINARY) $(DEB_DIR) *.deb

# --- Build .deb package ---
deb: $(BINARY)
	@echo "Building Debian package for arch: $(DEB_ARCH)"
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/bin
	cp $(BINARY) $(DEB_DIR)/usr/bin/
	# Copy debian files but substitute Version field from top-level VERSION
	cp debian/* $(DEB_DIR)/DEBIAN/ || true
	if [ -f $(DEB_DIR)/DEBIAN/control ]; then \
		sed -E 's/^Version:.*/Version: $(VERSION)/' $(DEB_DIR)/DEBIAN/control > $(DEB_DIR)/DEBIAN/control.tmp && mv $(DEB_DIR)/DEBIAN/control.tmp $(DEB_DIR)/DEBIAN/control ; \
	fi
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
