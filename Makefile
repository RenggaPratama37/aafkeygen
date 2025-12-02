# =========================================
#  AAFKeygen Makefile
# =========================================

NAME        := aafkeygen
VERSION     := $(shell cat VERSION)
DEB_VERSION := $(shell echo $(VERSION) | sed 's/^v//')
DEB_DIR_VERSION := $(VERSION)

BINARY      := $(NAME)

SRC_DIR     := src
INC_DIR     := include
BUILD_DIR   := build

ARCH ?= $(shell uname -m)

# Normalize architecture names
DEB_ARCH := $(ARCH)
ifeq ($(ARCH),x86_64)
DEB_ARCH := amd64
endif
ifeq ($(ARCH),aarch64)
DEB_ARCH := arm64
endif

DEB_DIR := $(NAME)_$(DEB_DIR_VERSION)_$(DEB_ARCH)
PREFIX  := /usr/local

CC ?= gcc

CFLAGS := -Wall -O2 -I$(INC_DIR) -MMD -MP
LIBS   := -lcrypto

# ================================
# Source & object discovery
# ================================

# All C files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

# Crypto library subset (only engine sources)
CRYPTO_SRCS := crypto.c header.c kdf.c aead.c cipher.c
LIB_OBJS := $(addprefix $(BUILD_DIR)/,$(CRYPTO_SRCS:.c=.o))

# ================================
# Static library
# ================================
libaafcrypto.a: $(LIB_OBJS)
	@echo "Creating static library $@"
	@ar rcs $@ $^

# ================================
# Default
# ================================
all: $(BINARY)

# ================================
# Build binary
# ================================
$(BINARY): $(OBJS)
	@echo "Linking $(BINARY)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# ================================
# Compile objects
# ================================
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling $< ..."
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

# ================================
# Install / uninstall
# ================================
install: $(BINARY)
	@echo "Installing $(BINARY) to $(PREFIX)/bin ..."
	sudo install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	sudo install -Dm644 VERSION $(PREFIX)/share/$(BINARY)/VERSION

uninstall:
	@echo "Removing $(BINARY) from system..."
	sudo rm -f $(PREFIX)/bin/$(BINARY)
	sudo rm -rf $(PREFIX)/share/$(BINARY)

# ================================
# Clean
# ================================
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(BINARY) $(DEB_DIR) *.deb

# ================================
# Build .deb package
# ================================
deb: $(BINARY)
	@echo "Building .deb for $(DEB_ARCH)..."
	@if [ ! -f "$(BINARY)" ]; then \
		echo "Binary missing, rebuilding..."; \
		$(MAKE) all; \
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
	@echo "Package built: $(DEB_DIR).deb"

.PHONY: all install uninstall clean deb help
