# =========================================
#  AAFKeygen Makefile
#  CLI encryption tool (C + OpenSSL)
#  Compatible with Linux / Debian packaging
# =========================================

# --- Project info ---
NAME        := aafkeygen
VERSION     := 1.4.2
BINARY      := $(NAME)
SRC_DIR     := src
BUILD_DIR   := build
DEB_DIR     := $(NAME)_$(VERSION)
PREFIX      := /usr/local
CC          := gcc
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
	@echo "Building Debian package..."
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/bin
	cp $(BINARY) $(DEB_DIR)/usr/bin/
	cp debian/* $(DEB_DIR)/DEBIAN/
	chmod 755 $(DEB_DIR)/DEBIAN/postinst
	dpkg-deb --build $(DEB_DIR)
	@echo "✅ Package built: $(DEB_DIR).deb"

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
