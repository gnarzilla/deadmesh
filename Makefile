#=============================================================================
# Project
#=============================================================================
PROJECT := deadmesh
VERSION := 1.0.0

#=============================================================================
# Compiler + Flags (single source of truth)
#=============================================================================
CC := cc

COMMON_CFLAGS := -std=gnu11 -Wall -Wextra -pedantic -O2 -g
INCLUDES      := -Isrc -Isrc/core -Isrc/mesh

PKG_CFLAGS := $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)
PKG_LIBS   := $(shell pkg-config --libs   glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)

CFLAGS  := $(COMMON_CFLAGS) $(INCLUDES) $(PKG_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\"
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS :=
  PLUGIN_LDFLAGS := -shared -undefined dynamic_lookup
else
  LDFLAGS := -Wl,--as-needed
  PLUGIN_LDFLAGS := -shared
endif
LIBS 	:= -lpthread $(PKG_LIBS) -lssl -lcrypto -lresolv

#=============================================================================
# Feature Flags
#=============================================================================
UI ?= 0

#=============================================================================
# Directories
#=============================================================================
OBJDIR        := obj
BINDIR        := bin
TOOLSDIR      := tools
PLUGIN_BINDIR := $(BINDIR)/plugins

#=============================================================================
# Sources
#=============================================================================
CORE_SRC   := $(wildcard src/core/*.c)
PROTO_SRC  := $(wildcard src/protocols/*.c)
MESH_SRC   := $(wildcard src/mesh/*.c)
VPN_SRC    := $(wildcard src/vpn/*.c)
ifeq ($(UNAME_S),Darwin)
  VPN_SRC :=
endif
PLUGIN_SRC := src/plugins/ratelimiter.c

ALL_SRC := $(CORE_SRC) $(PROTO_SRC) $(MESH_SRC) $(VPN_SRC) $(PLUGIN_SRC)

ifeq ($(UI),1)
  CFLAGS  += -DENABLE_UI
  CFLAGS  += $(shell pkg-config --cflags libmicrohttpd)
  LIBS    += $(shell pkg-config --libs libmicrohttpd)
  # Explicit list — assets.c is generated so wildcard won't see it at parse time
  ALL_SRC += src/ui/ui.c src/ui/assets.c
endif

OBJ := $(patsubst %.c,$(OBJDIR)/%.o,$(ALL_SRC))

#=============================================================================
# Nanopb / Meshtastic protobufs
#=============================================================================
NANOPB_DIR := src/plugins/nanopb
NANOPB_INC := src/plugins/include/nanopb
PROTO_BASE := src/plugins/protobufs
PROTO_DIR  := $(PROTO_BASE)/meshtastic
GEN_DIR    := src/plugins/meshtastic

NANOPB_SRC := $(NANOPB_DIR)/pb_common.c \
              $(NANOPB_DIR)/pb_encode.c \
              $(NANOPB_DIR)/pb_decode.c

NANOPB_CFLAGS := -I$(NANOPB_INC) \
                 -I$(GEN_DIR) \
                 -I$(GEN_DIR)/meshtastic \
                 -Isrc -Isrc/core -Isrc/mesh \
                 -Wno-pedantic

PROTO_FILES := $(filter-out $(PROTO_DIR)/deviceonly.proto,$(wildcard $(PROTO_DIR)/*.proto))
PROTO_PB_C  := $(patsubst $(PROTO_DIR)/%.proto,$(GEN_DIR)/meshtastic/%.pb.c,$(PROTO_FILES))
PROTO_PB_H  := $(patsubst $(PROTO_DIR)/%.proto,$(GEN_DIR)/meshtastic/%.pb.h,$(PROTO_FILES))

#=============================================================================
# Top-level Targets
#=============================================================================
MAIN    := $(BINDIR)/$(PROJECT)
SIM     := $(TOOLSDIR)/mesh-sim
CLIENT  := $(BINDIR)/deadmesh-client
PLUGINS := $(PLUGIN_BINDIR)/adblocker.so \
           $(PLUGIN_BINDIR)/ratelimiter.so \
           $(PLUGIN_BINDIR)/meshtastic.so

all: dirs $(MAIN) plugins sim client

dirs:
	@mkdir -p $(OBJDIR) $(BINDIR) $(PLUGIN_BINDIR) $(TOOLSDIR)

#=============================================================================
# Generic compile rule
#=============================================================================
$(OBJDIR)/%.o: %.c
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

#=============================================================================
# UI asset generation
# assets.c doesn't exist until this runs, so it can't be caught by wildcard.
# The generic .o rule handles compilation once the .c exists.
#=============================================================================
ifeq ($(UI),1)
UI_ASSETS := src/ui/index.html src/ui/favicon.ico src/ui/favicon.png

src/ui/assets.c: $(UI_ASSETS)
	@echo "Generating UI assets..."
	@printf '/* Auto-generated UI assets */\n\n' > $@
	@for asset in $(UI_ASSETS); do \
		echo "Embedding $$asset..."; \
		xxd -i $$asset >> $@; \
		printf '\n' >> $@; \
	done

# Force assets.o to depend on the generated .c explicitly
$(OBJDIR)/src/ui/assets.o: src/ui/assets.c
endif

#=============================================================================
# Main binary
#=============================================================================
$(MAIN): $(OBJ)
	@echo "Linking $(PROJECT)..."
	@$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "Built $(PROJECT) v$(VERSION)"

#=============================================================================
# Plugins
#=============================================================================
PLUGIN_CFLAGS := $(CFLAGS) -fPIC

plugins: $(PLUGINS)

$(PLUGIN_BINDIR)/adblocker.so: src/plugins/adblocker.c src/plugins/adblocker.h
	@echo "Building AdBlocker plugin..."
	@$(CC) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS) -o $@ $< $(LIBS)

$(PLUGIN_BINDIR)/ratelimiter.so: src/plugins/ratelimiter.c src/plugins/ratelimiter.h
	@echo "Building RateLimiter plugin..."
	@$(CC) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS) -o $@ $< $(LIBS)

$(GEN_DIR)/meshtastic:
	@mkdir -p $@

$(GEN_DIR)/meshtastic/%.pb.c $(GEN_DIR)/meshtastic/%.pb.h: $(PROTO_DIR)/%.proto | $(GEN_DIR)/meshtastic
	@echo "Generating nanopb: $(notdir $<)..."
	@PROTO_NAME=$$(basename $< .proto); \
	protoc \
		--plugin=protoc-gen-nanopb=$(NANOPB_DIR)/generator/protoc-gen-nanopb \
		--proto_path=$(PROTO_BASE) \
		--nanopb_out=$(GEN_DIR) \
		meshtastic/$$PROTO_NAME.proto

$(PLUGIN_BINDIR)/meshtastic.so: \
		src/plugins/meshtastic.c \
		src/plugins/meshtastic.h \
		$(MESH_SRC) \
		$(PROTO_PB_C) \
		$(NANOPB_SRC)
	@echo "Building Meshtastic plugin..."
	@$(CC) $(PLUGIN_CFLAGS) $(NANOPB_CFLAGS) $(PLUGIN_LDFLAGS) -o $@ \
		src/plugins/meshtastic.c $(MESH_SRC) $(PROTO_PB_C) $(NANOPB_SRC) \
		$(LIBS)

#=============================================================================
# Tools
#=============================================================================
sim: dirs $(SIM)

$(SIM): tools/mesh-sim.c $(MESH_SRC)
	@echo "Building mesh simulator..."
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "Simulator built: $@"

client: dirs $(CLIENT)

$(CLIENT): \
		tools/client_main.c \
		tools/client_transport.c \
		$(MESH_SRC) \
		$(NANOPB_SRC) \
		$(PROTO_PB_C)
	@echo "Building deadmesh-client..."
	@$(CC) $(CFLAGS) $(NANOPB_CFLAGS) -DCLIENT_TRANSPORT_SERIAL \
		-o $@ \
		tools/client_main.c tools/client_transport.c \
		$(MESH_SRC) $(NANOPB_SRC) $(PROTO_PB_C) \
		$(LDFLAGS) $(LIBS)
	@echo "Client built: $@"

#=============================================================================
# Clean
#=============================================================================
clean:
	@echo "Cleaning..."
	@rm -rf $(OBJDIR) $(BINDIR) $(SIM)
	@rm -f src/ui/assets.c
	@rm -f $(PROTO_PB_C) $(PROTO_PB_H)
	@rm -rf $(GEN_DIR)
	@echo "Clean complete"

.PHONY: all clean dirs plugins sim client
