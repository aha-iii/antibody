# Nerve Antibody — developer & release tasks (GNU Make)
# Run from repository root.

VERSION := $(shell awk -F'"' '/^version = /{print $$2; exit}' Cargo.toml)
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
UI_DIR := $(ROOT)/apps/dashboard

.PHONY: help install build test fmt fmt-check clippy dashboard seal dist clean

help:
	@echo "Nerve Antibody $(VERSION)"
	@echo ""
	@echo "  make install        One-shot install: toolchain check + release build + tests"
	@echo "  make build          cargo build --release"
	@echo "  make test           cargo test (whole workspace)"
	@echo "  make fmt            cargo fmt --all"
	@echo "  make fmt-check      cargo fmt --all -- --check"
	@echo "  make clippy         cargo clippy --workspace --all-targets -- -D warnings"
	@echo "  make dashboard      Arc-Cortex Console: API :8790 + Vite :5178 (hot reload)"
	@echo "  make seal PACK=<dir> [OUT=<file>]   encrypt a rule pack into .sealed"
	@echo "  make dist           release artifacts under dist/"
	@echo "  make clean          cargo clean + remove dashboard build output"

install:
	bash $(ROOT)/install.sh

build:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

dashboard:
	bash $(ROOT)/tools/dev-dashboard.sh

seal:
	@test -n "$(PACK)" || { echo "usage: make seal PACK=<pack_dir> [OUT=<file.sealed>]"; echo "key: export NERVE_PACK_SEAL_KEY_B64=... or pass --key-file"; exit 1; }
	@mkdir -p $(ROOT)/dist
	cargo run -q -p nerve-antibody-pack --bin seal-pack -- \
		"$(PACK)" "$(if $(OUT),$(OUT),$(ROOT)/dist/$(notdir $(PACK)).sealed)"

dist: build
	@test -f $(UI_DIR)/vendor/nerve-ui/src/index.ts || \
		{ echo "missing $(UI_DIR)/vendor/nerve-ui/src/index.ts (@nerve/ui 源码副本不完整)"; exit 1; }
	cd $(UI_DIR) && npm install && npm run build
	@mkdir -p $(ROOT)/dist
	@rm -rf $(ROOT)/dist/packs
	cp -R $(ROOT)/packs $(ROOT)/dist/packs
	@echo "dist/ ready: engine binaries in target/release, packs in dist/packs"

clean:
	cargo clean
	rm -rf $(UI_DIR)/dist
