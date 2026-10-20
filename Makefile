# Build helpers.
#
# macOS refuses local-network connections from programs it does not trust: the
# connection completes at the TCP level and is then torn down, which shows up as
# EINVAL from socket options and ENOTCONN from reads. An ad-hoc signature is what
# the firewall checks, so every build here signs what it produced. Off macOS the
# signing step is a no-op.

CARGO ?= cargo
SIGN  := scripts/codesign-macos.sh

.DEFAULT_GOAL := help
.PHONY: help build release test lint fmt check scale sign verify clean

help: ## Show the available targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-9s %s\n", $$1, $$2}'

build: ## Build the debug binary and sign it (macOS)
	$(CARGO) build
	@$(SIGN) target/debug/twin

release: ## Build the release binary and sign it (macOS)
	$(CARGO) build --release
	@$(SIGN) target/release/twin

test: ## Run the test suite (loopback only, so signing is not needed)
	$(CARGO) test

lint: ## Clippy with warnings denied
	$(CARGO) clippy --all-targets -- -D warnings

fmt: ## Format the sources
	$(CARGO) fmt

check: fmt lint test sign ## Format, lint, test, then sign whatever was produced

scale: ## The 1k-file tree test (slow: one fsync per file)
	$(CARGO) test --test scale -- --ignored --nocapture

sign: ## Sign whatever binaries already exist (macOS)
	@for binary in target/debug/twin target/release/twin; do \
		[ -f "$$binary" ] && $(SIGN) "$$binary" || true; \
	done

verify: build ## Prove that a local-network connection survives on this machine
	@./target/debug/twin doctor .

clean: ## Remove build output
	$(CARGO) clean
