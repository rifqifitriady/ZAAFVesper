# ZAAFVesper build targets. No target needs or accepts root: `make package`
# builds a flat installer package as the normal user, and root only runs
# Apple's /usr/sbin/installer and /bin/launchctl on the result (see README).

VERSION     ?= 0.1.0
BIN         := bin/zaafvesper
PKG         := ./cmd/zaafvesper
BREW_PREFIX ?= /opt/homebrew
RULES       ?= rules
# Installed layout (fixed: the LaunchDaemon plist names these paths).
ETC         := /usr/local/etc/zaafvesper
PKG_ID      := com.rifqifitriady.zaafvesper
PLIST       := packaging/$(PKG_ID).plist
NEWSYSLOG   := packaging/newsyslog-zaafvesper.conf
# Staging tree and binary (removed literally in the package and clean targets).
PKG_ROOT    := build/pkgroot
PKG_BIN     := build/pkg/zaafvesper
PKG_OUT     := dist/ZAAFVesper-$(VERSION).pkg
LDFLAGS     := -s -w -X main.version=$(VERSION)
INSTALL_LDFLAGS := $(LDFLAGS) -X main.defaultRulesDir=$(ETC)/rules -X main.defaultConfigPath=$(ETC)/zaafvesper.yml
# Dynamic libyara (development only: a root zaafvesper refuses Homebrew dylibs).
YARA_ENV    := CGO_ENABLED=1 PKG_CONFIG_PATH=$(BREW_PREFIX)/lib/pkgconfig \
               CGO_CFLAGS=-I$(BREW_PREFIX)/include CGO_LDFLAGS=-L$(BREW_PREFIX)/lib
# Static libyara and its dependencies. ld64 prefers a dylib found in the same
# directory, so libyara.a is linked from a directory of its own.
H           := $(BREW_PREFIX)/opt
STATICLIB   := $(CURDIR)/build/staticlib
YARA_STATIC_ENV := CGO_ENABLED=1 CGO_CFLAGS="-I$(H)/yara/include" \
               CGO_LDFLAGS="-L$(STATICLIB) $(H)/libmagic/lib/libmagic.a $(H)/jansson/lib/libjansson.a $(H)/openssl@4/lib/libcrypto.a -lz -lbz2"
YARA_STATIC_TAGS := yara yara_no_pkg_config

.PHONY: build build-yara build-yara-dev check-static staticlib test test-race test-yara rules-test bench fuzz vet package install clean

## build: pure-Go binary (YARA disabled with a warning)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

staticlib:
	mkdir -p build/staticlib
	ln -sf $(H)/yara/lib/libyara.a build/staticlib/libyara.a

## build-yara: YARA binary with libyara linked statically (the one to run as root)
build-yara: staticlib
	$(YARA_STATIC_ENV) go build -tags '$(YARA_STATIC_TAGS)' -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)
	$(MAKE) check-static

## check-static: fail if the binary loads any library outside /usr/lib or /System
check-static:
	@bad=$$(otool -L $(BIN) | tail -n +2 | awk '{print $$1}' | grep -v -E '^(/usr/lib/|/System/)' || true); \
	if [ -n "$$bad" ]; then echo "$(BIN) links libraries outside /usr/lib and /System:"; echo "$$bad"; exit 1; fi; \
	echo "$(BIN): only /usr/lib and /System libraries"

## build-yara-dev: YARA with the Homebrew dylib, for non-root development only
build-yara-dev:
	$(YARA_ENV) go build -tags yara -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

vet:
	go vet ./...

## test: vet plus all unit tests
test: vet
	go test ./...

test-race:
	go test -race ./...

test-yara:
	$(YARA_ENV) go test -tags yara ./...

## rules-test: every rule's match/nomatch fixtures
rules-test:
	go run $(PKG) rules validate $(RULES)
	go run $(PKG) rules test $(RULES)

## bench: engine throughput (target >= 20 000 events/s with 30 rules)
bench:
	go test -run '^$$' -bench BenchmarkEngine -benchmem ./pkg/rules/

fuzz:
	go test -run '^$$' -fuzz FuzzParse -fuzztime 60s ./pkg/filter/ql/

## package: build dist/ZAAFVesper-$(VERSION).pkg as the normal user (pure Go;
## YARA=1 for the static YARA build, checked with check-static). Payload:
## /usr/local/sbin/zaafvesper (0755), /usr/local/etc/zaafvesper/{zaafvesper.yml,
## config.d,rules} (dirs 0755, files 0644), the LaunchDaemon plist (0644),
## /etc/newsyslog.d/zaafvesper.conf (0644), /var/log/zaafvesper (0700) and the response state
## directory /var/db/zaafvesper with its quarantine vault (both 0700). pkgbuild records every path as root:wheel
## (--ownership recommended). The package carries no install scripts.
package:
	@test "$$(id -u)" != 0 || { echo "make package runs as your normal user, never as root; root only runs /usr/sbin/installer on the result"; exit 1; }
	rm -rf build/pkgroot build/pkg
	mkdir -p build/pkg dist
	if [ "$(YARA)" = 1 ]; then \
	  $(MAKE) staticlib && \
	  $(YARA_STATIC_ENV) go build -tags '$(YARA_STATIC_TAGS)' -trimpath -ldflags '$(INSTALL_LDFLAGS)' -o $(PKG_BIN) $(PKG) && \
	  $(MAKE) check-static BIN=$(PKG_BIN); \
	else \
	  CGO_ENABLED=0 go build -trimpath -ldflags '$(INSTALL_LDFLAGS)' -o $(PKG_BIN) $(PKG); \
	fi
	/usr/bin/plutil -lint $(PLIST)
	$(PKG_BIN) rules validate $(RULES)
	mkdir -p $(PKG_ROOT)/usr/local/sbin $(PKG_ROOT)$(ETC)/config.d $(PKG_ROOT)$(ETC)/rules \
	  $(PKG_ROOT)/Library/LaunchDaemons $(PKG_ROOT)/private/var/log/zaafvesper $(PKG_ROOT)/private/etc/newsyslog.d \
	  $(PKG_ROOT)/private/var/db/zaafvesper/quarantine
	install -m 0644 $(NEWSYSLOG) $(PKG_ROOT)/private/etc/newsyslog.d/zaafvesper.conf
	install -m 0755 $(PKG_BIN) $(PKG_ROOT)/usr/local/sbin/zaafvesper
	sed 's|^rules_dir:.*|rules_dir: $(ETC)/rules|' configs/zaafvesper.yml > $(PKG_ROOT)$(ETC)/zaafvesper.yml
	for f in configs/config.d/*.yml; do install -m 0644 "$$f" $(PKG_ROOT)$(ETC)/config.d/; done
	cd $(RULES) && find . -type d -exec mkdir -p "$(CURDIR)/$(PKG_ROOT)$(ETC)/rules/{}" \;
	cd $(RULES) && find . -type f ! -name '.*' -exec install -m 0644 "{}" "$(CURDIR)/$(PKG_ROOT)$(ETC)/rules/{}" \;
	install -m 0644 $(PLIST) $(PKG_ROOT)/Library/LaunchDaemons/$(PKG_ID).plist
	find $(PKG_ROOT) -type d -exec chmod 0755 {} +
	find $(PKG_ROOT) -type f -exec chmod 0644 {} +
	chmod 0755 $(PKG_ROOT)/usr/local/sbin/zaafvesper
	chmod 0700 $(PKG_ROOT)/private/var/log/zaafvesper
	chmod 0700 $(PKG_ROOT)/private/var/db/zaafvesper $(PKG_ROOT)/private/var/db/zaafvesper/quarantine
	/usr/bin/xattr -cr $(PKG_ROOT) 2>/dev/null || true
	rm -f $(PKG_OUT)
	/usr/bin/pkgbuild --root $(PKG_ROOT) --ownership recommended --identifier $(PKG_ID) \
	  --version $(VERSION) --install-location / $(PKG_OUT)
	@echo "built $(PKG_OUT)"
	@/usr/bin/shasum -a 256 $(PKG_OUT)
	@echo "install (root runs only Apple binaries; compare the hash above with the one root computes):"
	@echo "  sudo /bin/mkdir -m 0700 /var/root/zaafvesper-install"
	@echo "  sudo /bin/cp $(CURDIR)/$(PKG_OUT) /var/root/zaafvesper-install/"
	@echo "  sudo /usr/bin/shasum -a 256 /var/root/zaafvesper-install/ZAAFVesper-$(VERSION).pkg"
	@echo "  sudo /usr/sbin/pkgutil --expand /var/root/zaafvesper-install/ZAAFVesper-$(VERSION).pkg /var/root/zaafvesper-install/x"
	@echo "  sudo /bin/ls /var/root/zaafvesper-install/x        (must list only Bom, PackageInfo, Payload: no Scripts)"
	@echo "  sudo /usr/sbin/installer -pkg /var/root/zaafvesper-install/ZAAFVesper-$(VERSION).pkg -target /"
	@echo "  sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/$(PKG_ID).plist"

## install: disabled. Root must never run make, the Go toolchain or anything
## else the normal account can modify (finding H1).
install:
	@echo "make install is disabled: root must never run make, go or other user-writable code."
	@echo "1. As your normal user:   make package            (or: make package YARA=1)"
	@echo "2. As root, Apple binaries only: copy the package into /var/root, check its"
	@echo "   SHA-256 and that it has no Scripts, then installer and launchctl."
	@echo "   make package prints the exact commands; README.md (Install and run live)"
	@echo "   explains them, Full Disk Access and uninstall."
	@exit 1

clean:
	rm -rf bin build/pkgroot build/pkg dist
