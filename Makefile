# ZAAFVesper build targets. No target needs root except `install`, which the
# owner runs with sudo; tests never run it.

VERSION     ?= 0.1.0
BIN         := bin/zaafvesper
PKG         := ./cmd/zaafvesper
BREW_PREFIX ?= /opt/homebrew
RULES       ?= rules
PREFIX      ?= /usr/local
DESTDIR     ?=
ETC         := $(PREFIX)/etc/zaafvesper
STAGE       := bin/install
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

.PHONY: build build-yara build-yara-dev check-static staticlib test test-race test-yara rules-test bench fuzz vet install clean

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

## install: run as `sudo make install` (pure-Go build) or `sudo make install
## YARA=1` (static YARA build, checked with check-static). Binary -> $(PREFIX)/sbin/zaafvesper (root:wheel 0755); rules and config
## -> $(PREFIX)/etc/zaafvesper (dirs 0755, files 0644). The installed binary
## defaults to those paths. ZAAFVesper refuses to run as root from anywhere a
## non-root user can write. Staging files stay in bin/install (gitignored).
install:
	@test "$$(id -u)" = 0 || { echo "make install must run as root: sudo make install"; exit 1; }
	mkdir -p $(STAGE)
	if [ "$(YARA)" = 1 ]; then \
	  $(MAKE) staticlib && \
	  $(YARA_STATIC_ENV) go build -tags '$(YARA_STATIC_TAGS)' -trimpath -ldflags '$(INSTALL_LDFLAGS)' -o $(STAGE)/zaafvesper $(PKG) && \
	  $(MAKE) check-static BIN=$(STAGE)/zaafvesper; \
	else \
	  CGO_ENABLED=0 go build -trimpath -ldflags '$(INSTALL_LDFLAGS)' -o $(STAGE)/zaafvesper $(PKG); \
	fi
	sed 's|^rules_dir:.*|rules_dir: $(ETC)/rules|' configs/zaafvesper.yml > $(STAGE)/zaafvesper.yml
	install -d -o root -g wheel -m 0755 $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(ETC) $(DESTDIR)$(ETC)/config.d $(DESTDIR)$(ETC)/rules
	install -o root -g wheel -m 0755 $(STAGE)/zaafvesper $(DESTDIR)$(PREFIX)/sbin/zaafvesper
	install -o root -g wheel -m 0644 $(STAGE)/zaafvesper.yml $(DESTDIR)$(ETC)/zaafvesper.yml
	for f in configs/config.d/*.yml; do install -o root -g wheel -m 0644 "$$f" $(DESTDIR)$(ETC)/config.d/; done
	cd $(RULES) && find . -type d -exec install -d -o root -g wheel -m 0755 "$(DESTDIR)$(ETC)/rules/{}" \;
	cd $(RULES) && find . -type f ! -name '.*' -exec install -o root -g wheel -m 0644 "{}" "$(DESTDIR)$(ETC)/rules/{}" \;
	@echo "installed $(PREFIX)/sbin/zaafvesper; rules and config in $(ETC)"
	@echo "run: sudo $(PREFIX)/sbin/zaafvesper run"

clean:
	rm -rf bin
