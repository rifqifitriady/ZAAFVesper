#!/bin/sh
# Regenerates the committed eBPF objects (zaaf_*_bpfel.o and .go) from
# zaaf.bpf.c inside the pinned toolchain. Needs Docker. Run from anywhere:
#   pkg/source/ebpf/bpf/regen.sh
# The build runs with an empty environment plus an explicit allow-list, so
# nothing on the host (CFLAGS, BPF2GO_*, CCC_OVERRIDE_OPTIONS, GOFLAGS)
# changes the result.
set -eu
root=$(cd "$(dirname "$0")/../../../.." && pwd)
image=zaaf-bpf-toolchain
docker build -q -t "$image" "$root/pkg/source/ebpf/bpf/toolchain" >/dev/null
docker run --rm --network=default \
	-v "$root":/src -w /src/pkg/source/ebpf \
	--user "$(id -u):$(id -g)" \
	"$image" env -i \
	PATH=/usr/local/go/bin:/usr/bin:/bin \
	HOME=/tmp GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomod GOPATH=/tmp/go \
	GOTOOLCHAIN=local GOFLAGS= GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
	GOPACKAGE=ebpf \
	go generate ./gen.go
