package ebpf

// The kernel programs in bpf/zaaf.bpf.c are compiled into zaaf_x86_bpfel.o
// and zaaf_arm64_bpfel.o (with the Go files that embed them) by bpf2go.
// The outputs are committed, so a normal build needs no clang. Regenerate
// them only with bpf/regen.sh, which runs this directive inside the pinned
// toolchain (bpf/toolchain/Dockerfile); CI checks that the result is
// byte-identical to what is committed.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang-19 -strip llvm-strip-19 -cflags "-O2 -g -Wall -Werror -mcpu=v3" -target amd64,arm64 -tags linux -go-package ebpf zaaf bpf/zaaf.bpf.c -- -I./bpf
