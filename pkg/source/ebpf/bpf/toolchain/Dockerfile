# Pinned toolchain that compiles zaaf.bpf.c into the committed objects
# (see ../../README.md, "Regenerating the kernel programs"). Everything is
# pinned: the Go image by digest, clang/LLVM by exact Debian version from a
# dated snapshot, bpf2go by module version (gen.go). The same inputs give
# byte-identical objects, which CI checks.
FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && echo 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261101T000000Z trixie main' > /etc/apt/sources.list.d/snapshot.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends clang-19=1:19.1.7-3+b1 llvm-19=1:19.1.7-3+b1 \
 && rm -rf /var/lib/apt/lists/*
ENV GOTOOLCHAIN=local
