# Vendored libbpf headers

Unchanged copies of five header files from libbpf **v1.7.0** (tag commit
`f5dcbae736e5d7f83a35718e01be1a8e3010fa39`, <https://github.com/libbpf/libbpf>),
used only to compile `../zaaf.bpf.c`. Nothing from them is linked into the Go
binary. Vetted before adoption (security-auditor, 9 Nov 2026: safe).

Licence: `LGPL-2.1 OR BSD-2-Clause`. ZAAFVesper uses them under the
BSD-2-Clause option (`LICENSE.BSD-2-Clause`); `bpf_helper_defs.h` is generated
by libbpf and carries no SPDX line, the repository-level `LICENSE` covers it.

To update: download the same five files and the two licence files from a new
tag, replace them here, update the version and the hashes below, run
`../regen.sh`, and commit the new objects with the headers.

SHA-256 of every file here is in `SHA256SUMS` (checked by the
`ebpf-objects` workflow: `sha256sum -c SHA256SUMS`).
