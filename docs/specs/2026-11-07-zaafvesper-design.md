# ZAAFVesper — sensor keamanan macOS bergaya Fibratus

**Tanggal:** 7 Nov 2026 · **Status:** DISETUJUI 7 Nov 2026 (dengan YARA di MVP)
**Keputusan terkunci:** macOS dulu dengan engine netral platform · Go · deteksi dengan kill opsional

> Nama kerja awal proyek ini "Ronda"; diganti menjadi **ZAAFVesper** pada 7 Nov 2026 atas permintaan Rifqi.

## 1. Tujuan dan kriteria sukses

Sensor endpoint untuk macOS yang mengamati event sistem secara realtime, mencocokkannya dengan rule perilaku yang dipetakan ke MITRE ATT&CK, lalu memberi alert, merekam capture forensik, dan (bila diizinkan) mematikan proses.

ZAAFVesper dinyatakan berhasil bila:
1. `sudo zaafvesper run` menampilkan alert dalam waktu kurang dari 1 detik setelah perilaku terjadi.
2. Setiap rule bawaan punya fixture positif dan negatif, dan `zaafvesper rules test` hijau 100%.
3. Minimal 20 rule bawaan tervalidasi dengan atomic test macOS yang nyata (GUID tercatat di rule).
4. Engine mengevaluasi minimal 20.000 event per detik di Apple Silicon (benchmark Go).
5. `zaafvesper replay` berjalan tanpa root, sehingga rule bisa dikembangkan dan dites dari capture.

## 2. Pelajaran dari 5 repo yang direview

| Repo | Yang diambil | Yang tidak diambil |
|---|---|---|
| **rabbitstack/fibratus** | Pipeline source → snapshot proses → filter → rule → aksi. Bahasa rule `field op value`, `imatches` glob, macro, `sequence maxspan … by …`, `%field` di output, label ATT&CK, capture plus replay, aktivasi event berdasarkan rule yang dimuat. | ETW, callstack, PE parsing, filament Python, YARA (fase 2). |
| **redcanaryco/atomic-red-team** | 318 tes macOS sebagai **bukti deteksi**. Field `tests.atomic` di rule menautkan ke GUID tes. | Menjalankan tes otomatis tanpa izin. |
| **olafhartong/sysmon-modular** | Konfigurasi telemetri modular (`config.d/*.yml`, digabung), include/exclude per jenis event untuk menekan noise, tag teknik per event, layer ATT&CK Navigator untuk cakupan. | Format XML Sysmon (adapter Windows di fase 2). |
| **A-poc/RedTeam-Tools** | Daftar tradecraft macOS dan Unix yang perlu dideteksi (osascript prompt, dylib injection, persistence plist). | Tooling ofensif. |
| **mukul975/Anthropic-Cybersecurity-Skills** | Pola penulisan deteksi (Sysmon, YARA, Sigma). Celah yang terkonfirmasi: tidak ada skill Endpoint Security macOS. | Tidak dipasang, hanya dibaca. |

## 3. Pendekatan sumber event (dipilih: A)

| | Pendekatan | Kelebihan | Kekurangan |
|---|---|---|---|
| **A ✅** | Membungkus `/usr/bin/eslogger` (JSON per baris di stdout) | Tanpa entitlement Apple, sudah ada di macOS 13+, 104 jenis event | Butuh root dan Full Disk Access untuk terminal. Hanya bisa mengamati (NOTIFY), tidak bisa memblokir (AUTH). |
| B | Klien Endpoint Security native (cgo, `es_new_client`) | Bisa AUTH/blokir, latensi rendah | Butuh entitlement `com.apple.developer.endpoint-security.client` dari Apple atau SIP dimatikan |
| C | OpenBSM / audit | Data lama | Sudah deprecated di macOS modern |

Sumber event berada di balik interface `source.Source`, jadi B bisa menggantikan A kelak tanpa mengubah engine.

## 4. Arsitektur

```
eslogger ─▶ source/eslogger ─▶ normalize ─▶ ps.Snapshotter ─▶ engine ─▶ alert sinks (konsol, JSONL)
  (JSON)     (decode, drop       (Event         (pohon proses,    │  ├▶ respons (kill, bergerbang)
              awal per config)   netral)         leluhur, uuid)   │  └▶ capture (.rcap = gzip JSONL)
                                                                  └─ rules (YAML) + macros + exclusions
replay(.rcap) ────────────────────────────────▲  (jalur yang sama, tanpa root)
```

Paket Go (`github.com/rifqifitriady/ZAAFVesper`, lisensi Apache-2.0):

| Paket | Tanggung jawab tunggal |
|---|---|
| `pkg/event` | Tipe `Event` netral platform plus registry field. **Kontrak bersama.** |
| `pkg/source/eslogger` | Menjalankan eslogger dengan jenis event yang dibutuhkan, decode JSON, lalu memetakan ke `Event`. |
| `pkg/ps` | Snapshot proses dari fork, exec, dan exit. Menyediakan leluhur, `ps.uuid` (pid + pidversion), dan bootstrap proses yang sudah berjalan via `sysctl`. |
| `pkg/filter/ql` | Lexer, parser AST, dan evaluator bahasa rule. |
| `pkg/rules` | Memuat YAML, ekspansi macro, kompilasi, indeks per `evt.name`, mesin `sequence`, exclusion. |
| `pkg/alert` | Sink alert konsol (aman dari escape ANSI) dan file JSONL. |
| `pkg/response` | Aksi `kill` dengan pagar pengaman. |
| `pkg/capture` | Menulis dan membaca `.rcap`. |
| `pkg/config` | `zaafvesper.yml` + `config.d/*.yml` (gaya sysmon-modular). |
| `cmd/zaafvesper` | CLI. |

### 4.1 Model event (field yang bisa dipakai rule)

`evt.name`, `evt.time`, `evt.seq` · `ps.pid`, `ps.ppid`, `ps.uuid`, `ps.exe`, `ps.name`, `ps.cmdline`, `ps.args`, `ps.cwd`, `ps.uid`, `ps.euid`, `ps.username`, `ps.signing_id`, `ps.team_id`, `ps.is_platform`, `ps.is_signed`, `ps.cdhash`, `ps.tty` · `ps.parent.*` (field yang sama) · `ps.ancestors` (daftar exe) · `file.path`, `file.name`, `file.dir`, `file.ext`, `file.dest` (rename/link) · `target.ps.*` (get_task, signal, ptrace) · `evt.arg[nama]` untuk detail khusus event (misalnya `evt.arg[xattr]`, `evt.arg[signal]`, `evt.arg[env.DYLD_INSERT_LIBRARIES]`).

Pemetaan event ES ke `evt.name` (MVP, ±20 jenis): exec→`CreateProcess` · fork→`Fork` · exit→`TerminateProcess` · open→`OpenFile` · create→`CreateFile` · write/close(modified)→`WriteFile` · rename→`RenameFile` · unlink→`DeleteFile` · setextattr/deleteextattr→`SetXattr`/`DeleteXattr` · setmode/setowner→`SetMode`/`SetOwner` · get_task→`OpenProcess` · signal→`Signal` · trace→`Ptrace` · remote_thread_create→`CreateRemoteThread` · btm_launch_item_add→`AddLaunchItem` · mount→`Mount` · kextload→`LoadKext` · authentication→`Authenticate` · sudo→`Sudo` · tcc_modify→`ModifyTCC` · xp_malware_detected→`XProtectDetect`.

Sumber hanya berlangganan jenis event yang dipakai oleh rule aktif (prinsip "approver" Fibratus). Event `open` dan `write` sangat ramai, jadi exclusion prefix path dipasang paling awal.

### 4.2 Bahasa rule (kompatibel-gaya Fibratus)

- Operator: `and or not`, `= != < <= > >=`, `in`, `iin`, `contains icontains`, `startswith istartswith`, `endswith iendswith`, `matches imatches` (glob `*` `?`), `regex`, serta daftar `('a','b')` di semua operator string.
- Fungsi MVP: `base()`, `dir()`, `ext()`, `length()`, `lower()`.
- Macro: `- macro: spawn_process\n  expr: evt.name = 'CreateProcess'`, dan juga macro daftar (`list:`).
- Sequence:
  ```
  sequence maxspan 2m
    |create_file and file.path imatches '/tmp/*'| by file.path
    |spawn_process| by ps.exe
  ```
  Join bisa global (`by ps.uuid`) atau per langkah. Output merujuk langkah dengan `%1.file.path`. Sebagian sequence yang kedaluwarsa dibuang. Status dibatasi 10.000 partial per rule (yang paling lama dibuang lebih dulu).

### 4.3 Skema rule

```yaml
name: Launch Agent persistence via plist write
id: 6f1c…              # UUID
version: 1.0.0
description: …
labels: {tactic.id: TA0003, technique.id: T1543.001, technique.name: Launch Agent}
references: [https://attack.mitre.org/techniques/T1543/001/]
condition: >
  create_file and file.path imatches ('/Users/*/Library/LaunchAgents/*.plist', '/Library/LaunchAgents/*.plist')
  and not ps.signing_id in ('com.apple.xpc.launchd', 'com.apple.backgroundtaskmanagementd')
output: "%ps.exe membuat launch agent %file.path"
severity: high          # info|low|medium|high|critical
action: []              # [{name: kill}] → hanya aktif dengan --enable-response
tests:
  atomic: [a5983dee-bf6c-4eaf-951c-dbc1a7b90900]
min-engine-version: 0.1.0
```
Fixture rule ada di `rules/testdata/<file>.yml` berisi `match:` dan `nomatch:` (daftar event).

### 4.4 Rule bawaan MVP (±25, macOS)

Persistence: Launch Agent/Daemon (T1543.001/.004), shell profile (T1546.004), StartupItems (T1037.005), Login Item via osascript (T1547.015), cron/periodic, emond (T1546.014).
Stealth/Impairment: penghapusan atribut quarantine (T1553.001), `spctl --master-disable`, `DYLD_INSERT_LIBRARIES` (T1574.006), menyembunyikan file via `chflags hidden` (T1564.001), mematikan firewall atau logging (T1562), penghapusan log (T1070.002).
Credential Access: `security dump-keychain` dan akses file keychain oleh proses non-Apple (T1555.001), prompt password via osascript (T1056.002), akses kunci SSH oleh proses tak biasa (T1552.004), akses store kredensial browser (T1555.003).
Discovery/Collection: screencapture senyap (T1113), enumerasi software keamanan (T1518.001), `system_profiler`/`sw_vers` beruntun (sequence T1082).
Execution/C2: curl/wget yang di-pipe ke shell (T1059.004 + T1105), binary dijalankan dari `/tmp` atau `/Users/Shared` lalu tanpa tanda tangan (sequence), osascript JXA dari parent tak lazim (T1059.002), `get_task` ke proses lain oleh binary tanpa tanda tangan (T1055).

### 4.5 Respons (kill) dan pengaman

- Mati secara default. Baru aktif dengan `--enable-response` **dan** rule yang menyebut `action: [{name: kill}]`.
- Tidak pernah membunuh pid ≤ 1, ZAAFVesper sendiri, `kernel_task`, `launchd`, `WindowServer`, `loginwindow`, binary platform Apple dalam daftar terlindung, atau parent dari eslogger.
- Membatasi maksimal 10 kill per menit. Kill selalu dicatat, dan `--dry-run-response` hanya mencatat apa yang akan dimatikan.
- Karena sifatnya reaktif (NOTIFY), kill terjadi sesudah perilaku. Ini dinyatakan jujur di README.

### 4.6 Keamanan ZAAFVesper sendiri (berjalan sebagai root)

- File rule dan config harus milik root dan tidak bisa ditulis grup atau publik saat berjalan sebagai root. Bila tidak, ZAAFVesper menolak start, karena siapa pun yang bisa menulis rule bisa memaksa kill.
- Field dari event (path, cmdline) dibersihkan dari karakter kontrol sebelum dicetak ke terminal (cegah injeksi ANSI).
- ZAAFVesper tidak memakai shell dan tidak memanggil `exec` dengan string dari event. Regex di-compile dengan RE2 (Go), jadi tidak ada ReDoS.
- Ukuran baris JSON dibatasi (16 MB), dan decode yang gagal dihitung, bukan membuat panic.

### 4.6b YARA (masuk MVP atas permintaan Rifqi)

- Paket `pkg/yara` memakai `github.com/hillu/go-yara/v4` (cgo, libyara dari Homebrew) di balik build tag `yara`. Build tanpa tag tetap pure-Go, dan YARA dinonaktifkan dengan peringatan.
- Pemicu: setiap `CreateProcess` memindai `ps.exe` (plus `file.path` pada `CreateFile`/`WriteFile` ke direktori yang dikonfigurasi, default `/tmp`, `/Users/*/Downloads`, `/Users/Shared`).
- Hasil pemindaian disuntikkan kembali sebagai event sintetis `evt.name = 'YaraMatch'` dengan field `yara.rule`, `yara.namespace`, `yara.tags`, `yara.meta[...]`, plus konteks proses. Dengan begitu rule biasa bisa memakainya, misalnya `yara_match and yara.tags in ('stealer')`, dan rule bawaan "YARA signature match" memberi alert.
- Pagar kinerja dan keamanan: worker pool (default 2), batas ukuran file 64 MB, timeout 10 detik per scan, cache hasil per (path, ukuran, mtime) atau cdhash, file dibuka dengan `O_NOFOLLOW` dan hanya file reguler. Rule YARA berada di `rules/yara/*.yar`, dikompilasi saat start, dan tunduk pada aturan kepemilikan root yang sama.
- Rule YARA contoh: beberapa rule generik untuk infostealer macOS (pola AMOS/Atomic Stealer, misalnya string osascript prompt dan path keychain), ditulis sendiri, bukan disalin.

### 4.7 CLI

`zaafvesper run [--rules dir] [--config f] [--capture out.rcap] [--enable-response] [--json alerts.jsonl]` · `zaafvesper replay <file.rcap|eslogger.jsonl>` (tanpa root, juga menerima output mentah eslogger) · `zaafvesper rules list|validate|test` · `zaafvesper coverage --navigator layer.json` (layer ATT&CK Navigator, seperti attack_matrix di sysmon-modular) · `zaafvesper version`.

## 5. Pengujian dan validasi

1. **Unit:** golden test lexer/parser, evaluator berbasis tabel, mesin sequence dengan jam palsu, decoder eslogger dengan fixture JSON.
2. **Rule:** `zaafvesper rules test` memeriksa fixture match dan nomatch untuk setiap rule (wajib di CI).
3. **Benchmark:** `go test -bench` untuk evaluasi engine, target ≥ 20k event/detik.
4. **Validasi atomic (butuh persetujuanmu per batch):** kamu menjalankan `sudo zaafvesper run --capture` di terminal, lalu aku menjalankan atomic test macOS yang jinak dan punya cleanup (daftar GUID ditampilkan dulu), lalu memeriksa apakah rule menyala. Capture yang dihasilkan disimpan sebagai fixture regresi.
5. **Risiko utama:** skema JSON eslogger di macOS 26 bisa berbeda dari dokumentasi. Mitigasinya: decoder toleran (field opsional), plus satu capture nyata darimu di awal untuk mengonfirmasi.

## 6. Di luar cakupan MVP (fase 2+)

Adapter Windows (Sysmon EVTX/JSON dengan konfigurasi sysmon-modular) · adapter Linux · telemetri jaringan (ES tidak punya event connect socket, butuh NetworkExtension) · klien ES native untuk blokir (AUTH) · instalasi LaunchDaemon · output webhook/SIEM · import Sigma.

## 7. Cara kerja tim

Kontrak `pkg/event` ditulis lebih dulu oleh thread utama. Setelah itu dua agent bekerja paralel di paket yang tidak bersinggungan: (1) engine (`filter/ql`, `rules`, `alert`, `response`, `capture`, CLI), dan (2) sumber, normalisasi, snapshot proses, serta rule bawaan dengan fixture. Lalu `judge` (SPEC sebelum mulai, VERDICT sesudah), `security-expert`, dan `security-audit`. Repo lokal di `~/Claude/Skills/zaafvesper`, tanpa push sampai kamu minta.
