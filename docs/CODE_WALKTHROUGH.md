# flowtap コード逐行解説

この文書は、eBPFを初めて学ぶ人が「なぜこの行が必要なのか」を追えるように、
実行される順番とsourceの行番号を対応させた解説書です。

対象は手書きの設定・Rust sourceです。次は逐行対象から除外します。

- `Cargo.lock`: Cargoが生成するdependencyの固定表
- 空行: 可読性のための区切り
- 単独の `{` / `}` / `);`: 周囲の説明に含める
- `README.md`、`CHANGELOG.md`、`docs/*.md`: 文章自体が説明になっている

行番号は `0.0.1-beta.1` 時点です。source変更後にずれた場合は、関数名や変数名で
検索してください。

## 1. 最初に全体像

```text
Linux event
    │
    ├─ sched_process_exec tracepoint ─┐
    ├─ tcp_v4_connect kprobe ─────────┤
    ├─ SSL_write uprobe ──────────────┤
    └─ SSL_read uprobe + uretprobe ───┤
                                      ▼
                           flowtap-ebpf/src/main.rs
                                      │
                               Ring Buffer
                                      │
                                      ▼
                             flowtap/src/main.rs
                                      │
                         PID correlation / redact
                                      │
                                table or JSON
```

三つのcrateへ分ける理由:

- `flowtap-common`: kernel側とuser側が同じbinary layoutを共有する
- `flowtap-ebpf`: `no_std` でeBPF bytecodeになる
- `flowtap`: 普通のLinux processとしてAyaでeBPFをloadする

## 2. directory / file一覧

| Path | 役割 |
|---|---|
| `.gitignore` | build生成物 `target/` をGit管理から外す |
| `Cargo.toml` | 3 crateをまとめるworkspace設定と共通version/dependency |
| `Cargo.lock` | 実際に解決されたdependency version。applicationなのでcommitする |
| `rust-toolchain.toml` | user-space buildに使うstable toolchain設定 |
| `README.md` | 利用者向けbuild/run/security/troubleshooting |
| `CHANGELOG.md` | releaseごとの変更履歴 |
| `LICENSE` | public sourceに適用するMIT License本文 |
| `docs/PUBLISHING.md` | public repositoryとbeta releaseの作り方 |
| `docs/CODE_WALKTHROUGH.md` | 今読んでいる学習用解説 |
| `flowtap-common/Cargo.toml` | 共有crateのmanifest |
| `flowtap-common/src/lib.rs` | Event、Config、定数 |
| `flowtap-ebpf/Cargo.toml` | eBPF crateのmanifest |
| `flowtap-ebpf/build.rs` | `bpf-linker` 変更時のrebuild設定 |
| `flowtap-ebpf/src/main.rs` | kernel内で実行されるprobe |
| `flowtap/Cargo.toml` | CLI crateのmanifest |
| `flowtap/build.rs` | eBPF crateをnightlyでbuildしCLIへ埋め込む準備 |
| `flowtap/src/main.rs` | CLI解析、load、attach、Ring Buffer受信 |
| `flowtap/src/output.rs` | PID相関、timestamp、table/JSON整形 |
| `flowtap/src/redact.rs` | HTTP header簡易maskとtest |

## 3. root設定

### `.gitignore`

| 行 | 解説 |
|---|---|
| 1 `/target` | Rustのobject、binary、build cacheは大きく再生成可能なのでcommitしない。先頭 `/` はrepository rootのtargetだけを指す。 |

### `rust-toolchain.toml`

| 行 | 解説 |
|---|---|
| 1 `[toolchain]` | rustupが読むtoolchain設定section。 |
| 2 `channel = "stable"` | 通常のCLIはstable Rustでbuildする。eBPFだけはbuild scriptが別途nightlyを選ぶ。 |
| 3 `components = ...` | format用rustfmtとlint用clippyもinstall対象にする。 |

### root `Cargo.toml`

| 行 | 解説 |
|---|---|
| 1 `[workspace]` | 複数crateを一つのCargo projectとして扱う。 |
| 2 `resolver = "2"` | feature解決の新しい規則を使い、build dependencyと通常dependencyのfeature混線を減らす。 |
| 3 `members = ...` | workspaceへCLI、共有型、eBPFの3 crateを登録する。 |
| 4 `default-members = ...` | bare `cargo build` ではCLIと共有型を入口にする。eBPFはCLIのbuild scriptから専用targetでbuildされる。 |
| 6 `[workspace.package]` | 各crateが継承できるpackage metadata。 |
| 7 `version` | prereleaseを含むSemVer。Git tagは `v0.0.1-beta.1` にする。 |
| 8 `edition = "2024"` | Rust 2024 editionのsyntaxとlint規則を使う。 |
| 9 `license` | source codeをMIT Licenseで公開することを宣言し、各crateへ継承する。 |
| 11 `[workspace.dependencies]` | dependency versionを一か所に集約する。 |
| 12 `anyhow` | user-spaceとbuild scriptのerrorへcontextを付ける。 |
| 13 `aya` | user-space eBPF loader。不要なdefault featureを切る。 |
| 14 `aya-build` | Cargo build中にeBPF crateを専用targetでbuildするhelper。 |
| 15 `aya-ebpf` | kernel側eBPF program API。 |
| 16 `cargo_metadata` | build scriptからworkspace package pathを調べる。 |
| 17 `chrono` | monotonic timestampをlocal RFC 3339文字列へ変換する。 |
| 18 `clap` | `--json` などのCLI optionを宣言的にparseする。 |
| 19 `libc` | `setrlimit`、`clock_gettime` 等のLinux C API binding。 |
| 20 `serde` | JSONへserializeするstructをderiveする。 |
| 21 `serde_json` | structからJSON Linesを生成する。 |
| 22 `tokio` | Ring Buffer fdとCtrl-Cを非同期に待つ。 |
| 23 `which` | build時に `bpf-linker` executableを探す。 |
| 25 profile header | `flowtap-ebpf` だけrelease profileを追加調整する。 |
| 26 `debug = 2` | eBPF objectへdebug/BTF生成に使う情報を残す。 |
| 27 `codegen-units = 1` | 最適化単位を一つにし、eBPF code生成を予測しやすくする。 |

## 4. 共有ABI: `flowtap-common`

### `flowtap-common/Cargo.toml`

| 行 | 解説 |
|---|---|
| 1 `[package]` | crate metadata開始。 |
| 2 `name` | Cargo上のcrate名。Rust codeでは `flowtap_common` とunderscoreになる。 |
| 3–5 `*.workspace = true` | version、edition、licenseをrootから継承する。 |
| 7 `[features]` | optional feature定義。 |
| 8 `default = []` | eBPF側では追加featureなし、つまりAya user-space crateを引かない。 |
| 9 `user = ["dep:aya"]` | user-spaceだけ `aya::Pod` 実装を有効にする。 |
| 11–12 | Ayaをoptional dependencyとして宣言する。 |

### `flowtap-common/src/lib.rs`

| 行 | 解説 |
|---|---|
| 1 `#![no_std]` | eBPFでも使えるよう標準libraryへ依存しない。 |
| 3 `COMM_LEN` | Linux `TASK_COMM_LEN` と同じ16 bytes。終端NULを含むため実文字は通常最大15 bytes。 |
| 4 `EXEC_DETAIL_LEN` | exec filename保存領域を256 bytesに固定する。 |
| 5 `MAX_PAYLOAD_BYTES` | verifierが追えるcompile-time上限。CLI optionの最大値もこれに合わせる。 |
| 7 `FLAG_TRUNCATED` | payloadが上限で切れたことを示すbit 0。 |
| 9 `#[repr(u8)]` | enumを必ず1 byteで表し、kernel/user間ABIを固定する。 |
| 10 derive | copy可能で比較・debug表示できるenumにする。 |
| 11 `EventType` | event種別の共有enum。 |
| 12 `Exec = 1` | 成功したexec。0を使わないことで未初期化/unknownと区別する。 |
| 13 `Connect = 2` | IPv4 TCP connect試行。 |
| 14 `TlsWrite = 3` | OpenSSLへ渡る暗号化前write buffer。 |
| 15 `TlsRead = 4` | OpenSSLが返した復号後read buffer。 |
| 18 impl開始 | EventTypeに変換・表示methodを追加する。 |
| 19 `from_u8` | wire上のraw byteを安全なenumへ変換する。 |
| 20–25 match | 1–4だけ受理し、壊れた値や将来値は `None` にする。 |
| 29 `as_str` | table/JSON用の固定event名を返す。 |
| 30–35 match | 各enumと表示文字列を一対一対応させる。 |
| 39 `#[repr(C)]` | C互換field順序でEventのmemory layoutを固定する。 |
| 40 derive | eBPF mapからRing Bufferへ値をcopyできるplain dataにする。 |
| 41 `Event` | 全event共通のwire format。 |
| 42 `timestamp_ns` | `bpf_ktime_get_ns` のmonotonic nanoseconds。 |
| 43–44 `pid` | kernelのTGID。user-spaceから見たprocess ID。 |
| 45–46 `tid` | kernelのPID。user-spaceから見たthread ID。 |
| 47 `payload_len` | `payload` のうち有効な先頭bytes数。 |
| 48 `detail_len` | exec filename領域の有効長。 |
| 49 `port` | CONNECT宛先port。user-spaceで扱いやすいhost byte order。 |
| 50 `addr_v4` | IPv4 addressのraw 32-bit値。 |
| 51 `event_type` | `EventType as u8` を格納する。enumそのものにせず未知値でもABIを読めるようにする。 |
| 52 `flags` | truncated等のbit field。 |
| 53 `_padding` | 後続 `comm` のoffsetを明示的に揃え、暗黙paddingを避ける。 |
| 54 `comm` | kernel task command name。 |
| 55 `detail` | exec filename用。CONNECT/TLSでは使用しない。 |
| 56 `payload` | TLS plaintext用の固定最大領域。 |
| 59 `#[repr(C)]` | Configもkernel/user間で同じlayoutにする。 |
| 60 derive | Array mapへ値copyできるようにする。 |
| 61 `Config` | CLIからeBPFへ渡す設定。 |
| 62 `max_payload_bytes` | TLS helperが読む最大bytes。 |
| 63 `target_pid` | 0なら無効、それ以外はTGID完全一致。 |
| 64 `filter_comm` | NUL paddingされた最大16-byte command filter。 |
| 65 `filter_comm_enabled` | comm filterの有無。boolのABI差を避けてu8にする。 |
| 66 `_padding` | struct末尾を明示的に4-byte alignmentへ揃える。 |
| 69–78 `Config::empty` | filterなし・payload 128 bytesという安全寄りの初期値を作る。 |
| 81 cfg | `user` feature時だけ次の実装をcompileする。 |
| 82 `unsafe impl aya::Pod` | Configがpointer等を含まないplain bytesだとAyaへ保証する。`repr(C)` と整数配列だけなので成立する。 |

## 5. eBPF crate

### `flowtap-ebpf/Cargo.toml`

| 行 | 解説 |
|---|---|
| 1–5 | package名とworkspace metadata継承。 |
| 7 `[dependencies]` | kernel側dependency開始。 |
| 8 `aya-ebpf` | map、helper、probe macroを提供する。 |
| 9 `flowtap-common` | user-spaceと同じEvent/Configをpath dependencyで使う。 |
| 11–12 | build script用に `which` を使う。 |
| 14–16 `[[bin]]` | `src/main.rs` を `flowtap` というeBPF ELFへbuildする。 |

### `flowtap-ebpf/build.rs`

| 行 | 解説 |
|---|---|
| 1 `fn main` | Cargoがcrate compile前に実行するbuild script。 |
| 2–3 comment | `bpf-linker` は普通のRust dependencyではなく外部executableだと説明する。 |
| 4 `which::which` | PATHからlinkerを探し、なければ早い段階で明確なerrorにする。 |
| 5 `rerun-if-changed` | linker binaryのmtimeが変わったらeBPFを再buildする。 |

### `flowtap-ebpf/src/main.rs`: crate属性とimport

| 行 | 解説 |
|---|---|
| 1 `#![no_std]` | kernel内にはRust標準libraryがないためcoreだけを使う。 |
| 2 `#![no_main]` | OS processの `main` entry pointを作らず、各probeをELF sectionへ出す。 |
| 4 `c_void` | raw BPF helperのuntyped pointerへcastするために使う。 |
| 6–15 `use aya_ebpf` | context、helper、attribute macro、map型、probe contextをimportする。 |
| 16–18 common import | 共有ABI、event種別、上限、flagをimportする。 |

### local struct

| 行 | 解説 |
|---|---|
| 20 `#[repr(C)]` | map valueのlayoutを固定する。 |
| 21 derive | mapへcopyする小さな値。 |
| 22 `ReadArgs` | SSL_read entryからreturnへ引き継ぐ値。 |
| 23 `buffer: u64` | user pointerを整数としてMapへ保存する。 |
| 26 `SockAddrIn` | kernelのIPv4 `struct sockaddr_in` の必要fieldだけを同じlayoutで表す。 |
| 27 `family` | AF_INETか確認する。 |
| 28 `port` | network byte orderのport。 |
| 29 `addr` | network byte order由来のIPv4値。 |
| 30 padding | sockaddr_in全体を16 bytesにする。 |

### eBPF map

| 行 | 解説 |
|---|---|
| 33 `#[map]` | staticをBPF map定義としてELF `maps` sectionへ出す。 |
| 34 `EVENTS` | 1 MiBの共有Ring Buffer。全CPUからuser-spaceへeventを送る。 |
| 36–37 comment | 4096-byte payloadを512-byte BPF stackへ置けない理由。 |
| 38–39 `SCRATCH` | CPUごとに1個の大きなEvent作業領域を確保する。 |
| 41–42 `CONFIG` | user-spaceがindex 0へ書く設定Array。 |
| 44–45 comment | entry/returnがCPUを跨ぎ得るためTID keyが必要。 |
| 46–47 `READ_ARGS` | 最大4096 thread分のSSL_read buffer pointerを保持するHashMap。 |

### EXEC tracepoint

| 行 | 解説 |
|---|---|
| 49 `#[tracepoint]` | 関数をtracepoint programとしてELFへ出す。 |
| 50 `process_exec` | user-spaceがこの名前でprogramを取得するentry。 |
| 51–54 match | 内部ResultをBPF programのu32 returnへ変換する。観測なのでkernel動作は変更しない。 |
| 57 `try_process_exec` | error propagationを `?` で書ける内部関数。 |
| 58–60 | PID/COMM filter不一致ならeventを作らず終了する。 |
| 62 `begin_event` | SCRATCHを初期化しEXEC種別にする。 |
| 64–65 comment | tracepoint record先頭8 bytesの後に `__data_loc filename` がある。 |
| 66 `read_at(8)` | record offset 8からu32 locatorをkernel helperで読む。unsafeなのはraw context layoutをcallerが保証するため。 |
| 67 | locator下位16 bitをfilename byte offsetとして取り出す。 |
| 68–70 | 異常offsetを拒否しverifierとmemory safetyを守る。 |
| 72–73 comment | tracepoint recordはkernel memoryなのでuser-read helperではない。 |
| 74 | context先頭pointerへoffsetを足しfilename pointerを作る。 |
| 75 | 最大256 bytesでNUL終端kernel文字列をdetailへcopyする。 |
| 76 | 実際に読めた長さを記録する。 |
| 79 | 完成したEventをRing Bufferへcopyする。 |
| 80 | 正常終了。 |

### IPv4 TCP CONNECT kprobe

| 行 | 解説 |
|---|---|
| 83 `#[kprobe]` | kernel function entry probeにする。 |
| 84 `tcp_v4_connect` | program名をhook先symbol名と揃えて分かりやすくする。 |
| 85–88 | 内部ResultをBPF returnへ変換する。 |
| 91 `try_tcp_v4_connect` | connect event本体。 |
| 92–94 | filterを最初に適用して不要なread/outputを避ける。 |
| 96–97 comment | 第2引数はsyscallからkernel内へcopy済みのsockaddrである。 |
| 98 `ctx.arg(1)` | Cの0-origin第2引数 `struct sockaddr *` を取得する。 |
| 99 `bpf_probe_read_kernel` | raw kernel pointerからlocal `SockAddrIn` へ安全にcopyする。 |
| 100–102 | familyがAF_INET=2でないeventを捨てる。 |
| 104 | CONNECT Eventを初期化する。 |
| 105–108 | addressとnetwork-to-host変換したportをEventへ保存する。 |
| 109–110 | Ring Bufferへ送り正常終了する。 |

### SSL_write uprobe

| 行 | 解説 |
|---|---|
| 113 `#[uprobe]` | user-space function entryへattachできるprogramにする。 |
| 114–119 | `ssl_write` entryとResult変換。 |
| 121 `try_ssl_write` | `SSL_write(SSL*, const void *buf, int num)` を読む。 |
| 122–124 | filter不一致ならplaintextへ触れない。 |
| 126 | 0-origin引数1、つまり送信buffer pointerを取得する。 |
| 127 | 引数2の要求lengthを取得する。 |
| 128–130 | NULLや0/negative lengthを無視する。 |
| 132 | 共通TLS capture処理へTLS_WRITEとして渡す。 |

### SSL_read entry / return

| 行 | 解説 |
|---|---|
| 135–141 | `SSL_read` entry用uprobe entryとResult変換。 |
| 143–146 | filter適用。 |
| 148 | `SSL_read(SSL*, void *buf, int num)` のbuffer引数を取得する。entry時点では中身はまだ復号結果ではない。 |
| 149–151 | NULL pointerを保存しない。 |
| 153–161 | current TIDをkeyにbuffer addressをREAD_ARGSへ保存し、map errorをi64へ変換する。 |
| 162 | entry probe完了。 |
| 165 `#[uretprobe]` | user function return時に呼ばれるprogramにする。 |
| 166–171 | `ssl_read_return` entryとResult変換。 |
| 173 | return処理本体。 |
| 174 | TGIDではなくthread IDを取得する。同一processの同時readを区別するため。 |
| 175–177 | 対応するentry dataがなければ終了する。 |
| 179–180 comment | map value pointerはremove後に無効になり得る。 |
| 181 | remove前に小さなReadArgsをvalue copyする。unsafe理由はraw map pointer dereference。 |
| 182 | 成否にかかわらずentry dataを削除し、pointerを残さない。 |
| 184 | OpenSSLのreturn value、つまり実際にreadできたbyte数を取得する。 |
| 185–187 | 0/negative returnまたはfilter不一致ならcaptureしない。 |
| 189–194 | 保存したbufferをTLS_READとして、実際のreturn lengthだけcaptureする。 |

### filter / Event初期化 / TLS copy

| 行 | 解説 |
|---|---|
| 197 `inline(always)` | 小関数callを消しverifierがcontrol flowを追いやすくする。 |
| 198 `should_trace` | 全probe共通filter。EbpfContext genericで各context型に対応する。 |
| 199–201 | CONFIGが読めない場合は観測を止めないdefault allow。 |
| 202 | map pointerからConfigをvalue copyする。 |
| 204–206 | target_pidが非0かつcurrent TGIDと不一致ならreject。 |
| 207–209 | comm filter無効ならaccept。 |
| 211–213 | current command取得に失敗した場合はfilterを安全側のrejectにする。 |
| 214 | 比較indexを0で初期化する。 |
| 215–220 | 固定16 bytesをloop比較し、一つでも違えばrejectする。 |
| 221 | 全条件を通過したのでaccept。 |
| 224 `inline(always)` | Event初期化もinline化する。 |
| 225 `begin_event` | SCRATCH pointerまたはerrorを返す。 |
| 226 | PerCpuArray index 0のmutable raw pointerを得る。 |
| 228–229 comment | 同じCPUではこのinvocation中のwriter競合がないというunsafe前提。 |
| 230 `unsafe` | raw map pointerのfieldを書き換えるscope。 |
| 231 | monotonic nanosecondsを記録する。 |
| 232 | process IDとしてTGIDを記録する。 |
| 233 | thread IDを記録する。 |
| 234–240 | eventごとに変わるlength/address/flag/paddingを初期化する。 |
| 241 | current commandを取得し、失敗時はzero配列にする。 |
| 243 | 初期化済みSCRATCH pointerを返す。 |
| 246–252 | `emit_tls` のsignature。context、種別、user pointer、OpenSSL lengthを受け取る。 |
| 253 | まず要求length全体を候補にする。 |
| 254–257 | CONFIG index 0の上限を読み、なければ128にする。 |
| 259–261 | CLI指定上限へclampする。 |
| 262–264 | Configが壊れていてもcompile-time最大4096を超えないよう再clampする。 |
| 265–267 | 最終長0なら何もしない。 |
| 269 | TLS Eventを初期化する。 |
| 270–275 | 有効payload長を設定し、切り詰めた場合はTRUNCATED bitを立てる。 |
| 277–278 comment | sourceはOpenSSL processのuser memory、destinationはBPF map memory。 |
| 279–285 | `bpf_probe_read_user` でcapture_lengthだけcopyする。これがTLS暗号解読ではなくlibrary buffer観測である核心。 |
| 286–288 | helperがnegative errorを返したらEventを送らない。 |
| 290–291 | 成功Eventを送る。 |
| 294–295 | 共通Ring Buffer output関数。 |
| 296–297 comment | outputが同期copyするためSCRATCH pointer lifetime内で安全。 |
| 298 | generic contextがここでは不要なのでunused警告を抑える。 |
| 299 | Event全体をRing Bufferへcopyする。失敗はbuffer fullを意味し、観測toolなのでkernel処理を止めずdropする。 |
| 302–306 | test以外のno_std binaryに必要なpanic handler。kernel内でunwindせずloopする。 |
| 308 | 次のstaticをELF `license` sectionへ置く。 |
| 309 | symbol名をmangleせずloaderが見つけられるようにする。 |
| 310 | GPL-compatible dual license文字列。GPL-only helper利用可能性にも関係する。 |

## 6. user-space CLI crate

### `flowtap/Cargo.toml`

| 行 | 解説 |
|---|---|
| 1–5 | package名とworkspace metadata。 |
| 7–16 dependencies | error、Aya、時刻、CLI、共有ABI、libc、JSON、async runtimeを追加する。 |
| 8 | user-spaceではanyhowのstandard library supportを有効にする。 |
| 9 | Aya loader本体。 |
| 10 | chronoのclock/std featureを有効にする。 |
| 11 | clap derive、help、usage、error contextを有効にする。 |
| 12 | commonの `user` featureを有効にしAya Pod実装を使う。 |
| 13 | Linux syscall binding。 |
| 14–15 | JSON serialization。 |
| 16 | Tokio macro、multi-thread runtime、fd、signal support。 |
| 18–21 | build scriptがeBPFをbuildするためのdependency。 |
| 23–25 | binary名とentry sourceを指定する。 |

### `flowtap/build.rs`

| 行 | 解説 |
|---|---|
| 1 | error contextと `anyhow!` macroをimportする。 |
| 2 | eBPF buildに使うtoolchain選択型。 |
| 4 | build scriptもfailureをCargoへ返せるResultにする。 |
| 5–6 | eBPF/common source変更時に再実行する。 |
| 8–11 | workspace metadataをdependency抜きで読み込む。 |
| 13–16 | package一覧から `flowtap-ebpf` を探し、なければ明示error。 |
| 18–22 | packageからnameとmanifest pathを取り出す。 |
| 23–30 | aya-build用packageへnameとcrate root directoryを渡す。 |
| 32 | defaultのnightly toolchainでBPF targetをbuildし、objectをOUT_DIRへ置く。 |

### `flowtap/src/main.rs`: option宣言

| 行 | 解説 |
|---|---|
| 1–2 | outputとredactを同じcrateのmoduleとして読み込む。 |
| 4–8 | memory size、Path、raw pointer helperをimportする。 |
| 10 | error contextと早期return macroをimportする。 |
| 11–15 | Aya loader、Array/RingBuf、program型をimportする。 |
| 16 | clap Parser trait。 |
| 17 | common定数・Config・Event。 |
| 18 | Eventを表示するProcessor。 |
| 19 | Ring Buffer fdとCtrl-Cを待つTokio API。 |
| 21 derive | Argsをcommand-line parserにする。 |
| 22–26 command属性 | binary名、version、help概要を生成する。versionはCargo.toml由来。 |
| 27 `Args` | CLI option全体。 |
| 28–30 `json` | `--json` boolean。 |
| 32–34 `pid` | `--pid` を1以上のu32に制限する。 |
| 36–38 `comm` | `--comm <STRING>`。追加のbyte長検証は後で行う。 |
| 40–42 `tls_plaintext` | 明示した場合だけTLS probeをload/attachするgate。 |
| 44–46 `libssl_path` | TLS optionと同時指定をclapが要求する。 |
| 48–54 `max_payload_bytes` | default 128、CLI parser段階で1..=4096に制限する。 |
| 56–58 `redact` | TLS有効時だけ使える簡易mask option。 |

### `main` の実行順

| 行 | 解説 |
|---|---|
| 61 `#[tokio::main]` | async mainをTokio runtime起動codeへ展開する。 |
| 62 | main全体をanyhow Resultにし、詳細errorを返す。 |
| 63 | command lineをArgsへparseする。無効値ならhelp付きで終了する。 |
| 64 | file存在やcomm byte長を追加検証する。 |
| 65 | 古いkernel向けにmemlock上限を上げる。 |
| 67–71 | build時に埋め込まれたalignment済みeBPF ELF bytesをAyaでloadする。 |
| 73 | CLI filter/max payloadをCONFIG mapへ書く。program load前なので最初のeventから有効。 |
| 74 | EXECとCONNECTを常にattachする。 |
| 75–80 | `--tls-plaintext` の場合だけ3個のTLS probeをattachする。defaultでplaintextは観測されない。 |
| 82–86 | opaque EVENTS mapをtyped RingBufへ変換する。 |
| 87 | RingBuf file descriptorをTokio AsyncFdへ登録する。Linuxではepollが使われる。 |
| 89 | 出力mode、redact、PID correlation stateを作る。 |
| 90 | table modeだけheaderを表示する。 |
| 92–93 | Ctrl-C futureを作り、loop内で継続pollできるようpinする。 |
| 94–116 | Ctrl-CかRing Buffer readableのどちらかを待つevent loop。 |
| 96–99 | Ctrl-Cならsignal errorを確認してloop終了。 |
| 100–101 | Ring Buffer readable notificationを待つ。 |
| 102 | 今ある全eventをdrainする。 |
| 103–104 | wire bytesをEventへdecodeできたらProcessorへ渡す。 |
| 105–111 | size不一致eventはpanicせず警告して捨てる。 |
| 113 | readiness flagをclearし次の通知を待てるようにする。 |
| 118 | eBPF objectをdropするとlinkもdetachされ、正常終了する。 |

### argument検証とattach helper

| 行 | 解説 |
|---|---|
| 121 `validate_args` | clapの相互依存以外のruntime検証。 |
| 122–130 | TLS有効時にlibssl path必須かつregular fileであることを確認する。 |
| 132 | comm指定時だけ内部を検証する。 |
| 133–135 | 空文字を拒否する。 |
| 136–138 | Linux commの終端NULを考慮し15 bytes以下にする。`len` はbyte長。 |
| 139–141 | Map内文字列を壊すNULを拒否する。 |
| 143 | 検証成功。 |
| 146 `write_config` | Argsを共有Configへ変換しBPF mapへ書く。 |
| 147 | filterなしdefault Configから始める。 |
| 148 | payload上限を反映する。 |
| 149 | PID未指定をsentinel 0へ変換する。 |
| 150–153 | comm bytesをzero-padded配列へcopyしenable flagを立てる。 |
| 155–158 | Ayaのopaque mapを `Array<Config>` へ型変換する。 |
| 159 | index 0へConfigを書き込む。最後の0はBPF map update flags。 |
| 162 `attach_core_programs` | 常時有効な2 programをload/attachする。 |
| 163–169 | process_execをTracePointへ変換、verifier load、sched tracepointへattachする。 |
| 171–178 | tcp_v4_connectをKProbeへ変換、load、kernel symbol offset 0へattachする。 |
| 179 | 両方成功。途中errorならmainへcontext付きで戻る。 |
| 182 `attach_tls_programs` | libssl pathへ3 programをまとめてattachする。 |
| 183–189 | SSL_write entry。 |
| 190–196 | SSL_read entry。 |
| 197–203 | 同じSSL_read symbolのreturn。 |
| 207–213 | 重複するUProbe load/attachを小さなhelperにする。 |
| 214–217 | program名でELF内programを探しUProbe型へ変換する。 |
| 218–220 | verifierへloadする。 |
| 221–223 | symbol、shared object、全process scopeを指定してattachする。eBPF側filterが先にcapture対象を絞る。 |
| 227 `decode_event` | Ring Buffer byte sliceを共有Eventへ戻す。 |
| 228–230 | Event全体より短いsampleを拒否する。 |
| 231–232 comment | Ring Buffer dataのaddressはRust Event alignmentを保証しない。 |
| 233 `read_unaligned` | `repr(C)` plain fieldsをunaligned copyする。unsafe前提はsource長を直前に検証済みであること。 |
| 236 `raise_memlock_limit` | BPF map/program用locked memory制限を緩和する。 |
| 237–240 | soft/hard limitをinfinityにしたC structを作る。 |
| 241–242 comment | libcへ渡すpointer lifetimeとfailure方針。 |
| 243 | `setrlimit(RLIMIT_MEMLOCK)` syscall wrapperを呼ぶ。 |
| 244–249 | 新しいmemcg accounting kernelでは不要な場合もあるため、failureはwarningに留める。 |

## 7. outputとPID相関

### `flowtap/src/output.rs`

| 行 | 解説 |
|---|---|
| 1–6 | HashMap、`/proc` read、IPv4表示、time型をimportする。 |
| 8 | local timezone RFC3339変換。 |
| 9 | wire Event、種別、truncated bit。 |
| 10 | JSON derive macro。 |
| 12 | TLS payload用redact関数。 |
| 14 derive | ProcessInfoをevent処理中にcloneできるようにする。 |
| 15–18 `ProcessInfo` | PIDごとの表示commと最後に観測したexec command line。 |
| 20–25 `Processor` | output mode、clock変換、PID correlation mapをまとめるstate。 |
| 27 impl | Processor method開始。 |
| 28–35 `new` | optionを保存しclock originと空HashMapを作る。 |
| 37 `print_header` | table headerを必要な場合だけ出す。 |
| 38 | JSON LinesではheaderがJSON parserを壊すので出さない。 |
| 39–42 | fixed widthのcolumn名を表示する。 |
| 46 `process` | Event一件を相関・整形・出力する中心関数。 |
| 47–49 | unknown event_typeを安全に捨てる。 |
| 51 | BPF monotonic timestampをlocal wall clockへ変換する。 |
| 52 | NUL終端commをStringへ変換する。 |
| 53 | flagsのTRUNCATED bitをtestする。 |
| 55 | event種別ごとに最終comm/detail/correlationを作る。 |
| 56–60 EXEC | eBPF filenameを読み、可能なら `/proc/PID/cmdline` の引数付き文字列を優先する。 |
| 61–67 | PID keyでProcessInfoをcacheする。次のCONNECT/TLSがこれを参照する。 |
| 68 | EXEC自身の表示値をtupleで返す。 |
| 70–75 CONNECT | 同じPIDのcache commがあれば使い、なければevent commを使う。 |
| 76 | raw IPv4をnetwork orderから変換して表示型にする。 |
| 77 | `IP:port` detailを作る。 |
| 78–79 | 直近exec commandをoptional correlationとして付ける。 |
| 81–86 TLS | CONNECTと同様にPID cache commを選ぶ。 |
| 87 | payload_lenを配列実長以下へ防御的にclampする。 |
| 88 | arbitrary bytesをinvalid UTF-8置換付きStringへ変換する。 |
| 89–93 | `--redact` 時だけHTTP header maskを適用する。 |
| 94–96 | captureを切ったeventへellipsisを付ける。 |
| 97–98 | correlationを添えてtupleを返す。 |
| 102 | JSON mode分岐。 |
| 103–112 | JSON用structへ全fieldを移す。 |
| 113–116 | 一行JSONへserializeし、failure時だけstderrへ出す。 |
| 117–126 | table modeではcolumn整形し、control characterを見えるescapeへ変換する。 |
| 130 derive | JsonEventをSerde serialize可能にする。 |
| 131–141 | JSON schema。`correlated_exec=None` は属性により出力から省略する。 |
| 143–145 `WallClock` | BPF monotonic 0に対応するwall-clock originを保持する。 |
| 147 impl | clock method開始。 |
| 148–152 | `clock_gettime` が書き込むtimespecをzero初期化する。 |
| 153–155 | BPFと同じCLOCK_MONOTONICを取得する。unsafeはC APIへのvalid pointerを渡すため。 |
| 156–160 | syscall成功ならDuration化し、failureならzero fallback。 |
| 161–164 | 現在wall clockから現在monotonicを引き、monotonic時刻0のwall timeを推定する。 |
| 167–171 | event nanosecondsをoriginへ足す。overflow時はUNIX_EPOCHへfallback。 |
| 172–173 | host local timezoneのmillisecond RFC3339へformatする。 |
| 177–178 `read_cmdline` | `/proc/PID/cmdline` を読み、process終了等のerrorはNoneにする。 |
| 179–183 | NUL区切りargumentsを空要素除外・lossy UTF-8変換してcollectする。 |
| 184–190 | argumentsをspace区切りcommand lineへjoinする。 |
| 193–198 `nul_terminated` | 最初のNULまでをcomm文字列にする。NULなしなら全slice。 |
| 201–207 `utf8_lossy` | requested lengthと配列長の小さい方、さらにNULまでをString化する。 |
| 210–217 `escape_table_detail` | backslash、CR、LF、TAB、NULを `\\r` 等へ変換し一event一行を守る。 |
| 219–227 test | table escapeが期待どおりか確認するunit test。 |

## 8. redact

### `flowtap/src/redact.rs`

| 行 | 解説 |
|---|---|
| 1 | HTTPらしいtextを受け取りmask後Stringを返す。 |
| 2 | inputと同程度のcapacityを先に確保して再allocationを減らす。 |
| 3 | 空行まではheader sectionだと覚える。 |
| 4 | newlineを残したまま一行ずつ処理する。 |
| 5–11 | CRLF、LF、newlineなしをbodyとline endingへ分ける。 |
| 13–15 | 空行でHTTP header終了と判定する。 |
| 16–20 | body部分は変更せずcopyし、次のlineへ進む。 |
| 22–26 | colonがないrequest/status line等はそのままcopyする。 |
| 27 | colon前をtrimしてheader名を得る。 |
| 28–33 | mask対象header名を列挙する。 |
| 34–35 | ASCII case-insensitiveで一致判定する。 |
| 37 | sensitive header分岐。 |
| 38 | 元のheader名とcolonまでは保持する。 |
| 39 | 値全体を `[REDACTED]` へ置換する。 |
| 40–42 | 非対象headerは変更しない。 |
| 43 | 元のCRLF/LFを戻す。 |
| 45 | 完成Stringを返す。 |
| 48–50 | test build時だけtest moduleと対象関数を読み込む。 |
| 52–66 | case差を含むAuthorization/Cookieがmaskされ、Hostとsecret非残存を検証する。 |
| 68–74 | 最終lineにnewlineがなくてもSet-Cookieをmaskするtest。 |
| 76–80 | header/body境界後の `Cookie:` 文字列を本文として変更しないtest。 |

## 9. 一つのeventを追跡する練習

### `curl http://example.com/` のCONNECT

1. curlが `connect(2)` を呼ぶ
2. kernel内で `tcp_v4_connect` に到達する
3. kprobeの `ctx.arg(1)` が宛先sockaddrを得る
4. `begin_event` がPID/TID/COMM/timeを入れる
5. address/portを追加しRing Bufferへ送る
6. AsyncFdがreadableになる
7. `decode_event` がbytesをEventへcopyする
8. Processorが同じPIDのEXEC cacheを探す
9. `93.184.216.34:80` をtableまたはJSONへ出す

### `curl https://example.com/` のTLS_READ

1. `SSL_read` entry uprobeがTIDとbuffer pointerをMapへ保存する
2. OpenSSLがTLS recordを復号してbufferへplain bytesを書く
3. `SSL_read` return uretprobeが実際のread byte数を得る
4. TIDでentry dataを取得し、Mapから削除する
5. `min(retval, --max-payload-bytes, 4096)` bytesだけuser memoryから読む
6. TLS_READ EventをRing Bufferへ送る
7. Processorが必要ならAuthorization/Cookieをmaskする
8. tableではCR/LFをvisible escapeし、JSONではSerdeがescapeする

## 10. `unsafe` を復習する

このprojectの `unsafe` は主に「kernel/C APIのraw pointerをRustが自動検証できない」
境界に限定しています。

| 場所 | なぜ必要か | 呼び出し側が保証すること |
|---|---|---|
| tracepoint `read_at` | raw tracepoint layoutを読む | offset 8が標準formatのdata_loc |
| `ctx.as_ptr().add` | raw pointer arithmetic | offsetを8..=4096に検証済み |
| BPF probe-read helpers | kernel/user addressを読む | hook signatureとmemory種別が正しい |
| map pointer read/write | BPF map APIがraw pointerを返す | invocation中のpointer lifetimeとPerCpu排他 |
| `aya::Pod for Config` | Ayaへplain-byte性を宣言 | repr(C)かつinteger/arrayのみ |
| `read_unaligned` | Ring BufferはEvent alignmentを保証しない | sample sizeを先に検証済み |
| `clock_gettime` | C API | initialized timespecへのvalid mutable pointer |
| `setrlimit` | C API | initialized rlimitへのvalid pointer |

`unsafe` は「危険なので使ってはいけない」ではなく、「compilerの代わりにprogrammerが
前提を証明する小さな境界」です。コメントにはその前提を書くのが大切です。

## 11. 次に試す学習課題

1. `EventType::Exit` と `sched_process_exit` を追加しPID cacheを削除する
2. Ring Buffer drop counterをMapに追加する
3. EXECのargvをsys_enter_execve entryで取得し、成功eventと相関する
4. `tcp_v4_connect` entry/returnをTIDで相関し成功/失敗errnoを表示する
5. TLS Eventだけvariable-length Ring Buffer recordへして転送量を減らす
6. `SSL_write_ex` / `SSL_read_ex` を別experimental optionで追加する

一度に全部入れず、一つ追加するたびに「共有ABI → eBPF → attach → output → test」の順で
小さく動作確認すると、verifier errorの原因を絞りやすくなります。
