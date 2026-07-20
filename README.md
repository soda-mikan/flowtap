# flowtap

Rust + [Aya](https://aya-rs.dev/) で作る、学習用の小さな Linux
observability CLI です。プロセスの `exec` と IPv4 TCP `connect` を観測し、
同じ PID のイベントを1本のストリームとして表示します。

追加の experimental 機能として、明示的に有効化した場合だけ OpenSSL の
`SSL_write` / `SSL_read` に uprobe / uretprobe を付け、TLSライブラリへ渡る
平文バッファの先頭を観測できます。

> [!CAUTION]
> TLS plaintext 機能はTLS暗号を解読するものではありません。対象ホスト上の
> OpenSSLプロセスで、暗号化前または復号後のメモリを限定的に読み取ります。
> 本人が管理するホスト、許可を得たプロセス、検証環境でのみ使用してください。
> payload取得はデフォルトで無効です。

## MVPの範囲

- `sched:sched_process_exec` tracepoint: 成功した `exec` を取得
- `tcp_v4_connect` kprobe: IPv4 TCP接続試行と宛先を取得
- BPF Ring Buffer: eBPFからユーザー空間へイベントを転送
- PIDごとの直近のEXECをユーザー空間で保持し、後続CONNECT/TLSイベントと相関
- table出力（デフォルト）とJSON Lines出力（`--json`）
- eBPF側での完全一致フィルタ（`--pid`、`--comm`）
- experimental OpenSSL plaintext（明示的な `--tls-plaintext` のみ）

XDP、LSM、Kubernetes、IPv6、他のTLS実装は含みません。Go `crypto/tls`、
rustls、Java、NSS、GnuTLS、BoringSSL は観測対象外です。

## 構成

```text
.
├── flowtap/          # ユーザー空間CLI、出力、PID相関、redact
├── flowtap-ebpf/     # tracepoint / kprobe / uprobe / uretprobe
└── flowtap-common/   # 両側で共有するrepr(C)のイベント型
```

大きなpayloadを512-byteのBPFスタックへ置かないため、eBPF側では
`PerCpuArray<Event>` を作業領域として使います。`SSL_read` のentryでは
`tid -> buffer pointer` をHashMapへ保存し、returnで戻り値が正の場合だけ読み、
必ずMapから削除します。

学習・公開用の補助資料:

- [コード逐行解説](docs/CODE_WALKTHROUGH.md)
- [GitHub public repository / beta release手順](docs/PUBLISHING.md)
- [変更履歴](CHANGELOG.md)

## 必要条件

- Linux（ビルド自体もLinux上を推奨）
- 64-bit x86_64 または aarch64
- Rust stable（ユーザー空間）と Rust nightly + `rust-src`（eBPF）
- `bpf-linker`
- root、またはディストリビューションに応じたBPF/perfのcapability
- 実用上 Linux 5.8以降を推奨

Ring BufferのためLinux 5.8以降が必要です。kprobe/uprobe自体は4.1、
tracepointは4.7以降ですが、flowtap全体の最小条件は5.8です。
ただし古いカーネル、lockdown、コンテナ、ディストリビューション
独自設定では利用できない場合があります。主に次のkernel configが必要です。

```text
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_KPROBES=y
CONFIG_UPROBE_EVENTS=y
CONFIG_TRACEPOINTS=y
CONFIG_PERF_EVENTS=y
```

BTFやカーネルヘッダはこのMVPでは必須ではありません。

## ビルド

```bash
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release
```

成果物は `target/release/flowtap` です。eBPF objectはbuild scriptで生成され、
CLIバイナリへ埋め込まれます。

macOSではロード・実行できません。Linuxターゲットへのcross compileは可能ですが、
最初の動作確認はLinuxホスト上で行うのが簡単です。

## 基本的な実行

全イベントをtable表示します。

```bash
sudo ./target/release/flowtap
```

別ターミナルでイベントを発生させます。

```bash
curl http://example.com/
```

出力例:

```text
TIME                             PID     COMM            EVENT       DETAIL
2026-07-09T01:23:10.123+09:00    2311    curl            EXEC        curl http://example.com/
2026-07-09T01:23:10.130+09:00    2311    curl            CONNECT     93.184.216.34:80
```

EXEC時に `/proc/<pid>/cmdline` がまだ読めれば引数を含むコマンドラインを表示し、
読めなければtracepointが持つ実行ファイル名へfallbackします。

### JSON Lines

```bash
sudo ./target/release/flowtap --json
```

```json
{"time":"2026-07-09T01:23:10.130+09:00","pid":2311,"tid":2311,"comm":"curl","event":"CONNECT","detail":"93.184.216.34:80","correlated_exec":"curl http://example.com/","truncated":false}
```

### PID / command filter

```bash
sudo ./target/release/flowtap --pid 2311
sudo ./target/release/flowtap --comm curl
```

`--comm` はLinuxのtask command nameとの完全一致で、最大15 bytesです。
両方を指定した場合はAND条件です。フィルタはeBPF側でイベント生成前に適用されます。

## Experimental: OpenSSL TLS plaintext

まず対象の `curl` がOpenSSLを使っているか、実際のlibssl pathを確認します。

```bash
ldd "$(command -v curl)" | grep -E 'libssl|libgnutls|libnss'
readlink -f /lib/x86_64-linux-gnu/libssl.so.3
```

次にflowtapを起動します。`--libssl-path` は自動検出せず、対象プロセスがロードする
共有オブジェクトの正確なpathを指定します。

```bash
sudo ./target/release/flowtap \
  --comm curl \
  --tls-plaintext \
  --libssl-path /lib/x86_64-linux-gnu/libssl.so.3 \
  --max-payload-bytes 128 \
  --redact
```

別ターミナル:

```bash
curl --http1.1 https://example.com/
```

出力例:

```text
TIME                             PID     COMM            EVENT       DETAIL
2026-07-09T01:23:10.123+09:00    3211    curl            TLS_WRITE   GET / HTTP/1.1\r\nHost: example.com\r\n…
2026-07-09T01:23:10.150+09:00    3211    curl            TLS_READ    HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n…
```

`--max-payload-bytes` のデフォルトは128、範囲は1..=4096です。元のバッファが
上限より長い場合、tableでは末尾に `…`、JSONでは `"truncated": true` が付きます。

`--redact` は次のHTTP header値を大文字小文字を無視して `[REDACTED]` に置き換えます。

- `Authorization`
- `Proxy-Authorization`
- `Cookie`
- `Set-Cookie`

これは文字列ベースの簡易処理です。分割されたTLS write/read、HTTP/2、
非HTTP payload、独自credential形式を完全には保護しません。秘密情報を扱う環境では、
`--tls-plaintext` 自体を有効にしないでください。

OpenSSL 3を使う全てのアプリが必ず `SSL_write` / `SSL_read` を直接呼ぶとは限りません。
`SSL_write_ex` / `SSL_read_ex` のみを使うアプリは今回の対象外です。

## 動作確認コマンド

```bash
# format / unit test / build
cargo fmt --all -- --check
cargo test
cargo build --release

# hookと基本イベント
sudo ./target/release/flowtap --comm curl
curl http://example.com/

# JSON
sudo ./target/release/flowtap --json --comm curl
curl http://example.com/

# experimental TLS（別ターミナルからcurlを実行）
sudo ./target/release/flowtap \
  --json --comm curl --tls-plaintext \
  --libssl-path /lib/x86_64-linux-gnu/libssl.so.3 \
  --max-payload-bytes 128 --redact
curl --http1.1 -H 'Authorization: Bearer test-secret' https://example.com/
```

ロード後の確認:

```bash
sudo bpftool prog list | grep -E 'process_exec|tcp_v4_connect|ssl_'
sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format
sudo grep -w tcp_v4_connect /proc/kallsyms
```

## トラブルシュート

### `Operation not permitted` / `Permission denied`

まずrootで実行してください。コンテナ内ではhost PID namespace、perf_event、
BPF syscallが制限されるため、Linuxホスト上での実行を推奨します。
Secure Boot / kernel lockdownや以下も確認します。

```bash
sysctl kernel.unprivileged_bpf_disabled
sysctl kernel.perf_event_paranoid
cat /sys/kernel/security/lockdown 2>/dev/null || true
ulimit -l
```

### `failed to attach kprobe tcp_v4_connect`

対象kernelでsymbolが存在し、kprobe可能か確認します。

```bash
sudo grep -w tcp_v4_connect /proc/kallsyms
sudo cat /sys/kernel/tracing/available_filter_functions | grep -w tcp_v4_connect
```

symbolのinline化、非公開化、kprobe禁止kernelではこのMVPは動きません。

### EXECが出ない

tracepointとfield layoutを確認します。この実装は標準の
`sched_process_exec` format（8-byte common headerの直後に
`__data_loc char[] filename`）を使用します。

```bash
sudo test -e /sys/kernel/tracing/events/sched/sched_process_exec/format
sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format
```

### TLSイベントが出ない

次を順に確認してください。

1. `curl -V` と `ldd "$(command -v curl)"` でOpenSSL利用を確認する
2. `readlink -f` で `--libssl-path` が対象processの実体libsslと一致するか確認する
3. symbolがdynamic symbol tableにあるか確認する
4. `--comm` / `--pid` が対象に一致するか確認する
5. アプリが `SSL_write_ex` / `SSL_read_ex` だけを使っていないか確認する

```bash
readelf -Ws /lib/x86_64-linux-gnu/libssl.so.3 |
  grep -E ' SSL_(read|write)(@@|$)'
```

UbuntuのcurlがGnuTLS版、静的link、別namespace内のlibssl、BoringSSLなどの場合は
今回の実装では観測できません。

### verifier error

kernel logとAyaが返すverifier logを確認してください。

```bash
sudo dmesg --ctime | tail -n 100
```

この実装では大きなEventをPerCpuArrayへ逃がし、loopを小さく固定し、TLS read長を
4096以下へclampしています。それでも古いkernelのverifier差異があるため、
問題報告時はkernel version、architecture、verifier logを添えてください。

## 現在の制約

- CONNECTは接続成功ではなく `tcp_v4_connect` の接続試行
- IPv4のみ
- PID相関はflowtap起動後に観測したEXECのみ
- process exitを追跡しないため、長時間実行ではPID再利用まで古い相関情報が残り得る
- Ring Bufferが満杯の場合はイベントをdropする（eBPF処理自体は継続）
- TLS captureはOpenSSL `SSL_write` / `SSL_read` のみ
- redactはbest-effortであり、機密情報除去の保証ではない

脆弱性の非公開報告方法と、安全な運用上の注意は
[Security Policy](SECURITY.md)を参照してください。

## License

MIT
