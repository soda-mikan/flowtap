# Changelog

このプロジェクトの主な変更を記録します。バージョン番号は
[Semantic Versioning](https://semver.org/) に従います。

## [Unreleased]

## [0.0.3-beta] - 2026-07-20

### Security

- TLS plaintext取得に`--pid`または`--comm`を必須化し、広域取得には明示的な
  `--all-processes`とruntime警告を追加
- eBPF設定Mapを取得できない場合のfilterとTLS payload上限をfail-closed化

### Documentation

- 非公開の`PUBLISHING.md`への公開リンクを削除し、文書用IP addressとeBPF license宣言の
  説明を修正

## [0.0.2-beta] - 2026-07-20

### Fixed

- Debian 12 / Linux 6.1のeBPF verifierがTLS payload読み取り長を負数候補として拒否する問題を修正

### Security

- TLS payloadやprocess名に含まれる制御文字をtable出力でescapeし、terminal escape injectionを防止
- 機密性の高いobservability dataを安全に報告するためのsecurity policyを追加

## [0.0.1-beta.1] - 2026-07-09

初回public betaです。

### Added

- `sched_process_exec` によるprocess exec観測
- `tcp_v4_connect` によるIPv4 TCP connect観測
- BPF Ring Bufferによるユーザー空間へのイベント転送
- table / JSON Lines出力
- PID単位のEXEC / CONNECT / TLSイベント相関
- `--pid` / `--comm` filter
- experimental OpenSSL `SSL_write` / `SSL_read` plaintext観測
- payload上限とHTTP headerの簡易redact

[Unreleased]: https://github.com/soda-mikan/flowtap/compare/v0.0.3-beta...HEAD
[0.0.3-beta]: https://github.com/soda-mikan/flowtap/compare/v0.0.2-beta...v0.0.3-beta
[0.0.2-beta]: https://github.com/soda-mikan/flowtap/releases/tag/v0.0.2-beta
[0.0.1-beta.1]: https://github.com/soda-mikan/flowtap/releases/tag/v0.0.1-beta.1
