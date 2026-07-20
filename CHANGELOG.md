# Changelog

このプロジェクトの主な変更を記録します。バージョン番号は
[Semantic Versioning](https://semver.org/) に従います。

## [Unreleased]

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

[Unreleased]: https://github.com/YOUR_GITHUB_USER/flowtap/compare/v0.0.1-beta.1...HEAD
[0.0.1-beta.1]: https://github.com/YOUR_GITHUB_USER/flowtap/releases/tag/v0.0.1-beta.1

