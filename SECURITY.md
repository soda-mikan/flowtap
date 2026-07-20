# Security Policy

## Supported versions

flowtap is prerelease software. Security fixes are provided only for the latest
published beta release.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/soda-mikan/flowtap/security/advisories/new>

Do not include credentials, captured TLS plaintext, cookies, private IP
addresses, process command lines, or other sensitive observability data in a
public issue. If private reporting is unavailable, open a public issue that
contains only a request for a private contact channel.

## Operational security

flowtap loads eBPF programs and can optionally observe plaintext handled by
OpenSSL. Run it only on systems and processes you are authorized to inspect.

- Treat all output as sensitive. EXEC records can contain command-line
  arguments, and TLS records can contain credentials or personal data.
- `--redact` is a best-effort HTTP/1 header filter, not a security boundary. It
  does not fully cover split records, HTTP/2 HPACK, message bodies, or arbitrary
  application protocols.
- `--tls-plaintext` requires `--pid` or `--comm`. System-wide capture requires
  the explicit `--all-processes` flag and emits a warning because it can expose
  plaintext from every process using the selected libssl.
- Keep `--max-payload-bytes` small and avoid enabling `--tls-plaintext` when it
  is not required.
- Do not attach real captures, logs, or screenshots to public bug reports.
