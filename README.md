# US Proxy Auditor

A fast, terminal-only **Go** utility that collects public HTTP and SOCKS5 proxies, verifies their **US exit IPs**, and exports tested endpoints for clients such as Fury Browser. It requires **no Python, uv, third-party Go modules, graphical application, or account**.

> **Security:** Public proxies are untrusted. Never send passwords, tokens, or sensitive personal information through unknown proxies. Passing these checks does not mean an IP is private or trusted by anti-bot systems.

## Requirements

- [Go 1.23 or later](https://go.dev/dl/) for running from source.
- Windows 11, macOS, or Linux.
- Network access to public source lists and the testing APIs.

## Quick start (Windows / PowerShell)

Download or clone this repository, open PowerShell inside it, and run:

```powershell
go run . --limit 1500 --concurrency 128 --timeout 5 --rounds 3 --check-google --check-headers
```

Or double-click **`start.bat`**, which runs the same console command. The `.bat` launcher is optional; there is no desktop interface. Go compiles the application automatically as part of `go run`.

To build a portable executable once (optional):

```powershell
go build -o us-proxy-auditor.exe .
.\us-proxy-auditor.exe --help
```

## Presets

**Fast:**

```powershell
go run . --limit 2000 --concurrency 160 --timeout 4 --rounds 3 --geo-cap 200
```

**Thorough:**

```powershell
go run . --limit 5000 --concurrency 96 --timeout 8 --rounds 4 --geo-cap 500 --check-google --check-headers --exclude-hosting
```

**Custom list only:**

```powershell
go run . --no-feeds --input .\my_proxies.txt --input-protocol socks5
```

Each local list entry may be `IP:PORT`, `http://IP:PORT`, or `socks5://IP:PORT`. Authenticated proxies and IPv6 endpoint literals are not supported.

## Key options

| Flag | Default | Purpose |
| --- | --- | --- |
| `--limit` | `1500` | Maximum candidate endpoints (up to 10,000) |
| `--concurrency` | `128` | Concurrent proxy workers (up to 256) |
| `--timeout` | `5` | Timeout in seconds for each network request |
| `--rounds` | `3` | Minimum repeated HTTPS exit-IP checks (3–8) |
| `--geo-cap` | `300` | Limit of distinct exit IPs queried against geolocation services |
| `--geo-rate` | `2` | Maximum total geolocation requests per second (1–5) |
| `--check-google` | Off | Require a `204` response from Google generate_204 |
| `--check-headers` | Off | Reject exposed `Forwarded`, `Via`, and related headers |
| `--exclude-hosting` | Off | Reject likely hosting networks using name-based hints |
| `--input` | None | Read additional local proxy candidates |
| `--no-feeds` | Off | Skip online lists and check only local input |
| `--output` | `results` | Output directory |

The **Windows launcher enables strict checks** by default. The raw command without additional flags skips the optional Google and forwarding-header tests.

## Verification pipeline

1. Download 13 public proxy feeds concurrently and remove duplicates.
2. Reject malformed, local, private, and special-use IPv4 endpoints; attempt TCP connectivity.
3. Require two distinct HTTPS IP-check services to return the same public exit IP, using normal TLS certificate validation.
4. Query two independent geolocation services, **ipwho.is** and **ipapi.co**, over HTTPS and require both to confirm `US`. Requests are rate-limited and unique exit IPs are cached within the scan.
5. Repeat HTTPS checks and require a stable exit IP.
6. Optionally verify Google connectivity and forwarding headers; uncertain results fail closed when optional checks are enabled.
7. Rank the verified results using approximate ISP/hosting classification, number of source-list appearances, and latency.

Scanning is **network-bound**. A faster CPU or more concurrent workers cannot remove the latency of unresponsive proxies, bandwidth limitations, DNS delays, geolocation quotas, or remote rate limits. High worker counts can cause local resource exhaustion and trigger remote rate limiting. Prefer an incremental increase from 128 to 160 or 192, while checking actual results.

The US geographic tag describes two providers' IP location reports. The provider's organization string is only a rough heuristic; fewer appearances in publicly indexed feeds do **not** prove low usage or better reputation.

## Output

| File | Description |
| --- | --- |
| `results/verified_us.txt` | Confirmed proxy URLs (`socks5://IP:PORT` or `http://IP:PORT`) |
| `results/verified_socks5.txt` | Confirmed SOCKS5 proxy URLs |
| `results/verified_http.txt` | Confirmed HTTP proxy URLs |
| `results/verified_us.csv` | Detailed metrics for passing proxies |
| `results/all_results.csv` | Every candidate, including rejection reasons |
| `results/report.json` | Metadata, durations, status counts, and source failures |

**Fury:** Enter the endpoint protocol, host, and port in the profile's Proxy settings. Avoid pasting the full proxy URL into the Host field.

## Sources

The built-in feeds are maintained independently by ProxyScrape, Litport, monosans, TheSpeedX, FusionProxies, proxmint, and proxio. Some lists may be removed, rate-limited, or unavailable; the scanner records these failures and continues. Source URLs and protocol hints are defined in [`main.go`](main.go).

## Test and build

```powershell
go test ./...
go vet ./...
go test -race ./...  # if the Go race detector is supported on your system
go build .
```

The tests are offline and validate parsing, safe input filtering, deduplication, multi-stage decisions, classification, concurrency bounds, and report generation. Live proxy availability, ISP classification, anti-bot acceptance, and physical location cannot be guaranteed by unit tests. Only test public endpoints you are authorized to use; obey source-provider terms and API rate limits.
