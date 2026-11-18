# US Proxy Auditor

A Windows-friendly command-line tool that collects public **HTTP and SOCKS5** proxies and independently checks whether their **exit IP addresses are in the United States**. It tests HTTPS connectivity, verifies TLS certificates, compares external IP checks, checks geolocation with two providers, and exports reproducible results for proxy clients such as Fury.

> **Security:** public proxies are untrusted. Never submit passwords, authentication tokens, payment details, or other sensitive data through an unknown proxy. Verification does not guarantee anonymity or acceptance by anti-bot systems.

## Quick start (Windows 11)

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/).
2. Download the repository and extract it to a local folder.
3. Double-click **`start.bat`**. The first run may download Python and `httpx[socks]` automatically.
4. Open **`results/verified_us.txt`** or **`results/verified_us.csv`** after the scan.

Alternatively, open PowerShell in the project directory:

```powershell
uv run .\us_proxy_auditor.py --limit 1500 --concurrency 45 --timeout 5 --rounds 3 --check-google --check-headers
```

The default launcher runs up to 45 simultaneous proxy checks with a 5-second timeout. Increasing concurrency can improve throughput, but API rate limits, network conditions, and slow endpoints may become bottlenecks. Shorter timeouts may reject otherwise functional proxies.

## Commands

**Thorough scan** (slower, with more retries and a larger geolocation budget):

```powershell
uv run .\us_proxy_auditor.py --limit 5000 --concurrency 40 --timeout 8 --rounds 4 --geo-cap 500 --check-google --check-headers
```

**Exclude likely hosting/data-center networks** (heuristic classification):

```powershell
uv run .\us_proxy_auditor.py --exclude-hosting --check-google --check-headers
```

**Use your own proxy list** (`my_proxies.txt` contains one address per line; e.g. `socks5://1.2.3.4:1080`):

```powershell
uv run .\us_proxy_auditor.py --input .\my_proxies.txt --input-protocol socks5
```

Use `uv run .\us_proxy_auditor.py --help` for all options. Accepted proxy formats are `IP:PORT`, `http://IP:PORT`, and `socks5://IP:PORT`. Proxies requiring authentication are not supported.

## Verification process

1. Download public proxy feeds and deduplicate endpoints; country labels supplied by feeds are treated as untrusted hints.
2. Reject private, loopback, reserved, and non-global IPs. Attempt two HTTPS echo requests via each candidate with certificate validation enabled. Require both exit IP readings to match and differ from the direct IP when it is available.
3. Query **ipwho.is** and **ipapi.co** for each unique exit IP (subject to `--geo-cap` and API limits). Require **both** to report `US`.
4. Repeat HTTPS requests and require the exit IP to remain stable.
5. Optionally check **Google generate_204** (`--check-google`) and proxy forwarding headers via **httpbin** (`--check-headers`). Any failed optional strict check disqualifies the candidate.
6. Rank verified proxies by approximate network type, appearances in public lists, and latency. Organization-name keyword matching is only a hint; fewer list appearances do not imply lower real-world usage.

The tool deliberately fails closed when geolocation is unavailable, when providers disagree, or when configured checks cannot be completed. It does not check WebRTC, browser fingerprints, or whether an individual website will flag a connection as automated.

## Output files

| File | Contents |
| --- | --- |
| `results/verified_us.txt` | Verified URLs in `socks5://IP:PORT` or `http://IP:PORT` format |
| `results/verified_socks5.txt` | Verified SOCKS5 endpoints |
| `results/verified_http.txt` | Verified HTTP endpoints |
| `results/verified_us.csv` | Verified endpoints with latency, ISP/network hints, and sources |
| `results/all_results.csv` | Every tested candidate, including failures and uncertainty |
| `results/report.json` | Run metadata, result counts, errors, and input settings |

**Using Fury:** choose the protocol in the profile's Proxy settings, enter the IP in **Host** and the port in **Port**. Do not paste the entire URL into the Host field.

## Limitations and responsible use

- Free proxies may be unsafe, unreliable, overloaded, or blocked. Only test public endpoints you are authorized to use, and respect provider terms.
- `US` means two external geolocation providers agree; it does not prove physical location or residential status.
- A `possibly_isp` classification is a rough organization-name heuristic, not proof that a proxy is private or residential.
- IP geolocation services have usage quotas. The default `--geo-cap` is 300 unique exit IPs (maximum 500).
- Some source URLs may return `404`, `429`, or other errors; these are reported and do not automatically invalidate remaining sources.
- No proxy scan guarantees that Google or another anti-bot system will accept an IP.
- Avoid excessive request rates. Concurrency is deliberately capped at 60.

## Proxy list sources

- [ProxyScrape](https://github.com/ProxyScrape/free-proxy-list)
- [monosans](https://github.com/monosans/proxy-list)
- [TheSpeedX](https://github.com/TheSpeedX/PROXY-List)
- [FusionProxies](https://github.com/FusionProxies/free-proxy-list)
- [proxmint](https://github.com/proxmint/free-proxy-list)
- [proxio](https://github.com/proxio-io/proxy-list)
- Additional sources are enumerated directly in `SOURCES` inside the Python script.

## Tests

```powershell
uv run python -m unittest -v test_proxy_auditor.py
```

The included offline tests cover proxy parsing, duplicate handling, geolocation decisions, result ranking hints, and output generation. They do not verify live proxy availability. Network behavior depends on the user's environment and current third-party service availability.
