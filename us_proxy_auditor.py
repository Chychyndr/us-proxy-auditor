# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx[socks]>=0.27,<1"]
# ///
"""US Proxy Auditor: public HTTP/SOCKS5 proxy collector and conservative verifier.

Third-party public proxies are untrusted. Never transmit passwords or personal data.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

# Fixed, public text feeds. Every entry is independently checked; country hints are untrusted.
SOURCES: tuple[tuple[str, str, str, bool], ...] = (
    ("ProxyScrape US SOCKS5", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/us/socks5/data.txt", "socks5", True),
    ("ProxyScrape US HTTP", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/us/http/data.txt", "http", True),
    ("Litport US HTTP+SOCKS5", "https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/countries/us/all.txt", "http", True),
    ("monosans SOCKS5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5", False),
    ("monosans HTTP", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http", False),
    ("TheSpeedX SOCKS5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5", False),
    ("TheSpeedX HTTP", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http", False),
    ("FusionProxies SOCKS5", "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/socks5.txt", "socks5", False),
    ("FusionProxies HTTP", "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/http.txt", "http", False),
    ("proxmint SOCKS5", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt", "socks5", False),
    ("proxmint HTTP", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt", "http", False),
    ("proxio SOCKS5", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks5.txt", "socks5", False),
    ("proxio HTTP", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/http.txt", "http", False),
)

ECHO_A = "https://api.ipify.org?format=json"
ECHO_B = "https://checkip.amazonaws.com/"
HEADERS_URL = "https://httpbin.org/headers"
SITE_URL = "https://www.google.com/generate_204"
MAX_SOURCE_BYTES = 6_000_000
HOSTING_WORDS = (
    "hosting", "hostinger", "datacenter", "data center", "cloud", "vultr", "linode",
    "digitalocean", "ovh", "hetzner", "amazon", "aws", "azure", "microsoft",
    "google cloud", "leaseweb", "colocation", "colo ", "datawagon", "racknerd",
    "contabo", "server farm", "servers.com", "compute", "colo-crossing", "dedicated",
)
ISP_WORDS = (
    "comcast", "spectrum", "charter", "verizon", "at&t", "att ", "cox communications",
    "frontier", "centurylink", "lumen", "t-mobile", "tmobile", "optimum",
    "cablevision", "xfinity", "astound", "windstream", "mediacom", "fiber internet",
)


@dataclass
class Proxy:
    kind: str
    host: str
    port: int
    origins: set[str] = field(default_factory=set)
    us_hint: bool = False

    @property
    def key(self) -> str:
        return f"{self.kind}://{self.host}:{self.port}"

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Result:
    proxy: Proxy
    status: str = "not_checked"
    exit_ip: str = ""
    country_1: str = ""
    country_2: str = ""
    organization: str = ""
    network_type: str = "unknown"
    latency_ms: int = -1
    jitter_ms: int = -1
    successes: int = 0
    attempts: int = 0
    site_http_status: str = "not_checked"
    headers_leak: str = "not_checked"
    failure: str = ""
    geo_checked: bool = False


FIELDS = (
    "status", "protocol", "host", "port", "proxy_url", "exit_ip", "country_1", "country_2",
    "organization", "network_type_hint", "latency_ms", "jitter_ms", "successes", "attempts",
    "google_http_status", "headers_leak", "sources_count", "sources", "failure",
)


def parse_proxy(line: str, default_kind: str) -> tuple[str, str, int] | None:
    """Only publicly routable IPv4 literal endpoints, no embedded credentials."""
    raw = line.strip().strip("\ufeff")
    if not raw or raw.startswith(("#", "//")):
        return None
    raw = raw.split("#", 1)[0].strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"{default_kind}://{raw}"
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "socks5", "socks5h"}:
            return None
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return None
        host = parsed.hostname or ""
        ip = ipaddress.ip_address(host)
        if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
            return None
        port = parsed.port
        if port is None or not (1 <= port <= 65535):
            return None
        kind = "socks5" if parsed.scheme.lower().startswith("socks5") else "http"
        return kind, str(ip), port
    except (ValueError, TypeError):
        return None


def parse_source(content: str, kind: str, name: str, us_hint: bool, into: dict[str, Proxy]) -> int:
    added = 0
    for line in content.splitlines()[:60000]:
        value = parse_proxy(line, kind)
        if value is None:
            continue
        scheme, ip, port = value
        key = f"{scheme}://{ip}:{port}"
        if key not in into:
            into[key] = Proxy(scheme, ip, port)
            added += 1
        into[key].origins.add(name)
        into[key].us_hint |= us_hint
    return added


def positive_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.strip())
        if ip.is_global:
            return str(ip)
    except ValueError:
        pass
    return None


def org_type(organization: str) -> str:
    org = organization.casefold()
    if any(word in org for word in HOSTING_WORDS):
        return "possibly_hosting"
    if any(word in org for word in ISP_WORDS):
        return "possibly_isp"
    return "unknown"


def failure_reason(exc: Exception) -> str:
    reason = type(exc).__name__
    # Never output raw user-supplied proxy URLs containing credentials.
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP_{exc.response.status_code}"
    if isinstance(exc, httpx.ProxyError):
        return "ProxyError"
    if isinstance(exc, httpx.TimeoutException):
        return "Timeout"
    if isinstance(exc, httpx.ConnectError):
        message = str(exc).casefold()
        return "TLS_certificate_invalid" if any(part in message for part in ("certificate", "ssl", "tls")) else "ConnectFailure"
    return reason


def proxy_http_client(proxy: Proxy, timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        proxy=proxy.key, trust_env=False, verify=True,
        timeout=httpx.Timeout(timeout), follow_redirects=False,
        headers={"User-Agent": "US-Proxy-Auditor/1.0 (public-proxy-health-check)"},
    )


async def get_echo(client: httpx.AsyncClient, address: str) -> tuple[str, int]:
    start = time.perf_counter()
    r = await client.get(address)
    r.raise_for_status()
    if len(r.content) > 1024:
        raise ValueError("Echo response is oversized")
    if address == ECHO_A:
        value = r.json().get("ip", "")
    else:
        value = r.text.strip()
    ip = positive_ip(value)
    if not ip:
        raise ValueError("Echo endpoint returned no public IP")
    return ip, round((time.perf_counter() - start) * 1000)


async def initial_test(proxy: Proxy, timeout: float, direct_ip: str) -> Result:
    result = Result(proxy=proxy)
    try:
        async with proxy_http_client(proxy, timeout) as client:
            ip1, ms1 = await get_echo(client, ECHO_A)
            result.attempts += 1
            result.successes += 1
            ip2, ms2 = await get_echo(client, ECHO_B)
            result.attempts += 1
            result.successes += 1
        result.exit_ip = ip1
        result.latency_ms = round((ms1 + ms2) / 2)
        result.jitter_ms = abs(ms1 - ms2)
        if ip1 != ip2:
            result.status = "exit_ip_changed"
        elif direct_ip and ip1 == direct_ip:
            result.status = "same_as_direct_ip"
        else:
            result.status = "pending_geo"
    except Exception as exc:
        result.status = "connection_failed"
        result.failure = failure_reason(exc)
    return result


async def lookup_geo(client: httpx.AsyncClient, ip: str) -> tuple[str, str, str]:
    """Both providers queried directly, each with separate quota and rate limit."""
    a, b, org = "", "", ""
    try:
        r = await client.get(f"https://ipwho.is/{ip}")
        if r.status_code == 200:
            j = r.json()
            if j.get("success") is True:
                a = str(j.get("country_code", "")).upper()
                org = str((j.get("connection") or {}).get("org") or (j.get("connection") or {}).get("isp") or "")
    except (ValueError, httpx.HTTPError):
        pass
    try:
        r = await client.get(f"https://ipapi.co/{ip}/json/")
        if r.status_code == 200:
            j = r.json()
            if not j.get("error"):
                b = str(j.get("country_code", "")).upper()
                org = org or str(j.get("org") or "")
    except (ValueError, httpx.HTTPError):
        pass
    return a, b, org


async def verify_stability(result: Result, args: argparse.Namespace) -> Result:
    proxy = result.proxy
    measures: list[int] = [result.latency_ms]
    try:
        async with proxy_http_client(proxy, args.timeout) as client:
            # Repeat the independent HTTPS echo. A changed exit IP is a hard failure.
            for _ in range(max(0, args.rounds - 2)):
                result.attempts += 1
                ip, ms = await get_echo(client, ECHO_A)
                if ip != result.exit_ip:
                    result.status = "exit_ip_changed"
                    return result
                result.successes += 1
                measures.append(ms)
            result.latency_ms = round(statistics.median(measures))
            result.jitter_ms = round(max(measures) - min(measures))
            if args.check_headers:
                try:
                    r = await client.get(HEADERS_URL)
                    r.raise_for_status()
                    headers = r.json().get("headers", {})
                    forwarded = {str(k).lower(): str(v) for k, v in headers.items()
                                 if k.lower() in ("x-forwarded-for", "via", "forwarded", "x-real-ip")}
                    result.headers_leak = "present" if forwarded else "not_seen"
                except (ValueError, httpx.HTTPError):
                    result.headers_leak = "unknown"
            if args.check_google:
                try:
                    r = await client.get(SITE_URL)
                    result.site_http_status = str(r.status_code)
                except httpx.HTTPError:
                    result.site_http_status = "error"
    except Exception as exc:
        result.status = "unstable"
        result.failure = failure_reason(exc)
    return result


def final_status(result: Result, args: argparse.Namespace) -> str:
    if result.status not in {"pending_geo", "not_checked"}:
        return result.status
    if result.country_1 == "US" and result.country_2 == "US":
        geo = "confirmed_us"
    elif result.country_1 == "US" or result.country_2 == "US":
        geo = "unconfirmed_us"
    elif not result.country_1 and not result.country_2:
        geo = "geo_unavailable"
    elif result.country_1 != result.country_2 and result.country_1 and result.country_2:
        geo = "geo_disagreement"
    else:
        geo = "not_us"
    if geo != "confirmed_us":
        return geo
    if args.exclude_hosting and result.network_type == "possibly_hosting":
        return "excluded_hosting_hint"
    if args.check_google and result.site_http_status != "204":
        return "google_not_confirmed"
    if args.check_headers and result.headers_leak == "present":
        return "forwarding_headers"
    if args.check_headers and result.headers_leak != "not_seen":
        return "headers_unverified"
    return "verified_us"


def csv_row(r: Result) -> dict[str, str | int]:
    p = r.proxy
    return {
        "status": r.status, "protocol": p.kind, "host": p.host, "port": p.port,
        "proxy_url": p.key, "exit_ip": r.exit_ip, "country_1": r.country_1,
        "country_2": r.country_2, "organization": r.organization,
        "network_type_hint": r.network_type, "latency_ms": r.latency_ms,
        "jitter_ms": r.jitter_ms, "successes": r.successes, "attempts": r.attempts,
        "google_http_status": r.site_http_status, "headers_leak": r.headers_leak,
        "sources_count": len(p.origins), "sources": "; ".join(sorted(p.origins)),
        "failure": r.failure,
    }


def rank(r: Result) -> tuple[int, int, int, int]:
    category = {"possibly_isp": 0, "unknown": 1, "possibly_hosting": 2}.get(r.network_type, 3)
    return category, len(r.proxy.origins), max(0, r.latency_ms), max(0, r.jitter_ms)


def write_results(results: list[Result], out: Path, source_report: dict[str, object], args: argparse.Namespace) -> None:
    out.mkdir(parents=True, exist_ok=True)
    verified = sorted((r for r in results if r.status == "verified_us"), key=rank)
    all_ordered = sorted(results, key=lambda r: (0 if r.status == "verified_us" else 1, r.status, rank(r)))
    for filename, rows in (("all_results.csv", all_ordered), ("verified_us.csv", verified)):
        with (out / filename).open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(csv_row(r) for r in rows)
    for filename, proxies in (
        ("verified_us.txt", verified),
        ("verified_socks5.txt", [r for r in verified if r.proxy.kind == "socks5"]),
        ("verified_http.txt", [r for r in verified if r.proxy.kind == "http"]),
    ):
        (out / filename).write_text("\n".join(r.proxy.key for r in proxies) + ("\n" if proxies else ""), encoding="utf-8")
    counts = Counter(r.status for r in results)
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "checked_candidates": len(results),
        "verified_us": len(verified),
        "status_counts": dict(counts),
        "sources": source_report,
        "settings": {
            "rounds": args.rounds, "timeout_seconds": args.timeout,
            "concurrency": args.concurrency, "max_candidates": args.limit,
            "geo_cap": args.geo_cap, "check_google": args.check_google,
            "check_headers": args.check_headers, "exclude_hosting": args.exclude_hosting,
        },
        "caveats": [
            "The country is confirmed by two independent geolocation APIs, not a legal guarantee of location.",
            "Hosting vs ISP is keyword-based and can be wrong.",
            "No automated test guarantees acceptance by bot-detection systems.",
            "WebRTC leakage and browser fingerprint must be checked separately in the actual browser.",
            "Do not send credentials over unknown public proxies.",
        ],
    }
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


async def gather(args: argparse.Namespace) -> tuple[list[Proxy], dict[str, object]]:
    candidates: dict[str, Proxy] = {}
    source_report: dict[str, object] = {}
    # Download feeds directly; never use the proxies to fetch proxy lists.
    async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(20), follow_redirects=True) as client:
        sem = asyncio.Semaphore(5)

        async def one_source(spec: tuple[str, str, str, bool]) -> tuple[str, str, str, bool, str | None]:
            name, url, kind, us = spec
            async with sem:
                try:
                    r = await client.get(url)
                    r.raise_for_status()
                    if len(r.content) > MAX_SOURCE_BYTES:
                        raise ValueError("source too large")
                    return name, kind, r.text, us, None
                except Exception as exc:
                    return name, kind, "", us, failure_reason(exc)

        feeds = await asyncio.gather(*(one_source(s) for s in SOURCES))
    for name, kind, content, us_hint, error in feeds:
        if error:
            source_report[name] = {"error": error}
            print(f"  [source] {name}: error {error}")
            continue
        count = parse_source(content, kind, name, us_hint, candidates)
        source_report[name] = {"new_candidates": count, "downloaded_lines": len(content.splitlines())}
        print(f"  [source] {name}: +{count}")
    if args.input:
        local = Path(args.input)
        text = local.read_text(encoding="utf-8-sig")
        count = parse_source(text, args.input_protocol, f"local:{local.name}", False, candidates)
        source_report[f"local:{local.name}"] = {"new_candidates": count}
        print(f"  [file] {local.name}: +{count}")
    ordered = sorted(
        candidates.values(),
        key=lambda p: (not p.us_hint, -len(p.origins), p.kind != "socks5", p.host, p.port),
    )
    return ordered[:args.limit], source_report


async def get_direct_ip(timeout: float) -> str:
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(timeout), verify=True) as client:
            ip, _ = await get_echo(client, ECHO_A)
            return ip
    except (httpx.HTTPError, ValueError):
        return ""


async def main_async(args: argparse.Namespace) -> int:
    start = time.perf_counter()
    print("[1/4] Downloading public proxy lists...")
    proxies, source_report = await gather(args)
    print(f"Unique proxy candidates: {len(proxies)}")
    if not proxies:
        print("No candidates found. Check your connection or provide --input FILE.")
        return 2
    direct_ip = await get_direct_ip(args.timeout)
    print("Direct IP for leak detection:", direct_ip or "unavailable")
    print("[2/4] Checking HTTPS, TLS certificates, and two independent IP echoes...")
    worker_semaphore = asyncio.Semaphore(args.concurrency)
    completed = 0

    async def first(p: Proxy) -> Result:
        nonlocal completed
        async with worker_semaphore:
            r = await initial_test(p, args.timeout, direct_ip)
        completed += 1
        if completed % 50 == 0 or completed == len(proxies):
            print(f"  Checked: {completed}/{len(proxies)}", flush=True)
        return r

    results = await asyncio.gather(*(first(p) for p in proxies))
    candidates = [r for r in results if r.status == "pending_geo"]
    print(f"Passed initial checks: {len(candidates)}")
    print("[3/4] Verifying exit IP geolocation with two providers...")
    # Geolocation providers have finite free limits. We never silently assume US by source label.
    sorted_candidates = sorted(candidates, key=lambda r: (not r.proxy.us_hint, r.latency_ms))
    unique_ips = list(dict.fromkeys(r.exit_ip for r in sorted_candidates))
    allowed_ips = unique_ips[:args.geo_cap]
    geo_map: dict[str, tuple[str, str, str]] = {}
    async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(args.timeout)) as client:
        geo_sem = asyncio.Semaphore(2)

        async def one_geo(ip: str) -> None:
            async with geo_sem:
                geo_map[ip] = await lookup_geo(client, ip)
                # Conservative pacing for rate-limited free geo APIs.
                await asyncio.sleep(0.35)

        await asyncio.gather(*(one_geo(ip) for ip in allowed_ips))
    for r in candidates:
        if r.exit_ip in geo_map:
            r.country_1, r.country_2, r.organization = geo_map[r.exit_ip]
            r.network_type = org_type(r.organization)
            r.geo_checked = True
        r.status = final_status(r, args)
    us = [r for r in results if r.status == "verified_us"]
    print(f"Provisional verified US proxies: {len(us)}")
    print("[4/4] Repeating HTTPS checks and running additional tests...")
    completed = 0

    async def final_test(r: Result) -> None:
        nonlocal completed
        async with worker_semaphore:
            await verify_stability(r, args)
            if r.status == "verified_us":
                r.status = "pending_geo"
                r.status = final_status(r, args)
        completed += 1
        if completed % 20 == 0 or completed == len(us):
            print(f"  Rechecked: {completed}/{len(us)}", flush=True)

    await asyncio.gather(*(final_test(r) for r in us))
    write_results(results, Path(args.output), source_report, args)
    final = [r for r in results if r.status == "verified_us"]
    print("\nFinished in %.1f seconds. Checked %s, strictly verified US: %s" % (
        time.perf_counter() - start, len(results), len(final),
    ))
    for r in sorted(final, key=rank)[:10]:
        print(f"  {r.proxy.key:32s} {r.latency_ms:5d} ms | {r.network_type:17s} | {r.organization[:37]}")
    print("Output directory:", Path(args.output).resolve())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and conservatively verify public US HTTP/SOCKS5 proxies",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--limit", type=int, default=1500, help="maximum number of candidates to test")
    parser.add_argument("--concurrency", type=int, default=45, help="maximum concurrent proxy checks (up to 60)")
    parser.add_argument("--timeout", type=float, default=5.0, help="timeout per HTTPS request in seconds")
    parser.add_argument("--rounds", type=int, default=3, help="number of successful HTTPS requests including two initial IP echoes")
    parser.add_argument("--geo-cap", type=int, default=300, help="maximum unique IPs sent to geolocation APIs")
    parser.add_argument("--output", default="results", help="directory for generated reports")
    parser.add_argument("--input", help="optional local TXT proxy list")
    parser.add_argument("--input-protocol", default="socks5", choices=["socks5", "http"], help="default protocol for scheme-less addresses in --input")
    parser.add_argument("--check-google", action="store_true", help="add Google generate_204 connectivity test")
    parser.add_argument("--check-headers", action="store_true", help="check Forwarded/Via headers through httpbin")
    parser.add_argument("--exclude-hosting", action="store_true", help="exclude likely datacenter IPs using organization-name keywords")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not 1 <= args.limit <= 10000:
        parser.error("--limit must be between 1 and 10000")
    if not 1 <= args.concurrency <= 60:
        parser.error("--concurrency must be between 1 and 60")
    if not 2 <= args.timeout <= 30:
        parser.error("--timeout must be between 2 and 30")
    if not 3 <= args.rounds <= 8:
        parser.error("--rounds must be between 3 and 8")
    if not 1 <= args.geo_cap <= 500:
        parser.error("--geo-cap must be between 1 and 500 (free API limits)")
    try:
        raise SystemExit(asyncio.run(main_async(args)))
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        raise SystemExit(130)
    except (OSError, UnicodeError) as exc:
        print(f"Filesystem error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()