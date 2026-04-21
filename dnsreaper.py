#!/usr/bin/env python3
"""DNSReaper - public DNS CNAME drift / takeover candidate detector.

This public version is intentionally sanitized for open-source release:
- no company domains
- no internal endpoints
- no CI secrets wiring
- no email delivery integration
- no ticketing integration

It can:
1. Load candidate hostnames from a text file, or
2. Pull CNAME records from Cloudflare using an API token.

For each hostname, it follows the CNAME chain and checks whether the final
endpoint resolves to at least one public A/AAAA record. Hostnames whose final
endpoint has no public IP are reported as candidates for review.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import dns.resolver
import requests

LOGGING_FORMAT = "%(levelname)s - %(asctime)s.%(msecs)03d: %(message)s"
DEFAULT_CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
DEFAULT_PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
MAX_CNAME_DEPTH = 20


@dataclass
class Finding:
    hostname: str
    status: str
    reason: str
    chain: str


class BlacklistedDomainException(Exception):
    """Raised when a hostname matches an ignored suffix."""


def normalize_fqdn(name: str) -> str:
    return str(name).strip().rstrip(".").lower()


def is_public_ip(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text).is_global
    except ValueError:
        return False


def load_config(path: Path | None) -> dict:
    if path is None:
        return {}
    with path.open("rt", encoding="utf-8") as fp:
        return json.load(fp)


def build_resolver(nameservers: Sequence[str], lifetime: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.NXDOMAIN = dns.resolver.NXDOMAIN
    resolver.NoAnswer = dns.resolver.NoAnswer
    resolver.nameservers = list(nameservers)
    resolver.lifetime = lifetime
    return resolver


def load_domains_from_file(path: Path) -> list[str]:
    domains: list[str] = []
    with path.open("rt", encoding="utf-8") as fp:
        for line in fp:
            item = normalize_fqdn(line)
            if item and not item.startswith("#"):
                domains.append(item)
    return sorted(set(domains))


def cloudflare_headers(api_token: str) -> dict[str, str]:
    token = api_token.strip()
    if not token:
        raise ValueError("Cloudflare API token is empty")
    if not token.lower().startswith("bearer "):
        token = f"Bearer {token}"
    return {"Content-Type": "application/json", "Authorization": token}


def load_domains_from_cloudflare(api_base: str, api_token: str, verify_tls: bool) -> list[str]:
    session = requests.Session()
    headers = cloudflare_headers(api_token)

    zones_url = f"{api_base.rstrip('/')}/zones?per_page=1000"
    response = session.get(zones_url, headers=headers, verify=verify_tls, timeout=30)
    response.raise_for_status()
    payload = response.json()
    zones = payload.get("result", [])

    domains: set[str] = set()
    for zone in zones:
        zone_id = zone["id"]
        records_url = f"{api_base.rstrip('/')}/zones/{zone_id}/dns_records?type=CNAME&per_page=5000"
        record_response = session.get(records_url, headers=headers, verify=verify_tls, timeout=30)
        record_response.raise_for_status()
        record_payload = record_response.json()
        for record in record_payload.get("result", []):
            hostname = normalize_fqdn(record.get("name", ""))
            if hostname and "_" not in hostname:
                domains.add(hostname)

    return sorted(domains)


def should_be_skipped(domain_name: str, ignored_suffixes: Sequence[str]) -> bool:
    normalized = normalize_fqdn(domain_name)
    suffixes = [normalize_fqdn(item) for item in ignored_suffixes if str(item).strip()]
    return any(normalized.endswith(suffix) for suffix in suffixes)


def inspect_hostname(hostname: str, resolver: dns.resolver.Resolver, ignored_suffixes: Sequence[str]) -> Finding:
    hostname = normalize_fqdn(hostname)
    current = hostname
    chain = [current]
    visited = set()
    saw_cname = False
    public_ips: list[str] = []
    private_or_non_global_ips: list[str] = []

    try:
        for _ in range(MAX_CNAME_DEPTH):
            logging.info("Checking CNAME for %s", current)
            if should_be_skipped(current, ignored_suffixes):
                raise BlacklistedDomainException(current)

            if current in visited:
                return Finding(
                    hostname=hostname,
                    status="loop",
                    reason="CNAME loop detected",
                    chain=" -> ".join(chain),
                )
            visited.add(current)

            try:
                cname_answer = resolver.resolve(current, "CNAME")
            except (resolver.NXDOMAIN, resolver.NoAnswer):
                break

            target = normalize_fqdn(cname_answer[0].target.to_text())
            chain.append(target)
            current = target
            saw_cname = True

        if not saw_cname:
            return Finding(
                hostname=hostname,
                status="ignored-no-cname",
                reason="Hostname does not have a CNAME chain",
                chain=" -> ".join(chain),
            )

        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(current, record_type)
            except (resolver.NXDOMAIN, resolver.NoAnswer):
                continue

            for item in answer:
                ip_text = item.to_text()
                if is_public_ip(ip_text):
                    public_ips.append(ip_text)
                else:
                    private_or_non_global_ips.append(ip_text)

    except BlacklistedDomainException:
        return Finding(
            hostname=hostname,
            status="ignored-rule",
            reason="Matched ignored suffix rule",
            chain=" -> ".join(chain),
        )
    except Exception as exc:  # broad by design for batch scanning
        return Finding(
            hostname=hostname,
            status="error",
            reason=f"Lookup failed: {type(exc).__name__}: {exc}",
            chain=" -> ".join(chain),
        )

    if public_ips:
        return Finding(
            hostname=hostname,
            status="ok",
            reason="Public A/AAAA record found: " + ", ".join(sorted(set(public_ips))),
            chain=" -> ".join(chain),
        )

    if private_or_non_global_ips:
        return Finding(
            hostname=hostname,
            status="candidate",
            reason="Only non-public A/AAAA records found: " + ", ".join(sorted(set(private_or_non_global_ips))),
            chain=" -> ".join(chain),
        )

    return Finding(
        hostname=hostname,
        status="candidate",
        reason="No public A/AAAA record found at the end of the CNAME chain",
        chain=" -> ".join(chain),
    )


def run_scan(domains: Sequence[str], resolver: dns.resolver.Resolver, ignored_suffixes: Sequence[str], threads: int) -> list[Finding]:
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(inspect_hostname, hostname, resolver, ignored_suffixes): hostname
            for hostname in domains
        }
        for future in as_completed(futures):
            findings.append(future.result())
    findings.sort(key=lambda item: (item.status, item.hostname))
    return findings


def write_csv(findings: Iterable[Finding], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["hostname", "status", "reason", "chain"])
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "hostname": item.hostname,
                    "status": item.status,
                    "reason": item.reason,
                    "chain": item.chain,
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect CNAME takeover candidates")
    parser.add_argument("--input-file", type=Path, help="Text file with one hostname per line")
    parser.add_argument("--config", type=Path, default=Path("config.example.json"), help="JSON config file")
    parser.add_argument("--source", choices=["file", "cloudflare"], default="file", help="Source of hostnames")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads")
    parser.add_argument("--output", type=Path, default=Path("result.csv"), help="CSV output file")
    parser.add_argument("--logfile", type=Path, default=Path("dnsreaper.log"), help="Log file path")
    parser.add_argument("--resolver-timeout", type=int, default=5, help="DNS resolver lifetime in seconds")
    parser.add_argument(
        "--public-resolvers",
        type=str,
        default=",".join(DEFAULT_PUBLIC_RESOLVERS),
        help="Comma separated DNS resolvers used for validation",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification for provider API requests (not recommended)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        format=LOGGING_FORMAT,
        datefmt="%H:%M:%S",
        level=logging.INFO,
        filename=args.logfile,
        filemode="w",
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logging.getLogger().addHandler(console)

    config = load_config(args.config if args.config and args.config.exists() else None)
    ignored_suffixes = config.get("ignored_suffixes", [])
    nameservers = [item.strip() for item in args.public_resolvers.split(",") if item.strip()]
    resolver = build_resolver(nameservers, args.resolver_timeout)

    if args.source == "file":
        if not args.input_file:
            raise SystemExit("--input-file is required when --source=file")
        domains = load_domains_from_file(args.input_file)
    else:
        cloudflare = config.get("cloudflare", {})
        api_base = cloudflare.get("api_base", DEFAULT_CLOUDFLARE_API)
        api_token = cloudflare.get("api_token", "")
        domains = load_domains_from_cloudflare(api_base, api_token, verify_tls=not args.insecure)

    if not domains:
        logging.warning("No domains to process")
        return 0

    findings = run_scan(domains, resolver, ignored_suffixes, args.threads)
    write_csv(findings, args.output)

    counts: dict[str, int] = {}
    for item in findings:
        counts[item.status] = counts.get(item.status, 0) + 1

    logging.info("Scan completed for %d hostnames", len(findings))
    for status, count in sorted(counts.items()):
        logging.info("%s: %d", status, count)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
