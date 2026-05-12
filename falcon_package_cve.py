#!/usr/bin/env python3
"""
Falcon Package Vulnerability Report - Exploded CVE Format
One row per (package × CVE) combination. Fixes the "combined fields" CSV problem.

Authentication:
  export FALCON_CLIENT_ID=your-client-id
  export FALCON_CLIENT_SECRET=your-client-secret
  export FALCON_CLOUD_REGION=us-1   # optional, default: us-1

Note on image context:
  The packages API returns total image counts (running_images, all_images) but not
  per-image details. To see WHICH images have a specific CVE, use:
    python3 falcon_image_assessment.py --cve <CVE-ID> -o images.csv

Usage:
  # All packages with vulnerabilities
  python3 falcon_package_cve.py -o packages.csv

  # Every package affected by a specific CVE
  python3 falcon_package_cve.py --cve CVE-2024-1234 -o cve-impact.csv

  # Packages with any Critical severity CVE
  python3 falcon_package_cve.py --severity Critical -o critical.csv

  # Only rows for Critical CVEs (stricter post-filter)
  python3 falcon_package_cve.py --severity Critical --exact-severity -o critical.csv

  # Fixable vulnerabilities only
  python3 falcon_package_cve.py --fix-available -o fixable.csv

  # Filter by package name substring
  python3 falcon_package_cve.py --package openssl -o openssl.csv
"""

import sys
import csv
import argparse

from auth import get_oauth_token

try:
    import requests
except ImportError:
    print("Install dependencies: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# ── API: Packages v2 ──────────────────────────────────────────────────────────

def fetch_packages_page(token, base_url, fql_filter, offset, limit):
    url = f"{base_url}/container-security/combined/packages/v2"
    params = {"limit": limit, "offset": offset}
    if fql_filter:
        params["filter"] = fql_filter
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=30)
    if resp.status_code != 200:
        print(f"  API error {resp.status_code}: {resp.text[:400]}", file=sys.stderr)
        return [], 0
    body = resp.json()
    resources = body.get("resources") or []
    total = body.get("meta", {}).get("pagination", {}).get("total", len(resources))
    return resources, total


def fetch_all_packages(token, base_url, fql_filter, max_records=5000):
    page_size = min(500, max_records)
    all_pkgs, offset = [], 0
    total = None
    while True:
        this_limit = min(page_size, max_records - len(all_pkgs))
        batch, total = fetch_packages_page(token, base_url, fql_filter, offset, this_limit)
        if not batch:
            break
        all_pkgs.extend(batch)
        print(f"  Fetched {len(all_pkgs)} / {total}", end="\r", file=sys.stderr)
        if len(all_pkgs) >= max_records or len(all_pkgs) >= total or len(batch) < this_limit:
            break
        offset += len(batch)
    print(file=sys.stderr)
    return all_pkgs, total


def flatten_package_record(rec):
    pkg_nv = rec.get("package_name_version", "")
    if " " in pkg_nv:
        pkg_name, pkg_version = pkg_nv.rsplit(" ", 1)
    else:
        pkg_name, pkg_version = pkg_nv, ""

    fix_res = rec.get("fix_resolution") or ""
    if isinstance(fix_res, list):
        fix_res = "; ".join(str(f) for f in fix_res if f)

    return {
        "cve_id":               rec.get("cveid", ""),
        "severity":             rec.get("severity", ""),
        "description":          rec.get("vulnerability_description", ""),
        "fix_resolution":       fix_res,
        "package_name_version": pkg_nv,
        "package_name":         pkg_name,
        "package_version":      pkg_version,
        "package_type":         rec.get("type", ""),
        "license":              rec.get("license", ""),
        "running_images_count": rec.get("running_images", 0),
        "all_images_count":     rec.get("all_images", 0),
        "ai_related":           rec.get("ai_related", False),
    }


# ── FQL builder ───────────────────────────────────────────────────────────────

def build_fql(args):
    parts = []
    if args.severity:
        parts.append(f"severity:'{args.severity}'")
    if args.cve:
        parts.append(f"cveid:'{args.cve}'")
    if args.package:
        parts.append(f"package_name_version:~'{args.package}'")
    return "+".join(parts) if parts else None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Export package vulnerabilities as one row per CVE.")
    parser.add_argument("--cve", help="Show all packages affected by this CVE (e.g. CVE-2024-1234)")
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low"],
                        help="Filter: packages with any CVE at this severity")
    parser.add_argument("--exact-severity", action="store_true",
                        help="Post-filter: only rows where severity exactly matches")
    parser.add_argument("--package", help="Filter by package name substring")
    parser.add_argument("--fix-available", action="store_true",
                        help="Only include rows where fix_resolution is non-empty")
    parser.add_argument("--output", "-o", default="-",
                        help="Output CSV path (default: stdout)")
    parser.add_argument("--limit", type=int, default=5000,
                        help="Max rows to fetch (default: 5000)")
    args = parser.parse_args()

    print("=== Falcon Package CVE Report ===", file=sys.stderr)
    token, base_url = get_oauth_token()
    print("✓ Authenticated", file=sys.stderr)

    fql = build_fql(args)
    if fql:
        print(f"Filter: {fql}", file=sys.stderr)
        if args.severity and not args.exact_severity:
            print(f"  Note: returns all CVEs for packages that have any {args.severity} CVE", file=sys.stderr)
            print(f"  Use --exact-severity to restrict rows to {args.severity} only", file=sys.stderr)

    print("Fetching package CVE records...", file=sys.stderr)
    records, total = fetch_all_packages(token, base_url, fql, max_records=args.limit)
    if total and len(records) < total:
        print(f"⚠  Fetched {len(records)} of {total} total (increase --limit to get all)", file=sys.stderr)
    print(f"✓ {len(records)} records retrieved", file=sys.stderr)

    if not records:
        print("No results found.", file=sys.stderr)
        sys.exit(0)

    rows = [flatten_package_record(r) for r in records]

    if args.exact_severity and args.severity:
        before = len(rows)
        rows = [r for r in rows if r["severity"].lower() == args.severity.lower()]
        print(f"  Exact severity filter: {before} → {len(rows)} rows", file=sys.stderr)

    if args.fix_available:
        before = len(rows)
        rows = [r for r in rows if r.get("fix_resolution")]
        print(f"  Fix-available filter: {before} → {len(rows)} rows", file=sys.stderr)

    if not rows:
        print("No results after filtering.", file=sys.stderr)
        sys.exit(0)

    fieldnames = list(rows[0].keys())
    out = open(args.output, "w", newline="") if args.output != "-" else sys.stdout
    writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    if args.output != "-":
        out.close()
        print(f"✓ Written to {args.output}  ({len(rows)} rows)", file=sys.stderr)
    else:
        print(f"\n✓ {len(rows)} rows written", file=sys.stderr)


if __name__ == "__main__":
    main()
