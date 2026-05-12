#!/usr/bin/env python3
"""
Falcon Container Image Assessment Report
Exports ALL image fields to CSV - bypasses the 10-column UI limit.

Authentication:
  export FALCON_CLIENT_ID=your-client-id
  export FALCON_CLIENT_SECRET=your-client-secret
  export FALCON_CLOUD_REGION=us-1   # optional, default: us-1

Usage:
  # All images, full CSV
  python3 falcon_image_assessment.py -o images.csv

  # Filter by registry
  python3 falcon_image_assessment.py --registry myregistry.azurecr.io -o images.csv

  # Images with critical vulnerabilities
  python3 falcon_image_assessment.py --severity critical -o critical.csv

  # Scanned after a date
  python3 falcon_image_assessment.py --last-scanned-after 2024-01-01 -o images.csv

  # Images affected by a specific CVE
  python3 falcon_image_assessment.py --cve CVE-2024-1234 -o cve-images.csv

  # Only running containers
  python3 falcon_image_assessment.py --running-only -o running.csv

  # One row per CVE (expanded view)
  python3 falcon_image_assessment.py --expand-vulns --severity critical -o expanded.csv
"""

import sys
import csv
import argparse

from auth import get_auth

try:
    from falconpy import ContainerImages
except ImportError:
    print("Install dependencies: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# ── API helpers ───────────────────────────────────────────────────────────────

def fetch_images_page(client, fql_filter, offset, limit, expand_vulns):
    params = {
        "limit": limit,
        "offset": offset,
        "expand_vulnerabilities": expand_vulns,
        "expand_detections": False,
        "sort": "last_seen.desc",
    }
    if fql_filter:
        params["filter"] = fql_filter

    resp = client.read_combined_export(**params)

    if resp["status_code"] != 200:
        errors = resp.get("body", {}).get("errors") or []
        msg = "; ".join(e.get("message", str(e)) for e in errors) or str(resp["status_code"])
        print(f"  API error: {msg}", file=sys.stderr)
        return [], 0

    body = resp["body"]
    resources = body.get("resources") or []
    total = body.get("meta", {}).get("pagination", {}).get("total", len(resources))
    return resources, total


def fetch_all_images(client, fql_filter, expand_vulns, max_records=5000):
    page_size = min(500, max_records)
    all_images, offset = [], 0
    total = None
    while True:
        this_limit = min(page_size, max_records - len(all_images))
        batch, total = fetch_images_page(client, fql_filter, offset, this_limit, expand_vulns)
        if not batch:
            break
        all_images.extend(batch)
        print(f"  Fetched {len(all_images)} / {total}", end="\r", file=sys.stderr)
        if len(all_images) >= max_records or len(all_images) >= total or len(batch) < this_limit:
            break
        offset += len(batch)
    print(file=sys.stderr)
    return all_images, total


# ── Flattening ────────────────────────────────────────────────────────────────

def flatten_image_base(img):
    vuln = img.get("vulnerabilities") or {}
    if isinstance(vuln, list):
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
        for v in vuln:
            s = (v.get("severity") or "").lower()
            if s in sev_counts:
                sev_counts[s] += 1
        vuln_summary = sev_counts
        vuln_list = vuln
    else:
        vuln_summary = vuln
        vuln_list = []

    detection = img.get("detections") or {}
    labels = img.get("labels") or img.get("build_labels") or {}
    labels_str = "; ".join(f"{k}={v}" for k, v in labels.items()) if isinstance(labels, dict) else str(labels)

    row = {
        "image_id":                   img.get("id") or img.get("image_id", ""),
        "image_digest":               img.get("image_digest", ""),
        "registry":                   img.get("registry", ""),
        "repository":                 img.get("repository", ""),
        "tag":                        img.get("tag", ""),
        "source":                     img.get("source", ""),
        "arch":                       img.get("arch", ""),
        "base_os":                    img.get("base_os", ""),
        "multi_arch":                 img.get("multi_arch", ""),
        "container_id":               img.get("container_id", ""),
        "container_running_status":   img.get("container_running_status", ""),
        "first_seen":                 img.get("first_seen", ""),
        "last_seen":                  img.get("last_seen", ""),
        "cps_rating":                 img.get("highest_cps_current_rating", ""),
        "vuln_critical":              vuln_summary.get("critical", 0),
        "vuln_high":                  vuln_summary.get("high", 0),
        "vuln_medium":                vuln_summary.get("medium", 0),
        "vuln_low":                   vuln_summary.get("low", 0),
        "vuln_negligible":            vuln_summary.get("negligible", 0),
        "vuln_total":                 img.get("vulnerability_count",
                                          sum(vuln_summary.get(s, 0) for s in ["critical", "high", "medium", "low", "negligible"])),
        "highest_vuln_severity":      img.get("highest_vulnerability_severity", ""),
        "detection_count":            img.get("detection_count", detection.get("total", "")),
        "highest_detection_severity": img.get("highest_detection_severity", ""),
        "package_count":              img.get("packages", ""),
        "layers_with_vulns":          img.get("layers_with_vulnerabilities", ""),
        "build_labels":               labels_str,
    }
    return row, vuln_list


def expand_vuln_rows(base_row, vuln_list):
    if not vuln_list:
        return [base_row]
    rows = []
    for v in vuln_list:
        row = dict(base_row)
        row.update({
            "cve_id":           v.get("cve_id", ""),
            "cve_severity":     v.get("severity", ""),
            "cvss_score":       v.get("cvss_score", ""),
            "cve_description":  v.get("description", ""),
            "fix_status":       v.get("fix_status", ""),
            "remediation":      v.get("remediation", ""),
            "exploited_status": v.get("exploited_status", ""),
            "package_name":     v.get("package_name", ""),
            "package_version":  v.get("package_version", ""),
            "package_path":     v.get("package_path", ""),
        })
        rows.append(row)
    return rows


# ── FQL filter builder ────────────────────────────────────────────────────────

def build_fql(args):
    parts = []
    if args.registry:
        parts.append(f"registry:'{args.registry}'")
    if args.repository:
        parts.append(f"repository:'{args.repository}'")
    if args.tag:
        parts.append(f"tag:'{args.tag}'")
    if args.severity:
        parts.append(f"vulnerability_severity:'{args.severity}'")
    if args.cve:
        parts.append(f"cve_id:'{args.cve}'")
    if args.running_only:
        parts.append("container_running_status:true")
    if args.last_scanned_after:
        ts = args.last_scanned_after
        if len(ts) == 10:
            ts += "T00:00:00Z"
        parts.append(f"last_seen:>='{ts}'")
    if args.last_scanned_before:
        ts = args.last_scanned_before
        if len(ts) == 10:
            ts += "T23:59:59Z"
        parts.append(f"last_seen:<='{ts}'")
    return "+".join(parts) if parts else None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Export Falcon Container Image Assessment data to CSV with ALL fields.")
    parser.add_argument("--registry", help="Filter by registry (e.g. myregistry.azurecr.io)")
    parser.add_argument("--repository", help="Filter by repository name")
    parser.add_argument("--tag", help="Filter by image tag")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                        help="Filter by highest vulnerability severity")
    parser.add_argument("--cve", help="Filter images affected by a specific CVE")
    parser.add_argument("--running-only", action="store_true",
                        help="Only include currently running containers")
    parser.add_argument("--last-scanned-after", metavar="DATE",
                        help="Only images scanned after this date (YYYY-MM-DD or ISO8601)")
    parser.add_argument("--last-scanned-before", metavar="DATE",
                        help="Only images scanned before this date (YYYY-MM-DD or ISO8601)")
    parser.add_argument("--expand-vulns", action="store_true",
                        help="One row per CVE (instead of one row per image)")
    parser.add_argument("--output", "-o", default="-",
                        help="Output CSV file path (default: stdout)")
    parser.add_argument("--limit", type=int, default=5000,
                        help="Max images to fetch (default: 5000)")
    args = parser.parse_args()

    print("=== Falcon Image Assessment Report ===", file=sys.stderr)
    auth = get_auth()
    client = ContainerImages(auth_object=auth)
    print("✓ Authenticated", file=sys.stderr)

    fql = build_fql(args)
    if fql:
        print(f"Filter: {fql}", file=sys.stderr)

    print("Fetching images...", file=sys.stderr)
    images, total = fetch_all_images(client, fql, args.expand_vulns, max_records=args.limit)
    if total and len(images) < total:
        print(f"⚠  Fetched {len(images)} of {total} total (increase --limit to get all)", file=sys.stderr)
    print(f"✓ {len(images)} images retrieved", file=sys.stderr)

    if not images:
        print("No images found matching filters.", file=sys.stderr)
        sys.exit(0)

    all_rows = []
    for img in images:
        base_row, vuln_list = flatten_image_base(img)
        if args.expand_vulns:
            all_rows.extend(expand_vuln_rows(base_row, vuln_list))
        else:
            all_rows.append(base_row)

    fieldnames = list(all_rows[0].keys())
    out = open(args.output, "w", newline="") if args.output != "-" else sys.stdout
    writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(all_rows)
    if args.output != "-":
        out.close()
        print(f"✓ Written to {args.output}  ({len(all_rows)} rows)", file=sys.stderr)
    else:
        print(f"\n✓ {len(all_rows)} rows written", file=sys.stderr)


if __name__ == "__main__":
    main()
