# Falcon Container Vulnerability Reports

Python scripts that pull container vulnerability data from the CrowdStrike Falcon API and export it to CSV. They work around two limitations in the Falcon console UI:

- The image assessment view only shows 10 vulnerability columns — the API exposes 25+
- The package vulnerabilities CSV combines all CVE IDs into a single field — these scripts give you one row per CVE so you can filter and pivot properly

| Script | What it produces |
|--------|-----------------|
| `falcon_image_assessment.py` | One row per container image, with all vulnerability counts and metadata. Use `--expand-vulns` to get one row per CVE instead. |
| `falcon_package_cve.py` | One row per (package, CVE) pair across your environment. Use this to answer "which packages are affected by CVE-XXXX-YYYY?" |

---

## Prerequisites

- Python 3.9 or later
- A CrowdStrike Falcon subscription that includes **Falcon Container Security**
- A Falcon API client with the **Falcon Container Image — Read** scope

Install the required library:

```bash
pip install -r requirements.txt
```

---

## Creating a Falcon API Client

1. Log in to the Falcon console and go to **Support > API Clients and Keys**
2. Click **Add new API client**
3. Give it a name (e.g. `vuln-export`)
4. Under **Falcon Container Image**, check **Read**
5. Click **Add**
6. Copy the **Client ID** and **Client Secret** — the secret is only shown once

---

## Authentication

Export your credentials as environment variables before running the scripts:

```bash
export FALCON_CLIENT_ID=your-client-id
export FALCON_CLIENT_SECRET=your-client-secret
export FALCON_CLOUD_REGION=us-1        # Change if your tenant is on us-2, eu-1, or us-gov-1
```

The region defaults to `us-1` if not set. You can check which region your tenant is on in the Falcon console URL:
- `falcon.crowdstrike.com` → `us-1`
- `falcon.us-2.crowdstrike.com` → `us-2`
- `falcon.eu-1.crowdstrike.com` → `eu-1`

---

## Image Assessment Report

Exports all images that Falcon has scanned, with full vulnerability and detection metadata.

### Common use cases

**Export everything:**
```bash
python3 falcon_image_assessment.py -o images.csv
```

**Show only images with Critical vulnerabilities:**
```bash
python3 falcon_image_assessment.py --severity critical -o critical-images.csv
```

**Show which images are affected by a specific CVE:**
```bash
python3 falcon_image_assessment.py --cve CVE-2024-1234 -o cve-images.csv
```

**Filter to a specific registry (e.g. Azure Container Registry):**
```bash
python3 falcon_image_assessment.py --registry myregistry.azurecr.io -o images.csv
```

**Only images that are currently running:**
```bash
python3 falcon_image_assessment.py --running-only -o running.csv
```

**Images scanned in a date range:**
```bash
python3 falcon_image_assessment.py \
  --last-scanned-after 2024-01-01 \
  --last-scanned-before 2024-03-31 \
  -o q1-images.csv
```

**One row per CVE instead of one row per image** (useful for vulnerability-level analysis):
```bash
python3 falcon_image_assessment.py --expand-vulns --severity critical -o expanded.csv
```

**Fetch more than the default 5,000 images:**
```bash
python3 falcon_image_assessment.py --limit 10000 -o all-images.csv
```

### All flags

| Flag | Description |
|------|-------------|
| `--registry` | Filter by registry hostname |
| `--repository` | Filter by repository name |
| `--tag` | Filter by image tag |
| `--severity` | `critical`, `high`, `medium`, or `low` — filters by highest severity present |
| `--cve` | Filter to images affected by a specific CVE ID |
| `--running-only` | Only images with a currently running container |
| `--last-scanned-after DATE` | Only images scanned after this date (YYYY-MM-DD) |
| `--last-scanned-before DATE` | Only images scanned before this date (YYYY-MM-DD) |
| `--expand-vulns` | One row per CVE instead of one row per image |
| `--limit N` | Maximum number of images to fetch (default: 5,000) |
| `-o FILE` | Output CSV path. Omit to print to stdout. |

### Output fields

| Field | Description |
|-------|-------------|
| `image_id` | Falcon's internal image identifier |
| `image_digest` | SHA256 content digest |
| `registry` | Registry hostname (e.g. `index.docker.io`) |
| `repository` | Repository name (e.g. `library/nginx`) |
| `tag` | Image tag (e.g. `latest`) |
| `source` | Where Falcon detected the image (registry, runtime, CI) |
| `arch` | CPU architecture |
| `base_os` | Base OS and version |
| `container_running_status` | `true` if a container using this image is currently running |
| `first_seen` | When Falcon first scanned this image (ISO 8601) |
| `last_seen` | When Falcon last scanned this image (ISO 8601) |
| `cps_rating` | CrowdStrike Prevention Score — overall risk rating |
| `vuln_critical` | Count of Critical severity vulnerabilities |
| `vuln_high` | Count of High severity vulnerabilities |
| `vuln_medium` | Count of Medium severity vulnerabilities |
| `vuln_low` | Count of Low severity vulnerabilities |
| `vuln_negligible` | Count of Negligible severity vulnerabilities |
| `vuln_total` | Total vulnerability count |
| `highest_vuln_severity` | Highest severity present (e.g. `critical`) |
| `detection_count` | Number of behavioral detections on running containers |
| `highest_detection_severity` | Highest detection severity |
| `package_count` | Number of packages detected in the image |
| `layers_with_vulns` | Number of image layers that contain vulnerable packages |
| `build_labels` | Docker build labels in `key=value; key=value` format |

**Additional fields with `--expand-vulns`:**

| Field | Description |
|-------|-------------|
| `cve_id` | CVE identifier (e.g. `CVE-2024-1234`) |
| `cve_severity` | Severity of this specific CVE |
| `cvss_score` | CVSS base score |
| `cve_description` | CVE description |
| `fix_status` | Whether a fix is available |
| `remediation` | Remediation guidance |
| `exploited_status` | Whether this CVE is known to be exploited in the wild |
| `package_name` | Name of the affected package |
| `package_version` | Version of the affected package |
| `package_path` | Path to the package inside the image |

---

## Package CVE Report

Exports one row per (package, CVE) combination across your environment. This answers questions like:

- "How many images have a vulnerable version of `libssl`?"
- "Which packages have a fix available for this CVE?"
- "What is our Critical + fixable exposure?"

### Common use cases

**Export all package vulnerabilities:**
```bash
python3 falcon_package_cve.py -o packages.csv
```

**Find every package affected by a specific CVE:**
```bash
python3 falcon_package_cve.py --cve CVE-2024-1234 -o cve-packages.csv
```

**All packages with at least one Critical CVE:**
```bash
python3 falcon_package_cve.py --severity Critical -o critical-packages.csv
```

> Note: `--severity` returns packages that have **any** CVE at that severity. The results may include rows for other severities. Use `--exact-severity` to restrict to only that severity level.

```bash
python3 falcon_package_cve.py --severity Critical --exact-severity -o critical-only.csv
```

**Only vulnerabilities where a fix exists:**
```bash
python3 falcon_package_cve.py --fix-available -o fixable.csv
```

**Filter by package name:**
```bash
python3 falcon_package_cve.py --package openssl -o openssl.csv
```

### All flags

| Flag | Description |
|------|-------------|
| `--cve` | Filter to a specific CVE ID |
| `--severity` | `Critical`, `High`, `Medium`, or `Low` |
| `--exact-severity` | Post-filter to only rows matching that exact severity |
| `--package` | Filter by package name substring |
| `--fix-available` | Only rows where a fix or remediation exists |
| `--limit N` | Maximum rows to fetch (default: 5,000) |
| `-o FILE` | Output CSV path. Omit to print to stdout. |

### Output fields

| Field | Description |
|-------|-------------|
| `cve_id` | CVE identifier |
| `severity` | CVE severity (Critical / High / Medium / Low) |
| `description` | CVE description |
| `fix_resolution` | Fix or upgrade guidance from Falcon |
| `package_name_version` | Full package identifier as reported by Falcon |
| `package_name` | Package name (split from `package_name_version`) |
| `package_version` | Package version (split from `package_name_version`) |
| `package_type` | Package format (`rpm`, `deb`, `apk`, `python`, etc.) |
| `license` | Package license |
| `running_images_count` | Number of currently running images containing this package+CVE |
| `all_images_count` | Total images (running and stopped) containing this package+CVE |
| `ai_related` | Whether Falcon has flagged this package as AI-related |

---

## Tips

**Combine the two scripts to build a full picture of a CVE's impact:**
```bash
# Step 1: Which packages are vulnerable?
python3 falcon_package_cve.py --cve CVE-2024-1234 -o packages.csv

# Step 2: Which images contain those packages?
python3 falcon_image_assessment.py --cve CVE-2024-1234 -o images.csv
```

**Pipe output directly to another tool:**
```bash
python3 falcon_package_cve.py --severity Critical | sort -t, -k1,1 | head -50
```

**The default limit is 5,000 rows.** If you have a large environment and see the warning `⚠ Fetched N of M total`, increase `--limit`:
```bash
python3 falcon_image_assessment.py --limit 50000 -o all.csv
```

---

## Troubleshooting

**`ERROR: Falcon API credentials not set`**
You haven't exported the environment variables. Check that `echo $FALCON_CLIENT_ID` returns a value.

**`Authentication failed: 400`**
The client ID or secret is wrong, or the API client has been deleted. Regenerate it in the Falcon console.

**`Authentication failed: 403`**
The API client is missing the **Falcon Container Image — Read** scope. Edit the client in the console and add it.

**`No images found matching filters`**
Either no images match your filter criteria, or Falcon hasn't scanned any images yet. Try running without filters first to confirm data is present.

**Results are fewer than expected**
The default fetch limit is 5,000. Use `--limit` to increase it.
