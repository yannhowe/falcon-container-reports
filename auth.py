#!/usr/bin/env python3
"""
Shared Falcon API authentication helpers.

Credentials are read from environment variables:
  FALCON_CLIENT_ID       - Falcon API client ID (required)
  FALCON_CLIENT_SECRET   - Falcon API client secret (required)
  FALCON_CLOUD_REGION    - Cloud region: us-1 (default), us-2, eu-1, us-gov-1

Create an API client in the Falcon console under Support > API Clients.
Required scope: Falcon Container Image — Read
"""

import os
import sys
import requests
from typing import Tuple


def resolve_credentials() -> Tuple[str, str, str]:
    """
    Read Falcon API credentials from environment variables.
    Returns (client_id, client_secret, region). Exits with an error if missing.
    """
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    region = os.getenv("FALCON_CLOUD_REGION", "us-1")

    if not client_id or not client_secret:
        print("ERROR: Falcon API credentials not set.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Export the following environment variables before running:", file=sys.stderr)
        print("  export FALCON_CLIENT_ID=your-client-id", file=sys.stderr)
        print("  export FALCON_CLIENT_SECRET=your-client-secret", file=sys.stderr)
        print("  export FALCON_CLOUD_REGION=us-1   # or us-2, eu-1, us-gov-1", file=sys.stderr)
        sys.exit(1)

    return client_id, client_secret, region


def get_base_url(region: str) -> str:
    """Return the CrowdStrike API base URL for the given region."""
    if region == "us-1":
        return "https://api.crowdstrike.com"
    return f"https://api.{region}.crowdstrike.com"


def get_oauth_token() -> Tuple[str, str]:
    """
    Obtain a Falcon OAuth2 bearer token.
    Returns (token, base_url).
    """
    client_id, client_secret, region = resolve_credentials()
    base_url = get_base_url(region)

    resp = requests.post(
        f"{base_url}/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"client_id": client_id, "client_secret": client_secret},
    )
    if resp.status_code != 201:
        print(f"Authentication failed: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)

    return resp.json()["access_token"], base_url
