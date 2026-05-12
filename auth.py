#!/usr/bin/env python3
"""
Shared Falcon API authentication helpers using FalconPy.

Credentials are read from environment variables:
  FALCON_CLIENT_ID       - Falcon API client ID (required)
  FALCON_CLIENT_SECRET   - Falcon API client secret (required)
  FALCON_CLOUD_REGION    - Cloud region: us-1 (default), us-2, eu-1, us-gov-1

Create an API client in the Falcon console under Support > API Clients and Keys.
Required scope: Falcon Container Image — Read
"""

import os
import sys

try:
    from falconpy import OAuth2
except ImportError:
    print("Install dependencies: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


def get_auth() -> OAuth2:
    """
    Build a FalconPy OAuth2 authenticator from environment variables.
    Returns an OAuth2 instance ready to pass as auth_object to any service class.
    Exits with a helpful message if credentials are missing.
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

    # FalconPy maps region strings to base URLs automatically
    base_url = "https://api.crowdstrike.com" if region == "us-1" else f"https://api.{region}.crowdstrike.com"

    auth = OAuth2(client_id=client_id, client_secret=client_secret, base_url=base_url)

    # Trigger token fetch (FalconPy is lazy — token is not fetched until first use)
    auth.token()
    if not auth.authenticated():
        print(f"Authentication failed. Check your credentials and region ({region}).", file=sys.stderr)
        sys.exit(1)

    return auth
