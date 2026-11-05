"""Checks that this computer can reach NVD before a demo.

Usage (from the backend folder):
    python -m scripts.check_nvd
"""

import time

from app.nvd import NvdClient, NvdUnavailable


def main():
    client = NvdClient()
    print("API key:", "yes (fast lookups)" if client.api_key else "no (about 6 seconds per request)")
    start = time.monotonic()
    try:
        matches = client.lookup("a:apache:tomcat", "9.0.30", use_cache=False)
    except NvdUnavailable as exc:
        print(f"NVD not reachable: {exc}")
        print("The vetted rules still work. Software they don't cover will be listed as 'Not checked'.")
        return
    print(f"NVD reachable: Apache Tomcat 9.0.30 has {len(matches)} CVEs ({time.monotonic() - start:.1f} seconds)")


if __name__ == "__main__":
    main()
