"""Refresh the ChatGPT connector address ranges used by the keyless MCP quota.

OpenAI publishes the addresses ChatGPT connectors call from at
https://openai.com/chatgpt-connectors.json. This saves a checked copy next to server.py (the server
re-reads it when it changes). If the download or the check fails, the last good copy stays.
Run daily from cron. Standard library only.
"""
import datetime
import ipaddress
import json
import os
import sys
import urllib.request

URL = "https://openai.com/chatgpt-connectors.json"
OUT = os.environ.get(
    "MCP_OPENAI_RANGES_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "chatgpt-connectors.json"))
MIN_PREFIXES = 10   # a near-empty list is more likely a bad response than a real change


def main() -> int:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0 (oti-labs-mcp ranges refresh)"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
        data = json.loads(body)
        nets = [ipaddress.ip_network(p.get("ipv4Prefix") or p["ipv6Prefix"], strict=False) for p in data["prefixes"]]
        if len(nets) < MIN_PREFIXES:
            raise ValueError(f"only {len(nets)} prefixes")
    except Exception as e:
        print(f"{stamp} refresh failed, keeping the last copy: {type(e).__name__}: {e}")
        return 1
    try:
        with open(OUT, "rb") as f:
            if f.read() == body:
                print(f"{stamp} unchanged: {len(nets)} prefixes, creationTime {data.get('creationTime')}")
                return 0
    except FileNotFoundError:
        pass
    tmp = OUT + ".tmp"
    with open(tmp, "wb") as f:
        f.write(body)
    os.replace(tmp, OUT)
    print(f"{stamp} updated: {len(nets)} prefixes, creationTime {data.get('creationTime')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
