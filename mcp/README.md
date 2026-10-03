# Domain Intelligence MCP server

An [MCP](https://modelcontextprotocol.io) server that gives AI agents and assistants WHOIS/RDAP, DNS, SSL, subdomain and email-security lookups for any domain.

- **Hosted endpoint:** `https://oti-labs.com/mcp` (Streamable HTTP)
- **Registry name:** `com.oti-labs/domain-intelligence` (also on [Smithery](https://smithery.ai/servers/oti-labs/domain-intelligence))
- **No key to start:** 1,000 lookups a month per IP (per /64 for IPv6), up to 10 a minute. Hosted connectors that call from their provider's shared addresses (Claude, ChatGPT, the Smithery gateway) share one pool per provider: 10,000 a month, up to 120 a minute. Keyless use on the hosted server stops at 2,000 calls a day in total and resets at 00:00 UTC.
- **After that:** add a RapidAPI key in the `X-RapidAPI-Key` header (or `Authorization: Bearer <key>`). Calls then count on your RapidAPI plan; the free plan adds another 1,000 a month: [get a key](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api/pricing).

## Tools

| Tool | What it returns |
|---|---|
| `domain_lookup` | Everything below in one call. Big subdomain lists are trimmed (`subdomain_limit`, default 50). |
| `whois_lookup` | Registrar, created/updated/expiry dates, nameservers, status. RDAP first, port-43 WHOIS fallback. |
| `dns_records` | A, AAAA, MX, TXT, NS, CAA and SOA records. |
| `ssl_certificate` | Live TLS handshake: issuer, validity dates, `days_until_expiry`, SANs, signature algorithm. |
| `subdomains` | Live hosts with IPs, all names found (live first), collapsed infrastructure pools. `wait=true` waits for every source. |
| `email_security` | SPF, DMARC, and DKIM keys from ~29 common selectors. |

All tools are read-only.

## Setup

These work without a key. To use a RapidAPI key, add the header shown at the end of this section.

**Claude Code**

```bash
claude mcp add --transport http domain-intelligence https://oti-labs.com/mcp
```

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "domain-intelligence": {
      "url": "https://oti-labs.com/mcp"
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`)

```json
{
  "servers": {
    "domain-intelligence": {
      "type": "http",
      "url": "https://oti-labs.com/mcp"
    }
  }
}
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "domain-intelligence": {
      "serverUrl": "https://oti-labs.com/mcp"
    }
  }
}
```

**Claude Desktop and other stdio-only clients**, through [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "domain-intelligence": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://oti-labs.com/mcp"]
    }
  }
}
```

**Adding a RapidAPI key.** Claude Code: append `--header "X-RapidAPI-Key: YOUR_KEY"`. Cursor, VS Code and Windsurf: add `"headers": { "X-RapidAPI-Key": "YOUR_KEY" }` next to the URL. `mcp-remote`: add `"--header", "X-RapidAPI-Key:YOUR_KEY"` to `args`.

## Example prompts

- "How old is example.com and who is the registrar?"
- "Is this domain suspicious? Check its age, SSL issuer and SPF/DMARC."
- "List the live subdomains of example.com with their IPs."
- "When do the SSL certificates for these 10 domains expire?"

## Self-hosting

The server is one file. Keyed calls go through RapidAPI with the caller's key; keyless calls go to `DI_INTERNAL_BASE` with `RAPIDAPI_PROXY_SECRET` and are counted in Redis (`REDIS_URL`):

```bash
pip install -r requirements.txt
uvicorn server:app --host 127.0.0.1 --port 8002
```

To send keyed calls to your own copy of the API instead of RapidAPI, set `DI_API_BASE` (and `DI_PROXY_SECRET` if your API checks one).

Keyless limits can be changed with `MCP_KEYLESS_MONTHLY`, `MCP_KEYLESS_PER_MINUTE`, `MCP_PROVIDER_MONTHLY`, `MCP_PROVIDER_PER_MINUTE` and `MCP_KEYLESS_DAILY_CEILING`. ChatGPT's connector addresses come from `chatgpt-connectors.json`, which `refresh_openai_ranges.py` downloads from OpenAI; run it once a day from cron. Without that file, ChatGPT calls are counted per IP. Claude's outbound range is built in.
