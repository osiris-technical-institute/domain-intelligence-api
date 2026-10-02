# Domain Intelligence MCP server

An [MCP](https://modelcontextprotocol.io) server that gives AI agents and assistants WHOIS/RDAP, DNS, SSL, subdomain and email-security lookups for any domain.

- **Hosted endpoint:** `https://oti-labs.com/mcp` (Streamable HTTP)
- **Registry name:** `com.oti-labs/domain-intelligence`
- **Auth:** your RapidAPI key in the `X-RapidAPI-Key` header (or `Authorization: Bearer <key>`). Each tool call is a normal API call on your plan. The free plan gives 1,000 requests a month: [get a key](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api/pricing).

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

Replace `YOUR_KEY` with your RapidAPI key.

**Claude Code**

```bash
claude mcp add --transport http domain-intelligence https://oti-labs.com/mcp --header "X-RapidAPI-Key: YOUR_KEY"
```

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "domain-intelligence": {
      "url": "https://oti-labs.com/mcp",
      "headers": { "X-RapidAPI-Key": "YOUR_KEY" }
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
      "url": "https://oti-labs.com/mcp",
      "headers": { "X-RapidAPI-Key": "${input:rapidapi-key}" }
    }
  },
  "inputs": [
    { "type": "promptString", "id": "rapidapi-key", "description": "RapidAPI key", "password": true }
  ]
}
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "domain-intelligence": {
      "serverUrl": "https://oti-labs.com/mcp",
      "headers": { "X-RapidAPI-Key": "YOUR_KEY" }
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
      "args": ["-y", "mcp-remote", "https://oti-labs.com/mcp", "--header", "X-RapidAPI-Key:${RAPIDAPI_KEY}"],
      "env": { "RAPIDAPI_KEY": "YOUR_KEY" }
    }
  }
}
```

## Example prompts

- "How old is example.com and who is the registrar?"
- "Is this domain suspicious? Check its age, SSL issuer and SPF/DMARC."
- "List the live subdomains of example.com with their IPs."
- "When do the SSL certificates for these 10 domains expire?"

## Self-hosting

The server is one file. It calls the API through RapidAPI with the caller's key:

```bash
pip install -r requirements.txt
uvicorn server:app --host 127.0.0.1 --port 8002
```

To point it at your own copy of the API instead, set `DI_API_BASE` (and `DI_PROXY_SECRET` if your API checks one).
