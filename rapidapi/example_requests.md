# Example Requests & Responses

## cURL — Full Aggregate Lookup

```bash
curl -s "https://87-99-152-31.sslip.io/lookup?domain=github.com" \
  -H "X-RapidAPI-Key: YOUR_RAPIDAPI_KEY" \
  -H "X-RapidAPI-Proxy-Secret: $PROXY_SECRET"
```

## cURL — DNS Records Only

```bash
curl -s "https://87-99-152-31.sslip.io/domain/github.com/dns" \
  -H "X-RapidAPI-Key: YOUR_RAPIDAPI_KEY" \
  -H "X-RapidAPI-Proxy-Secret: $PROXY_SECRET"
```

## cURL — Email Security Check

```bash
curl -s "https://87-99-152-31.sslip.io/domain/github.com/email-security" \
  -H "X-RapidAPI-Key: YOUR_RAPIDAPI_KEY" \
  -H "X-RapidAPI-Proxy-Secret: $PROXY_SECRET"
```

## Python (requests)

```python
import requests

HOST = "https://87-99-152-31.sslip.io"
HEADERS = {
    "X-RapidAPI-Key": "YOUR_RAPIDAPI_KEY",
    "X-RapidAPI-Proxy-Secret": "YOUR_PROXY_SECRET",
}

# Full lookup
response = requests.get(f"{HOST}/lookup", params={"domain": "github.com"}, headers=HEADERS)
data = response.json()

print(data["dns"]["A"])          # ["140.82.114.4"]
print(data["ssl"]["valid_until"]) # "2026-03-..."  
print(data["email_security"]["dmarc"]["policy"]) # "reject"
```

## JavaScript (fetch)

```javascript
const res = await fetch(
  "https://87-99-152-31.sslip.io/domain/github.com/subdomains",
  {
    headers: {
      "X-RapidAPI-Key": "YOUR_RAPIDAPI_KEY",
      "X-RapidAPI-Proxy-Secret": "YOUR_PROXY_SECRET",
    }
  }
);
const data = await res.json();
console.log(data.subdomains); // ["api.github.com", "docs.github.com", ...]
```

## Sample Response — /lookup?domain=example.com

```json
{
  "domain": "example.com",
  "elapsed_ms": 420,
  "dns": {
    "A": ["93.184.216.34"],
    "MX": [],
    "TXT": ["v=spf1 -all"],
    "NS": ["a.iana-servers.net.", "b.iana-servers.net."]
  },
  "ssl": {
    "issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "subject": "www.example.com",
    "valid_from": "2024-01-15",
    "valid_until": "2025-01-14",
    "days_remaining": 42,
    "sans": ["www.example.com", "example.com"]
  },
  "whois": {
    "registrar": "RESERVED-Internet Assigned Numbers Authority",
    "created": "1995-08-14",
    "expires": "2025-08-13",
    "age_days": 10736
  },
  "email_security": {
    "spf": {"exists": true, "record": "v=spf1 -all"},
    "dmarc": {"exists": false},
    "dkim": {}
  },
  "subdomains": {"count": 3, "subdomains": ["www", "m", "dev"]}
}
```
