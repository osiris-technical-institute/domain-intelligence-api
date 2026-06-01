"""Curated seed list of popular domains for sitemap + report pre-warming.

CATEGORIES is the canonical source of truth — each domain belongs to exactly
one category. SITEMAP_DOMAINS is derived from it for backward compatibility
with existing imports (sitemap.xml, prewarm.sh, _related_for helpers).

To add a domain: append to the appropriate category list. Order within each
category determines the order in SITEMAP_DOMAINS (Python 3.7+ preserves dict
insertion order), which in turn determines TOP_PREWARM selection.
"""

CATEGORIES = {
    "AI & Big Tech": [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
        "openai.com", "anthropic.com", "nvidia.com", "ibm.com", "oracle.com",
        "intel.com", "amd.com", "qualcomm.com", "samsung.com", "tesla.com",
    ],
    "Cloud & Infrastructure": [
        "aws.amazon.com", "cloudflare.com", "vercel.com", "render.com", "fly.io",
        "supabase.com", "firebase.google.com", "heroku.com", "digitalocean.com",
        "linode.com", "vultr.com", "hetzner.com", "ovh.com", "scaleway.com",
    ],
    "Developer Tools": [
        "github.com", "gitlab.com", "bitbucket.org", "atlassian.com", "jira.com",
        "jetbrains.com", "docker.com", "kubernetes.io", "npmjs.com", "pypi.org",
        "rust-lang.org", "python.org", "nodejs.org", "go.dev", "java.com",
        "vscode.dev", "stackoverflow.com", "huggingface.co", "replicate.com",
    ],
    "SaaS & Productivity": [
        "slack.com", "notion.so", "figma.com", "airtable.com", "asana.com",
        "monday.com", "trello.com", "clickup.com", "linear.app", "miro.com",
        "canva.com", "dropbox.com", "box.com", "lastpass.com",
    ],
    "Sales, Marketing & Analytics": [
        "salesforce.com", "hubspot.com", "zendesk.com", "intercom.com", "mailchimp.com",
        "sendgrid.com", "twilio.com", "mixpanel.com", "amplitude.com", "segment.com",
    ],
    "Communication": [
        "zoom.us", "discord.com", "telegram.org", "signal.org", "whatsapp.com",
    ],
    "Email Providers": [
        "gmail.com", "outlook.com", "yahoo.com", "proton.me", "fastmail.com",
    ],
    "Search & Browsers": [
        "duckduckgo.com", "bing.com", "brave.com", "kagi.com", "mozilla.org",
    ],
    "Social": [
        "x.com", "linkedin.com", "instagram.com", "reddit.com", "youtube.com",
        "tiktok.com", "pinterest.com", "twitch.tv", "snapchat.com",
    ],
    "News & Media": [
        "nytimes.com", "bbc.com", "cnn.com", "theverge.com", "techcrunch.com",
        "wired.com", "arstechnica.com", "engadget.com", "ft.com", "wsj.com",
        "bloomberg.com", "reuters.com", "guardian.co.uk",
    ],
    "Reference": [
        "wikipedia.org", "imdb.com", "weather.com",
    ],
    "Finance & Payments": [
        "paypal.com", "stripe.com", "square.com", "plaid.com", "wise.com",
        "revolut.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
        "americanexpress.com", "visa.com", "mastercard.com",
    ],
    "Crypto": [
        "coinbase.com", "binance.com", "kraken.com", "etherscan.io",
    ],
    "E-commerce": [
        "shopify.com", "etsy.com", "ebay.com", "walmart.com", "target.com",
        "alibaba.com", "aliexpress.com", "bestbuy.com", "wayfair.com", "ikea.com",
    ],
    "Streaming & Entertainment": [
        "netflix.com", "spotify.com", "hulu.com", "disneyplus.com", "primevideo.com",
        "max.com", "paramountplus.com", "appletv.com",
    ],
    "Travel & Mobility": [
        "airbnb.com", "booking.com", "expedia.com", "kayak.com", "uber.com",
        "lyft.com", "doordash.com", "instacart.com",
    ],
    "Education": [
        "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu", "cmu.edu",
        "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    ],
    "Security": [
        "cisco.com", "paloaltonetworks.com", "crowdstrike.com", "splunk.com",
        "fortinet.com", "okta.com", "duo.com", "1password.com",
    ],
    "Domain & Hosting": [
        "godaddy.com", "namecheap.com", "porkbun.com", "name.com",
    ],
    "CDN & Performance": [
        "fastly.com", "akamai.com", "jsdelivr.net", "unpkg.com",
    ],
}


def category_slug(category_name: str) -> str:
    """Stable URL/anchor slug for a category name.

    Used by the reports index template for #cat-* anchors and any client-side
    JS that needs the same slug.
    """
    return (
        category_name.lower()
        .replace("&", "and")
        .replace(",", "")
        .replace(" ", "-")
    )


# Derived: flat domain list (insertion order preserved by Python 3.7+ dicts).
# Used by sitemap.xml, prewarm.sh, and _related_for helpers.
SITEMAP_DOMAINS = [d for ds in CATEGORIES.values() for d in ds]

# First N domains get prewarmed nightly (cache warm before Googlebot crawls)
TOP_PREWARM = SITEMAP_DOMAINS[:100]
