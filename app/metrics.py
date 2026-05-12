"""Prometheus metrics."""
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST

REGISTRY = CollectorRegistry()

REQUEST_COUNT = Counter(
    "domain_intel_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=REGISTRY,
)

REQUEST_LATENCY = Histogram(
    "domain_intel_request_latency_seconds",
    "Request latency in seconds",
    ["endpoint"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0),
    registry=REGISTRY,
)

CACHE_HITS = Counter(
    "domain_intel_cache_hits_total",
    "Cache hit count",
    ["namespace"],
    registry=REGISTRY,
)

CACHE_MISSES = Counter(
    "domain_intel_cache_misses_total",
    "Cache miss count",
    ["namespace"],
    registry=REGISTRY,
)

LOOKUP_TIMEOUTS = Counter(
    "domain_intel_lookup_timeouts_total",
    "External lookup timeouts",
    ["source"],
    registry=REGISTRY,
)

LOOKUP_ERRORS = Counter(
    "domain_intel_lookup_errors_total",
    "External lookup errors (non-timeout)",
    ["source"],
    registry=REGISTRY,
)

INFLIGHT = Gauge(
    "domain_intel_requests_inflight",
    "In-flight requests",
    registry=REGISTRY,
)


def render() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
