import re
from urllib.parse import urlparse

FEATURE_COLUMNS = [
    "url_length",
    "has_at",
    "has_dash",
    "dots",
    "has_https",
    "subdomains",
    "has_ip",
]


def normalize_url(url):
    """Validate and normalize the input URL."""
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    raw_url = url.strip()
    if not raw_url:
        raise ValueError("Please enter a URL.")

    if "://" not in raw_url:
        raw_url = f"https://{raw_url}"

    parsed = urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("The URL is invalid. Please enter a full website address.")

    return raw_url, parsed


def extract_features(url):
    """Extract the seven URL-based features used by the model."""
    normalized_url, parsed = normalize_url(url)
    hostname = (parsed.hostname or "").lower()

    url_length = len(normalized_url)
    has_at = 1 if "@" in normalized_url else 0
    has_dash = 1 if "-" in normalized_url else 0
    dots = normalized_url.count(".")
    has_https = 1 if normalized_url.lower().startswith("https://") else 0
    subdomains = max(hostname.count(".") - 1, 0) if hostname else 0
    has_ip = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname) else 0

    feature_dict = {
        "url_length": url_length,
        "has_at": has_at,
        "has_dash": has_dash,
        "dots": dots,
        "has_https": has_https,
        "subdomains": subdomains,
        "has_ip": has_ip,
    }

    return feature_dict, normalized_url


def build_feature_frame(features):
    """Convert a feature dictionary into a pandas DataFrame row."""
    import pandas as pd

    return pd.DataFrame([features], columns=FEATURE_COLUMNS)
