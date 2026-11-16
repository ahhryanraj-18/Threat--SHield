"""Turn a URL string into a dictionary of numeric features.

SAFETY: everything here works on the text of the URL only. We never fetch,
open or resolve the URL. urllib.parse only splits a string into parts.
"""

import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

# suffix_list_urls=() makes tldextract use its bundled copy of the public
# suffix list instead of downloading it, so this module never touches the network.
_extract = tldextract.TLDExtract(suffix_list_urls=())

# Words phishing pages use to look like a sign-in or account page.
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update"]

# Brands that phishers often impersonate. Kept short on purpose.
BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix",
          "facebook", "instagram", "linkedin", "dropbox", "outlook", "office365"]

# The order of the features the model sees. Keep it fixed.
FEATURE_NAMES = [
    "length", "num_dots", "num_hyphens", "num_digits", "subdomain_depth",
    "is_ip", "has_at", "has_punycode", "is_https", "suspicious_words",
    "brand_outside_domain",
]


def normalise(url):
    """Trim the URL and add http:// if no scheme was given, so it can be parsed."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def parse_host(url):
    """Return (host, subdomain, registered_domain) for a URL, all lower case."""
    # urlsplit already drops anything before an "@" from the hostname,
    # which is exactly what a browser does (the R02 trick).
    host = (urlsplit(normalise(url)).hostname or "").lower()
    subdomain, registered = split_domain(host)
    return host, subdomain, registered


def split_domain(host):
    """Split a host name into (subdomain, registered_domain)."""
    host = host.lower().strip(".")
    if is_ip_address(host):
        return "", host

    parts = _extract(host)
    if parts.suffix:
        # top_domain_under_public_suffix is "example.com" for "login.example.com".
        return parts.subdomain, parts.top_domain_under_public_suffix

    # Unknown ending (e.g. ".test" or ".local"): treat the last two labels
    # as the registered domain and everything before them as the subdomain.
    labels = host.split(".")
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def is_ip_address(host):
    """Return True if the host is a raw IPv4 or IPv6 address instead of a name."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def count_suspicious_words(url):
    """Count how many of the suspicious words appear in the URL."""
    text = url.lower()
    count = 0
    for word in SUSPICIOUS_WORDS:
        if word in text:
            count += 1
    return count


def brand_outside_domain(url, registered_domain):
    """Return True if a brand name appears in the URL but not in the registered domain."""
    # Trick: "paypal.com.secure-check.example" or "example.test/paypal/login".
    # The brand is visible to the user, but the site belongs to someone else.
    text = url.lower()
    for brand in BRANDS:
        if brand in text and brand not in registered_domain:
            return True
    return False


def url_features(url):
    """Turn a URL string into a dictionary of numeric features (see FEATURE_NAMES)."""
    full = normalise(url)
    host, subdomain, registered = parse_host(full)
    depth = len(subdomain.split(".")) if subdomain else 0

    return {
        "length": len(full),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_digits": len(re.findall(r"\d", full)),
        "subdomain_depth": depth,
        "is_ip": int(is_ip_address(host)),
        "has_at": int("@" in full),
        # "xn--" marks punycode: lookalike letters from other alphabets.
        "has_punycode": int("xn--" in host),
        "is_https": int(full.lower().startswith("https://")),
        "suspicious_words": count_suspicious_words(full),
        "brand_outside_domain": int(brand_outside_domain(full, registered)),
    }


if __name__ == "__main__":
    sample = "http://paypal.com.login-verify.example.test/account/update"
    print(sample)
    for name, value in url_features(sample).items():
        print(f"  {name:22} {value}")
