"""Load the rules from rules.yaml and return which ones fired, with reasons.

rules.yaml holds the data (points, reason, ATT&CK id). This file holds one
small check function per rule id that answers "does this rule fire?".
"""

import json
import os
import re
from urllib.parse import urlsplit

import yaml

from features import BRANDS, normalise, parse_host, url_features

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(HERE, "rules.yaml")
WEIGHTS_PATH = os.path.join(HERE, "rule_weights.json")

# Well-known link shorteners. They hide where a link really goes.
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at"]

# Phrases that pressure the reader to act before they think.
URGENT_PHRASES = ["account suspended", "account will be suspended", "will be suspended",
                  "within 24 hours", "within 48 hours", "urgent action", "act now",
                  "immediately", "final notice", "unusual activity",
                  "verify your account", "will be closed", "password expires"]

# File types that run code or render as a web page when opened.
RISKY_EXTENSIONS = ["html", "htm", "js", "exe", "iso", "scr", "bat", "vbs", "lnk"]

# Harmless-looking extensions used as a disguise: "invoice.pdf.exe".
DECOY_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "zip"]

# Visible link text that looks like a domain or URL, e.g. "www.example.com".
DOMAIN_TEXT = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE)


def load_rules(path=RULES_PATH, weights_path=WEIGHTS_PATH):
    """Read rules.yaml, apply tuned points from rule_weights.json if it exists, and return the rules."""
    with open(path) as f:
        rules = yaml.safe_load(f)
    # tune.py writes {"R08": 2.5, ...} for rules whose points it lowered.
    # Pass weights_path=None to get the original points from rules.yaml.
    if weights_path and os.path.exists(weights_path):
        with open(weights_path) as f:
            tuned = json.load(f)
        for rule in rules:
            if rule["id"] in tuned:
                rule["points"] = tuned[rule["id"]]
    return rules


# ---------- URL checks: each takes a context dict built by url_context() ----------

def url_context(url):
    """Work out the facts about a URL once, so every URL check can reuse them."""
    host, subdomain, registered = parse_host(url)
    return {"url": normalise(url), "host": host, "subdomain": subdomain,
            "registered": registered, "features": url_features(url)}


def r01_ip_host(ctx):
    """Fire if the host is a raw IP address (phishing kits on bare servers)."""
    return ctx["features"]["is_ip"] == 1


def r02_at_in_host(ctx):
    """Fire if '@' appears in the host part; 'bank.example@evil.test' really goes to evil.test."""
    # Only the part between "//" and the first "/" counts. An "@" in the path,
    # like a profile page "/@name", is harmless.
    return "@" in urlsplit(ctx["url"]).netloc


def r03_punycode(ctx):
    """Fire if the host is punycode, which can show lookalike letters (e.g. Cyrillic 'а')."""
    return ctx["features"]["has_punycode"] == 1


def r04_brand_outside_domain(ctx):
    """Fire if a brand name is in the URL but not in the registered domain."""
    return ctx["features"]["brand_outside_domain"] == 1


def r05_deep_subdomains(ctx):
    """Fire if there are four or more subdomain levels, which push the real domain out of view."""
    return ctx["features"]["subdomain_depth"] >= 4


def r06_login_words_and_hyphens(ctx):
    """Fire on login/verify wording plus a hyphenated host, like 'secure-login-example.test'."""
    return ctx["features"]["suspicious_words"] > 0 and "-" in ctx["host"]


def r07_shortener(ctx):
    """Fire if the link is a known URL shortener."""
    return ctx["registered"] in SHORTENERS


def r08_no_https(ctx):
    """Fire if the link is not HTTPS (weak signal: many phishing sites now have HTTPS)."""
    return ctx["features"]["is_https"] == 0


# ---------- Email checks: each takes the dict from email_parser.parse_email() ----------

def r09_reply_to_mismatch(mail):
    """Fire if Reply-To is a different domain from From, so replies go to the attacker."""
    reply = mail["reply_to_domain"]
    return reply != "" and reply != mail["from_domain"]


def r10_brand_display_name(mail):
    """Fire if the display name says e.g. 'PayPal' but the address is not paypal's domain."""
    name = mail["from_name"].lower().replace(" ", "")
    for brand in BRANDS:
        if brand in name and brand not in mail["from_domain"]:
            return True
    return False


def r11_auth_failed(mail):
    """Fire if SPF, DKIM or DMARC shows 'fail' in Authentication-Results (likely spoofed sender)."""
    return re.search(r"\b(spf|dkim|dmarc)=fail\b", mail["auth_results"], re.IGNORECASE) is not None


def r12_urgency(mail):
    """Fire if the subject or body uses pressure wording like 'within 24 hours'."""
    text = (mail["subject"] + " " + mail["body"]).lower()
    for phrase in URGENT_PHRASES:
        if phrase in text:
            return True
    return False


def r13_link_text_mismatch(mail):
    """Fire if a link shows one domain as its text but points to a different domain."""
    for link in mail["links"]:
        text = link["text"].strip()
        if not DOMAIN_TEXT.match(text):
            continue  # text like "Click here" makes no domain claim
        shown = parse_host(text)[2]
        actual = parse_host(link["href"])[2]
        if shown != actual:
            return True
    return False


def r14_risky_attachment(mail):
    """Fire if an attachment is a risky type or has a double extension like 'invoice.pdf.exe'."""
    for name in mail["attachments"]:
        parts = name.lower().split(".")
        if len(parts) < 2:
            continue
        if parts[-1] in RISKY_EXTENSIONS:
            return True
        if len(parts) >= 3 and parts[-2] in DECOY_EXTENSIONS:
            return True
    return False


# Which function checks which rule id.
CHECKS = {
    "R01": r01_ip_host, "R02": r02_at_in_host, "R03": r03_punycode,
    "R04": r04_brand_outside_domain, "R05": r05_deep_subdomains,
    "R06": r06_login_words_and_hyphens, "R07": r07_shortener, "R08": r08_no_https,
    "R09": r09_reply_to_mismatch, "R10": r10_brand_display_name,
    "R11": r11_auth_failed, "R12": r12_urgency,
    "R13": r13_link_text_mismatch, "R14": r14_risky_attachment,
}


def run_rules(target, kind, rules=None):
    """Run every rule of this kind ('url' or 'email') on the target; return the fired rules."""
    if rules is None:
        rules = load_rules()
    fired = []
    for rule in rules:
        if rule["applies_to"] != kind:
            continue
        if CHECKS[rule["id"]](target):
            fired.append(rule)
    return fired


def check_url(url, rules=None):
    """Return the URL rules that fire for one URL string."""
    return run_rules(url_context(url), "url", rules)


def check_email(mail, rules=None):
    """Return the email rules that fire for a parsed email (links are scored separately)."""
    return run_rules(mail, "email", rules)
