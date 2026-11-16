"""Tests for rules.py. All URLs and emails are made up and use reserved domains."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_parser import parse_email
from rules import CHECKS, check_email, check_url, load_rules

PHISHING_EMAIL = """\
From: "Example Bank Security" <alerts@example-bank-alerts.test>
Reply-To: help@collect.example.net
To: someone@example.com
Subject: Your account suspended
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/html

<p>We noticed unusual activity. Your account will be suspended within 24 hours.</p>
<p><a href="http://203.0.113.7/login">www.examplebank.com</a></p>
"""

NORMAL_EMAIL = """\
From: Alice Smith <alice@example.com>
To: bob@example.com
Subject: Lunch on Friday
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass

Hi Bob, are we still on for lunch on Friday? The menu is here:
https://www.example.com/menu
Alice
"""


def ids(fired):
    """Return the set of rule ids in a list of fired rules."""
    return {rule["id"] for rule in fired}


def test_every_rule_has_a_check_and_fields():
    rules = load_rules()
    assert len(rules) == 14
    for rule in rules:
        assert rule["id"] in CHECKS
        assert rule["applies_to"] in ("url", "email")
        assert rule["points"] > 0
        assert rule["reason"] and rule["attack"].startswith("T")


def test_phishing_email_fires_r09_r12_r13():
    assert ids(check_email(parse_email(PHISHING_EMAIL))) == {"R09", "R12", "R13"}


def test_normal_email_fires_nothing():
    mail = parse_email(NORMAL_EMAIL)
    assert ids(check_email(mail)) == set()
    for link in mail["links"]:
        assert ids(check_url(link["href"])) == set()


def test_brand_display_name_and_auth_fail():
    text = """\
From: "PayPal Service" <service@example.test>
Subject: Hello
Authentication-Results: mx.example.com; spf=pass; dkim=none; dmarc=fail

Hello.
"""
    assert ids(check_email(parse_email(text))) == {"R10", "R11"}


def test_double_extension_attachment():
    text = """\
From: billing@example.com
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XYZ"

--XYZ
Content-Type: text/plain

Please see the invoice.
--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

AAAA
--XYZ--
"""
    mail = parse_email(text)
    assert mail["attachments"] == ["invoice.pdf.exe"]
    assert ids(check_email(mail)) == {"R14"}


def test_url_rules():
    assert ids(check_url("https://www.example.com/")) == set()
    assert ids(check_url("http://192.0.2.1/")) == {"R01", "R08"}
    assert "R02" in ids(check_url("https://bank.example.com@203.0.113.9/"))
    assert "R02" not in ids(check_url("https://example.com/@someone"))
    assert "R03" in ids(check_url("https://xn--pypal-4ve.example/"))
    assert "R04" in ids(check_url("https://paypal.example.test/"))
    assert "R04" not in ids(check_url("https://www.paypal.com/"))
    assert "R05" in ids(check_url("https://a.b.c.d.example.com/"))
    assert "R06" in ids(check_url("https://secure-login.example.com/"))
    assert "R07" in ids(check_url("https://bit.ly/abc123"))
