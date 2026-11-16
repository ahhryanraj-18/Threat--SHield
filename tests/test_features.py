"""Tests for features.py. All URLs are made up and use reserved domains."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features import FEATURE_NAMES, parse_host, url_features


def test_all_features_present_in_fixed_order():
    feats = url_features("https://example.com")
    assert list(feats.keys()) == FEATURE_NAMES


def test_plain_benign_url():
    feats = url_features("https://www.example.com/about")
    assert feats["is_https"] == 1
    assert feats["is_ip"] == 0
    assert feats["has_at"] == 0
    assert feats["subdomain_depth"] == 1
    assert feats["brand_outside_domain"] == 0
    assert feats["suspicious_words"] == 0


def test_missing_scheme_is_treated_as_http():
    feats = url_features("example.com/login")
    assert feats["is_https"] == 0
    assert feats["suspicious_words"] == 1


def test_ip_host():
    assert url_features("http://192.0.2.10/login")["is_ip"] == 1


def test_at_sign_hides_real_host():
    url = "http://example.com@203.0.113.5/verify"
    feats = url_features(url)
    assert feats["has_at"] == 1
    # The real host is the part after "@", as a browser would read it.
    assert parse_host(url)[0] == "203.0.113.5"
    assert feats["is_ip"] == 1


def test_punycode_host():
    assert url_features("http://xn--pypal-4ve.example/")["has_punycode"] == 1


def test_brand_in_subdomain_not_registered_domain():
    url = "http://paypal.com.secure-login.example.test/account/update"
    feats = url_features(url)
    assert feats["brand_outside_domain"] == 1
    assert feats["subdomain_depth"] == 3  # paypal . com . secure-login
    assert feats["suspicious_words"] == 4  # secure, login, account, update


def test_registered_domain_uses_public_suffix():
    host, sub, registered = parse_host("https://login.shop.example.co.uk/x")
    assert host == "login.shop.example.co.uk"
    assert sub == "login.shop"
    assert registered == "example.co.uk"


def test_unknown_suffix_falls_back_to_last_two_labels():
    host, sub, registered = parse_host("http://a.b.example.test/")
    assert sub == "a.b"
    assert registered == "example.test"


def test_counts():
    feats = url_features("http://a-b-c.example.com/p1/p22")
    assert feats["num_hyphens"] == 2
    assert feats["num_digits"] == 3
    assert feats["num_dots"] == 2
