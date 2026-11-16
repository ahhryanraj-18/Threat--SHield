"""Tests for email_parser.py. All emails are made up and use reserved domains."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_parser import domain_of_address, find_links, parse_email


def test_headers_are_read():
    mail = parse_email("""\
From: "Help Desk" <help@mail.example.com>
Reply-To: other@example.net
Subject: Test
Authentication-Results: mx.example.com; spf=pass

Body text.
""")
    assert mail["from_name"] == "Help Desk"
    assert mail["from_address"] == "help@mail.example.com"
    assert mail["from_domain"] == "example.com"
    assert mail["reply_to_domain"] == "example.net"
    assert "spf=pass" in mail["auth_results"]
    assert "Body text." in mail["body"]


def test_missing_reply_to_is_empty():
    assert parse_email("From: a@example.com\n\nhi")["reply_to_domain"] == ""


def test_html_link_keeps_visible_text():
    links = find_links('<a href="http://example.net/x">example.com</a>')
    assert links == [{"href": "http://example.net/x", "text": "example.com"}]


def test_plain_text_link_trailing_punctuation_removed():
    links = find_links("See https://example.com/page.")
    assert links == [{"href": "https://example.com/page", "text": ""}]


def test_domain_of_address():
    assert domain_of_address("x@sub.example.co.uk") == "example.co.uk"
    assert domain_of_address("not-an-address") == ""
