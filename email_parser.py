"""Read pasted email text: From, Reply-To, Authentication-Results, body, links, attachments.

SAFETY: we only read text. Attachments are never opened or saved; we look at
their file names only. HTML is parsed to find links, never rendered.
"""

import email
import re
from email.utils import parseaddr
from html.parser import HTMLParser

from features import split_domain

# A bare http(s) link written in plain text.
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class LinkParser(HTMLParser):
    """Collect every <a href="..."> in an HTML body with the text shown for it."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"href": self._href.strip(),
                               "text": "".join(self._text).strip()})
            self._href = None


def domain_of_address(address):
    """Return the registered domain of an email address, e.g. 'example.com'."""
    if "@" not in address:
        return ""
    host = address.rsplit("@", 1)[1]
    return split_domain(host)[1]


def decode_part(part):
    """Return the text of one email part, decoding base64 or quoted-printable."""
    raw = part.get_payload(decode=True)
    if raw is None:
        return str(part.get_payload())
    charset = part.get_content_charset() or "utf-8"
    return raw.decode(charset, errors="replace")


def read_body_and_attachments(msg):
    """Return (body_text, attachment_names) for a parsed message."""
    bodies = []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name:
            # Only the name is kept. The content is never opened.
            attachments.append(name)
        elif part.get_content_type() in ("text/plain", "text/html"):
            bodies.append(decode_part(part))
    return "\n".join(bodies), attachments


def find_links(body):
    """Return a list of {'href', 'text'} for every link in the body."""
    parser = LinkParser()
    parser.feed(body)
    links = parser.links
    seen = {link["href"] for link in links}

    # Plain-text links have no separate visible text.
    for match in URL_PATTERN.findall(body):
        href = match.rstrip(".,);]")
        if href not in seen:
            links.append({"href": href, "text": ""})
            seen.add(href)
    return links


def parse_email(text):
    """Turn pasted email text into a dictionary of the parts the rules look at."""
    msg = email.message_from_string(text.lstrip())
    from_name, from_address = parseaddr(msg.get("From", ""))
    _, reply_to_address = parseaddr(msg.get("Reply-To", ""))
    body, attachments = read_body_and_attachments(msg)

    return {
        "from_name": from_name,
        "from_address": from_address.lower(),
        "from_domain": domain_of_address(from_address.lower()),
        "reply_to_domain": domain_of_address(reply_to_address.lower()),
        "auth_results": msg.get("Authentication-Results", ""),
        "subject": msg.get("Subject", ""),
        "body": body,
        "links": find_links(body),
        "attachments": attachments,
    }
