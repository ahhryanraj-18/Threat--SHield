"""Tests for scorer.py, db.py and the defang helper. Made-up URLs only."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
import model
from app import defang
from features import url_features
from scorer import combine, rule_score, score_email, score_url, verdict

THRESHOLDS = {"suspicious": 40, "malicious": 70}


def train_tiny_model(tmp_path):
    """Train a throwaway model so tests do not depend on the real dataset."""
    bad = ["http://192.0.2.1/login", "http://paypal.example.test/verify"]
    good = ["https://www.example.com", "https://www.example.org"]
    model.train([url_features(u) for u in bad + good], [1, 1, 0, 0],
                path=str(tmp_path / "m.joblib"))


def test_rule_score_is_capped():
    assert rule_score([{"points": 60}, {"points": 70}]) == 100


def test_combine_and_verdict():
    assert combine(80, 40) == 60
    assert verdict(39, THRESHOLDS) == "benign"
    assert verdict(40, THRESHOLDS) == "suspicious"
    assert verdict(70, THRESHOLDS) == "malicious"


def test_score_url_shape(tmp_path):
    train_tiny_model(tmp_path)
    result = score_url("http://192.0.2.1/login", thresholds=THRESHOLDS)
    assert "R01" in result["rule_ids"]
    assert 0 <= result["score"] <= 100
    assert result["verdict"] in ("benign", "suspicious", "malicious")
    assert result["reasons"][-1].startswith("Model:")


def test_save_and_read_history(tmp_path):
    path = str(tmp_path / "t.db")
    db.init_db(path)
    result = {"input": "http://example.test", "domain": "example.test",
              "score": 55, "verdict": "suspicious", "rule_ids": ["R08"]}
    new_id = db.save_analysis("url", result, 3.2, path=path)
    rows = db.recent_analyses(path=path)
    assert rows[0]["id"] == new_id
    assert rows[0]["verdict"] == "suspicious"


def test_defang():
    assert defang("http://login.example.com/a") == "hxxp://login[.]example[.]com/a"
    assert defang("https://example.com") == "hxxps://example[.]com"


PHISH_EMAIL = """\
From: "Example Bank Security" <alerts@example-bank-alerts.test>
Reply-To: help@collect.example.net
Subject: Your account suspended
Content-Type: text/html

<p>Your account will be suspended within 24 hours.</p>
<a href="http://203.0.113.7/login">www.examplebank.com</a>
<a href="mailto:help@example.net">mail us</a>
"""


def test_score_email_combines_email_and_link_rules(tmp_path):
    train_tiny_model(tmp_path)
    result = score_email(PHISH_EMAIL, thresholds=THRESHOLDS)
    assert len(result["links"]) == 1          # mailto: link is not scored
    assert {"R09", "R12", "R13", "R01", "R08"} <= set(result["rule_ids"])
    assert result["rule_score"] == 100        # capped
    assert result["domain"] == "example-bank-alerts.test"
    assert "Link 1 fired: R01, R08." in result["reasons"]


def test_email_without_links(tmp_path):
    train_tiny_model(tmp_path)
    result = score_email("From: a@example.com\nSubject: hi\n\nSee you soon.", thresholds=THRESHOLDS)
    assert result["links"] == [] and result["ml_score"] == 0
    assert result["verdict"] == "benign"


def test_feedback_and_repeat_domains(tmp_path):
    path = str(tmp_path / "t.db")
    db.init_db(path)
    flagged = {"input": "http://x.example.test", "domain": "example.test",
               "score": 80, "verdict": "malicious", "rule_ids": ["R04"]}
    ids = [db.save_analysis("url", flagged, 1.0, path=path) for _ in range(3)]
    assert db.repeat_domains(path=path) == [{"domain": "example.test", "times": 3}]

    assert db.save_feedback(ids[0], False, path=path) is True
    assert db.save_feedback(9999, True, path=path) is False  # unknown check
    rows = {r["id"]: r for r in db.recent_analyses(path=path)}
    assert rows[ids[0]]["feedback"] == 0 and rows[ids[1]]["feedback"] is None
