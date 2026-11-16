"""Tests for tune.py and for rules.py loading tuned weights. Made-up data only."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from rules import load_rules
from tune import feedback_examples, truly_malicious, tuned_weights


def test_truly_malicious_from_verdict_and_click():
    assert truly_malicious("malicious", True) is True     # flagged, analyst agrees
    assert truly_malicious("suspicious", False) is False  # flagged, analyst says wrong
    assert truly_malicious("benign", True) is False
    assert truly_malicious("benign", False) is True       # missed phishing


def test_noisy_rule_is_halved_and_good_rule_is_kept():
    rules = load_rules(weights_path=None)
    # R08 fires 6 times but only 2 were really malicious (precision 0.33).
    # R01 fires 6 times and all were malicious (precision 1.0).
    examples = [(["R08"], True)] * 2 + [(["R08"], False)] * 4 + [(["R01"], True)] * 6
    assert tuned_weights(examples, rules) == {"R08": 2.5}


def test_rule_with_too_few_hits_is_not_tuned():
    rules = load_rules(weights_path=None)
    examples = [(["R08"], False)] * 4  # only 4 hits, below the minimum of 5
    assert tuned_weights(examples, rules) == {}


def test_load_rules_applies_weights_file(tmp_path):
    path = tmp_path / "w.json"
    path.write_text(json.dumps({"R08": 2.5}))
    points = {r["id"]: r["points"] for r in load_rules(weights_path=str(path))}
    assert points["R08"] == 2.5 and points["R01"] == 30


def test_feedback_examples_read_from_db(tmp_path):
    path = str(tmp_path / "t.db")
    db.init_db(path)
    result = {"input": "http://x.example.test", "domain": "example.test",
              "score": 60, "verdict": "malicious", "rule_ids": ["R04", "R08"]}
    analysis_id = db.save_analysis("url", result, 1.0, path=path)
    db.save_feedback(analysis_id, False, path=path)  # analyst: verdict was wrong
    assert feedback_examples(path) == [(["R04", "R08"], False)]
