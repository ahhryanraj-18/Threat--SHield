"""Combine rule points and the model's probability into a score, a verdict and reasons.

  rule_score = sum of points of fired rules, capped at 100
  ml_score   = model probability x 100
  score      = 0.5 x rule_score + 0.5 x ml_score
The verdict cut-offs come from thresholds.json, which evaluate.py chooses on
validation data. If that file is missing we use the PRD defaults (40 / 70).
"""

import json
import os

import model
from email_parser import parse_email
from rules import check_email, load_rules, run_rules, url_context

HERE = os.path.dirname(os.path.abspath(__file__))
THRESHOLDS_PATH = os.path.join(HERE, "thresholds.json")
DEFAULT_THRESHOLDS = {"suspicious": 40, "malicious": 70}


def load_thresholds(path=THRESHOLDS_PATH):
    """Return the verdict cut-offs from thresholds.json, or the defaults."""
    if not os.path.exists(path):
        return dict(DEFAULT_THRESHOLDS)
    with open(path) as f:
        return json.load(f)


def rule_score(fired):
    """Add up the points of the fired rules, capped at 100."""
    total = 0
    for rule in fired:
        total += rule["points"]
    return min(total, 100)


def combine(r_score, m_score):
    """Average the rule score and the model score (both 0 to 100)."""
    # Equal weights: rules are precise and explainable, the model generalises.
    return 0.5 * r_score + 0.5 * m_score


def verdict(score, thresholds):
    """Turn a 0-100 score into 'benign', 'suspicious' or 'malicious'."""
    if score >= thresholds["malicious"]:
        return "malicious"
    if score >= thresholds["suspicious"]:
        return "suspicious"
    return "benign"


def rule_lines(fired):
    """Return one readable line per fired rule, with its ATT&CK id."""
    lines = []
    for rule in fired:
        lines.append(f"{rule['id']} ({rule['attack']}): {rule['reason']}")
    return lines


def reason_lines(fired, probability):
    """Build the reasons shown to the user: one per fired rule, plus the model's view."""
    lines = rule_lines(fired)
    lines.append(f"Model: {probability * 100:.0f}% probability that this URL looks like past phishing.")
    return lines


def score_url(url, rules=None, thresholds=None):
    """Score one URL and return its score, verdict, reasons and fired rule ids."""
    if rules is None:
        rules = load_rules()
    if thresholds is None:
        thresholds = load_thresholds()

    ctx = url_context(url)
    fired = run_rules(ctx, "url", rules)
    probability = model.predict_features([ctx["features"]])[0]

    r_score = rule_score(fired)
    m_score = probability * 100
    score = combine(r_score, m_score)
    return {
        "input": url,
        "domain": ctx["registered"],
        "score": round(score),
        "rule_score": r_score,
        "ml_score": round(m_score),
        "probability": probability,
        "verdict": verdict(score, thresholds),
        "reasons": reason_lines(fired, probability),
        "rule_ids": [rule["id"] for rule in fired],
    }


def score_email(text, rules=None, thresholds=None):
    """Score a pasted email: its own rules, plus a score and verdict for every link."""
    if rules is None:
        rules = load_rules()
    if thresholds is None:
        thresholds = load_thresholds()

    mail = parse_email(text)
    fired = check_email(mail, rules)

    # Score each web link on its own. mailto: and "#" links are not web pages.
    links = []
    for link in mail["links"]:
        if link["href"].lower().startswith(("http://", "https://")):
            links.append(score_url(link["href"], rules, thresholds))

    # The email is as risky as its own tricks plus its worst link's tricks.
    worst_link_rules = max([l["rule_score"] for l in links], default=0)
    r_score = min(rule_score(fired) + worst_link_rules, 100)
    # PRD: for an email, the model score is the highest probability among its links.
    probability = max([l["probability"] for l in links], default=0.0)
    m_score = probability * 100
    score = combine(r_score, m_score)

    reasons = rule_lines(fired)
    rule_ids = [rule["id"] for rule in fired]
    # Links are referred to by number; the page shows each one defanged in a table.
    for number, l in enumerate(links, start=1):
        if l["rule_ids"]:
            reasons.append(f"Link {number} fired: {', '.join(l['rule_ids'])}.")
        for rule_id in l["rule_ids"]:
            if rule_id not in rule_ids:
                rule_ids.append(rule_id)
    if links:
        reasons.append(f"Model: highest link probability is {probability * 100:.0f}%.")
    else:
        reasons.append("Model: no web links to score.")

    return {
        "input": text,
        "domain": mail["from_domain"],
        "from_address": mail["from_address"],
        "subject": mail["subject"],
        "score": round(score),
        "rule_score": r_score,
        "ml_score": round(m_score),
        "verdict": verdict(score, thresholds),
        "reasons": reasons,
        "rule_ids": rule_ids,
        "links": links,
    }
