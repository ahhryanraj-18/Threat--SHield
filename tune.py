"""Read analyst feedback, halve the points of noisy rules, and write rule_weights.json.

For each rule we measure its precision on the feedback:
    precision = (times it fired on something truly malicious) / (times it fired)
A rule with at least MIN_HITS hits and precision under MIN_PRECISION is noisy:
it raises false alarms, so its points are halved. Points always start from
rules.yaml, so running this twice does not halve a rule twice.

Run:  python tune.py
"""

import json

import db
from rules import WEIGHTS_PATH, load_rules

MIN_HITS = 5
MIN_PRECISION = 0.5


def truly_malicious(verdict, correct):
    """Work out the true label from our verdict and the analyst's right/wrong click."""
    flagged = verdict != "benign"
    # "Right" keeps our answer; "wrong" flips it.
    return flagged if correct else not flagged


def feedback_examples(path=db.DB_PATH):
    """Return (rule_ids, is_malicious) pairs from the feedback table."""
    with db.connect(path) as conn:
        rows = conn.execute(
            "SELECT f.rule_ids, f.correct, a.verdict FROM feedback f "
            "JOIN analyses a ON a.id = f.analysis_id").fetchall()
    examples = []
    for row in rows:
        examples.append((json.loads(row["rule_ids"]), truly_malicious(row["verdict"], row["correct"])))
    return examples


def rule_precision(examples):
    """Return {rule_id: (hits, true_hits)} counted over the examples."""
    counts = {}
    for rule_ids, is_malicious in examples:
        for rule_id in rule_ids:
            hits, true_hits = counts.get(rule_id, (0, 0))
            counts[rule_id] = (hits + 1, true_hits + (1 if is_malicious else 0))
    return counts


def tuned_weights(examples, rules):
    """Return {rule_id: new_points} for every noisy rule (only those whose points change)."""
    counts = rule_precision(examples)
    new_points = {}
    for rule in rules:
        hits, true_hits = counts.get(rule["id"], (0, 0))
        if hits >= MIN_HITS and true_hits / hits < MIN_PRECISION:
            new_points[rule["id"]] = rule["points"] / 2
    return new_points


def print_report(examples, rules, new_points):
    """Print hits, precision and old -> new points for every rule that fired."""
    counts = rule_precision(examples)
    print(f"{'rule':5} {'hits':>7} {'precision':>9}  points")
    for rule in rules:
        if rule["id"] not in counts:
            continue
        hits, true_hits = counts[rule["id"]]
        change = f"{rule['points']} -> {new_points[rule['id']]}" if rule["id"] in new_points else f"{rule['points']}"
        print(f"{rule['id']:5} {hits:>7} {true_hits / hits:>9.2f}  {change}")


def write_weights(new_points, path=WEIGHTS_PATH):
    """Save the tuned points to rule_weights.json, which rules.load_rules() reads."""
    with open(path, "w") as f:
        json.dump(new_points, f, indent=2)


def main():
    """Tune the rules from the feedback stored by the web app."""
    examples = feedback_examples()
    rules = load_rules(weights_path=None)  # always start from rules.yaml
    new_points = tuned_weights(examples, rules)
    print(f"{len(examples)} feedback clicks.")
    print_report(examples, rules, new_points)
    write_weights(new_points)
    print(f"Wrote {len(new_points)} tuned rule(s) to rule_weights.json.")


if __name__ == "__main__":
    main()
