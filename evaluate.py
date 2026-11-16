"""Split the dataset, train the model, and print metrics for rules-only, model-only and hybrid.

Method:
  * 70 / 15 / 15 train / validation / test split, stratified, fixed seed.
  * The model is trained on train only.
  * Every threshold is chosen on validation only.
  * All reported numbers are on test, which is never used to choose anything.
We report precision, recall, F1 and false-positive rate, not accuracy:
phishing is rare in real traffic, so "always benign" would score high accuracy.
"""

import csv
import json
import os

from sklearn.model_selection import train_test_split

import model
from rules import load_rules, run_rules, url_context
from scorer import combine, rule_score
from tune import print_report, tuned_weights

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "data", "phishing_urls.csv")
THRESHOLDS_PATH = os.path.join(HERE, "thresholds.json")
SEED = 42
CANDIDATES = list(range(5, 100, 5))  # thresholds tried on validation


def load_dataset(path=DATA_PATH):
    """Read the CSV and return (urls, labels) with label 1 = phishing."""
    urls, labels = [], []
    with open(path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            urls.append(row["URL"])
            # In the PhiUSIIL dataset label "1" means legitimate and "0" means
            # phishing, so we flip it: in our code 1 always means phishing.
            labels.append(1 if row["label"] == "0" else 0)
    return urls, labels


def split_dataset(urls, labels):
    """Split into 70% train, 15% validation, 15% test, keeping the phishing ratio in each."""
    u_train, u_rest, y_train, y_rest = train_test_split(
        urls, labels, test_size=0.30, stratify=labels, random_state=SEED)
    u_val, u_test, y_val, y_test = train_test_split(
        u_rest, y_rest, test_size=0.50, stratify=y_rest, random_state=SEED)
    return (u_train, y_train), (u_val, y_val), (u_test, y_test)


def score_all(contexts, rules):
    """Return (rule_scores, ml_scores, hybrid_scores) for URL contexts, each 0 to 100."""
    # Uses the same formulas as the web app (scorer.py), so the numbers match.
    r_scores = [rule_score(run_rules(c, "url", rules)) for c in contexts]
    m_scores = [p * 100 for p in model.predict_features([c["features"] for c in contexts])]
    h_scores = [combine(r, m) for r, m in zip(r_scores, m_scores)]
    return r_scores, m_scores, h_scores


def metrics(labels, scores, threshold):
    """Return precision, recall, F1, false-positive rate and counts when flagging score >= threshold."""
    tp = fp = fn = tn = 0
    for y, s in zip(labels, scores):
        flagged = s >= threshold
        if flagged and y == 1:
            tp += 1
        elif flagged and y == 0:
            fp += 1   # a legitimate URL wrongly flagged
        elif not flagged and y == 1:
            fn += 1   # a phishing URL we missed
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def best_threshold(labels, scores):
    """Try each candidate threshold and return the one with the highest F1."""
    best, best_f1 = CANDIDATES[0], -1.0
    for t in CANDIDATES:
        f1 = metrics(labels, scores, t)["f1"]
        if f1 > best_f1:
            best, best_f1 = t, f1
    return best


def malicious_threshold(labels, scores, low, min_precision=0.95):
    """Return the lowest threshold above `low` whose precision reaches min_precision."""
    # "Malicious" should mean "very likely phishing", so it needs high precision.
    for t in CANDIDATES:
        if t > low and metrics(labels, scores, t)["precision"] >= min_precision:
            return t
    return 70  # the PRD's default if no candidate reaches the target


def print_table(rows):
    """Print a metrics table, one row per detector."""
    print(f"{'detector':12} {'threshold':>9} {'precision':>9} {'recall':>7} "
          f"{'F1':>6} {'FP rate':>8} {'FP':>6} {'FN':>6}")
    for name, t, m in rows:
        print(f"{name:12} {t:>9} {m['precision']:>9.3f} {m['recall']:>7.3f} "
              f"{m['f1']:>6.3f} {m['fpr']:>8.3f} {m['fp']:>6} {m['fn']:>6}")


def evaluate_detectors(val_ctx, val_labels, test_ctx, test_labels, rules, names):
    """Pick each detector's threshold on validation and return (name, threshold, test metrics) rows."""
    detectors = {"rules-only": 0, "model-only": 1, "hybrid": 2}
    val_scores = score_all(val_ctx, rules)
    test_scores = score_all(test_ctx, rules)
    rows = []
    for name in names:
        i = detectors[name]
        t = best_threshold(val_labels, val_scores[i])
        rows.append((name, t, metrics(test_labels, test_scores[i], t)))
    return rows


def with_points(rules, new_points):
    """Return a copy of the rules with some points replaced."""
    copied = []
    for rule in rules:
        rule = dict(rule)
        if rule["id"] in new_points:
            rule["points"] = new_points[rule["id"]]
        copied.append(rule)
    return copied


def percent_change(before, after):
    """Return the change from before to after as a percentage of before."""
    if before == 0:
        return 0.0
    return (after - before) / before * 100


def tuning_report(val_ctx, val_labels, test_ctx, test_labels, rules, rows_before):
    """Replay validation as analyst feedback, tune the rules, and print FP counts before and after."""
    # Each validation URL acts as one feedback click: these rules fired, and
    # this was the true label. Tuning sees validation only; we count on test.
    examples = []
    for ctx, label in zip(val_ctx, val_labels):
        fired = [rule["id"] for rule in run_rules(ctx, "url", rules)]
        examples.append((fired, label == 1))
    new_points = tuned_weights(examples, rules)

    print("\nRule tuning, using validation labels as simulated feedback:")
    print_report(examples, rules, new_points)
    rows_after = evaluate_detectors(val_ctx, val_labels, test_ctx, test_labels,
                                    with_points(rules, new_points), ["rules-only", "hybrid"])

    print("\nAfter tuning (thresholds re-chosen on validation):")
    print_table(rows_after)

    before = {name: m for name, _, m in rows_before}
    after = {name: m for name, _, m in rows_after}
    rules_fp = before["rules-only"]["fp"]
    print("\nFalse positives on test:")
    for name in ["rules-only", "hybrid"]:
        print(f"  {name}, before tuning: {before[name]['fp']}   after tuning: {after[name]['fp']}   "
              f"({percent_change(before[name]['fp'], after[name]['fp']):+.1f}%)")
    print(f"  hybrid after tuning vs rules-only before: {after['hybrid']['fp']} vs {rules_fp}")


def main():
    """Run the whole evaluation and print the results."""
    urls, labels = load_dataset()
    train, val, test = split_dataset(urls, labels)
    print(f"Dataset: {len(urls)} URLs, {sum(labels)} phishing. "
          f"Split: train {len(train[0])}, validation {len(val[0])}, test {len(test[0])}.")

    print("Training logistic regression on the train split...")
    model.train([url_context(u)["features"] for u in train[0]], train[1])

    # Original points from rules.yaml, ignoring any rule_weights.json the app made.
    rules = load_rules(weights_path=None)
    val_ctx = [url_context(u) for u in val[0]]
    test_ctx = [url_context(u) for u in test[0]]
    rows = evaluate_detectors(val_ctx, val[1], test_ctx, test[1], rules,
                              ["rules-only", "model-only", "hybrid"])

    print(f"\nTest set ({len(test[0])} URLs). Thresholds chosen on validation.")
    print_table(rows)

    tuning_report(val_ctx, val[1], test_ctx, test[1], rules, rows)

    # Verdict cut-offs for the app: suspicious = hybrid's best-F1 threshold,
    # malicious = a stricter, high-precision threshold. Saved for scorer.py.
    suspicious = rows[2][1]
    malicious = malicious_threshold(val[1], score_all(val_ctx, rules)[2], suspicious)
    with open(THRESHOLDS_PATH, "w") as f:
        json.dump({"suspicious": suspicious, "malicious": malicious}, f, indent=2)
    print(f"\nVerdict cut-offs saved to thresholds.json: "
          f"suspicious >= {suspicious}, malicious >= {malicious}")

    print("\nModel weights (positive = pushes towards phishing):")
    model.print_weights()


if __name__ == "__main__":
    main()
