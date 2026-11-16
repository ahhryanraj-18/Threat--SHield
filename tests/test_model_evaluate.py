"""Tests for model.py and the metric helpers in evaluate.py. Made-up URLs only."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import model
from evaluate import best_threshold, metrics, split_dataset
from features import url_features


def test_train_and_predict(tmp_path):
    bad = ["http://192.0.2.1/login", "http://paypal.example.test/verify/account",
           "http://secure-login-update.example.net/a/b", "http://203.0.113.4/x"]
    good = ["https://www.example.com", "https://www.example.org",
            "https://www.example.net", "https://example.com"]
    feats = [url_features(u) for u in bad + good]
    model.train(feats, [1] * 4 + [0] * 4, path=str(tmp_path / "m.joblib"))

    p_bad = model.predict("http://198.51.100.2/login")
    p_good = model.predict("https://www.example.edu")
    assert 0.0 <= p_good < p_bad <= 1.0


def test_metrics_counts():
    labels = [1, 1, 0, 0]
    scores = [90, 10, 80, 5]
    m = metrics(labels, scores, 50)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["fpr"] == 0.5


def test_best_threshold_picks_clean_split():
    assert best_threshold([1, 1, 0, 0], [80, 60, 30, 20]) in (35, 40, 45, 50, 55, 60)


def test_split_is_70_15_15_and_stratified():
    urls = [f"https://example.com/{i}" for i in range(200)]
    labels = [1] * 40 + [0] * 160
    train, val, test = split_dataset(urls, labels)
    assert (len(train[0]), len(val[0]), len(test[0])) == (140, 30, 30)
    assert sum(test[1]) == 6  # 20% phishing kept in the test split
