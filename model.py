"""Logistic-regression model on URL features.

train() fits and saves the model; predict(url) returns a phishing probability.
We use logistic regression because it is small, fast, and explainable: each
feature gets one weight, and print_weights() shows them.
"""

import os

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_NAMES, url_features

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib")

_model = None  # loaded once, on first predict()


def to_row(features):
    """Turn a feature dictionary into a list of numbers in FEATURE_NAMES order."""
    return [features[name] for name in FEATURE_NAMES]


def train(feature_dicts, labels, path=MODEL_PATH):
    """Fit the model on feature dictionaries and 0/1 labels (1 = phishing), save and return it."""
    global _model
    rows = [to_row(f) for f in feature_dicts]
    # Scaling puts every feature on the same scale, so the weights can be
    # compared with each other and the solver converges quickly.
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))
    model.fit(rows, labels)
    joblib.dump(model, path)
    _model = model
    return model


def load(path=MODEL_PATH):
    """Load the saved model from disk (once) and return it."""
    global _model
    if _model is None:
        _model = joblib.load(path)
    return _model


def predict_features(feature_dicts):
    """Return the phishing probability (0 to 1) for each feature dictionary."""
    rows = [to_row(f) for f in feature_dicts]
    return list(load().predict_proba(rows)[:, 1])


def predict(url):
    """Return the phishing probability (0 to 1) for one URL string."""
    return predict_features([url_features(url)])[0]


def print_weights():
    """Print each feature's weight, largest effect first (positive = more phishy)."""
    lr = load()[-1]
    pairs = sorted(zip(FEATURE_NAMES, lr.coef_[0]), key=lambda p: -abs(p[1]))
    for name, weight in pairs:
        print(f"  {name:22} {weight:+.2f}")
