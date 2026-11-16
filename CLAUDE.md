# Threat-Shield (one-day build)

A small local web app. Paste a URL or an email; get a verdict (benign /
suspicious / malicious), a score from 0 to 100, and the reasons. Rules plus a
logistic-regression model, with a feedback loop that tunes the rules.

The specification is `docs/PRD.md`. Read it first. Do exactly one task
(T1 to T7) per request and stop.

## Priorities, in order

1. Simple enough that a student can explain every function in an interview.
2. Working end to end.
3. Nothing else. No extra features, abstractions, or dependencies.

## Stack (do not add to it)

- Python 3.11+, flat folder of modules, no package structure
- FastAPI + one Jinja HTML page (`templates/index.html`), plain HTML and CSS
- SQLite through the standard `sqlite3` module
- scikit-learn (logistic regression), joblib, PyYAML, tldextract
- pytest
- Run: `uvicorn app:app --reload`. Test: `pytest`. Metrics: `python evaluate.py`

No Docker, no Redis, no ORM, no JavaScript framework, no LLM calls.

## Files

`features.py`, `email_parser.py`, `rules.yaml`, `rules.py`, `model.py`,
`scorer.py`, `db.py`, `app.py`, `templates/index.html`, `tune.py`,
`evaluate.py`, `tests/`. Purposes are in the PRD under "Stack and files".

## Code style

- Short functions with a one-line docstring saying what they do in plain words.
- Comment the security reasoning: why a rule exists, what trick it catches.
- Prefer a clear `if` over a clever one-liner. No classes unless needed.
- Rules live in `rules.yaml` as data: id, points, reason, attack. Do not
  hard-code rule logic into the scorer.
- After finishing a task, explain each new function in two or three plain sentences.

## Safety rules (never break these)

- NEVER fetch, open, resolve or visit a submitted URL. No `requests`, `httpx`,
  `urllib.request`, DNS lookups or browser automation on user input. All
  analysis is on the text only.
- Never open or execute attachments; look at file names only.
- Show URLs and domains defanged in the page (`hxxp://`, `example[.]com`).
- Escape all user input in the HTML page; never render email HTML.
- Tests use made-up samples on reserved domains (`example.com`, `.test`). No
  real phishing URLs or real people's emails in the repo.
- `data/` and `*.joblib` are git-ignored.

## Evaluation

- Split the dataset 70 / 15 / 15 (train / validation / test), stratified, fixed seed.
- Print precision, recall, F1 and false-positive rate for rules-only,
  model-only and hybrid. Do not present accuracy as the headline.
- Choose thresholds and tune rule weights on validation only; report on test.
- Print the false-positive count before and after rule tuning.

## Out of scope today

Sandboxed page fetching, threat-intel lookups, domain-age checks, retraining
jobs, mailbox monitoring, user accounts, deployment.
