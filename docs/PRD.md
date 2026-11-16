Threat-Shield PRD
Nov 17, 2026 
A one-day version: a small web app that scores a URL or an email as benign, suspicious or malicious, shows its reasons, and learns from feedback. About five hours to build with Claude Code, three to prepare for the interview.
What you are building today
Threat-Shield is a local web app: paste a URL or an email, get a verdict, a score from 0 to 100, and the list of reasons. It combines hand-written rules with a small machine-learning model, logs every check, and uses right/wrong feedback to tune the rules.
That is enough to make both résumé bullets true and to explain every line in an interview. It is a learning project, not production software, and you should say so.
In today
Cut (mention as "what I would add next")
URL analysis from the text of the URL only
Visiting the page in a sandbox
Email analysis: headers, wording, links, attachment names
Opening or scanning attachments
14 rules, each mapped to a MITRE ATT&CK technique
Threat-intelligence feed lookups
One model: logistic regression on URL features
Email text model, deep learning
Hybrid score with reasons
Docker, job queue, PostgreSQL
Feedback buttons and a rule-tuning script
Automatic retraining
History page with a repeat-domain alert
Mailbox monitoring, campaign clustering
Evaluation script that prints real metrics
Time-based split, evasion testing
One safety rule: the app never opens, fetches or clicks a submitted URL. It only reads the text. This keeps you safe and is a good design point to raise in the interview.
How it works
Every input goes through the same five steps, and this picture is the one to draw on a whiteboard if asked to explain the design.

Threat-Shield flow · input, two detectors, scorer, feedback
The app pulls features out of the text, the rules and the model each judge them, the scorer averages the two into a verdict, and feedback lowers the points of rules that keep being wrong.
#
Feature
What the user sees
1
URL check
Paste a link; get verdict, score, reasons, response time
2
Email check
Paste an email with headers; get the same, plus a verdict per link
3
Reasons
One sentence per fired rule with its ATT&CK id, plus the model's probability
4
Feedback
"Right" and "wrong" buttons on every result
5
History and alert
A table of past checks; a banner when one domain is flagged three times
6
Evaluation
A command that prints the metrics table used on the résumé
Detection logic
Rules catch known tricks and give readable reasons; the model catches URLs that merely look like past phishing; the score averages the two.
URL features (computed from the string, no network): length, number of dots, hyphens and digits, subdomain depth, whether the host is an IP address, @ present, xn-- (punycode) present, HTTPS or not, count of words like login, verify, secure, account, update, and whether a brand name appears anywhere other than the registered domain.
Rules. Kept in one file, rules.yaml, each with an id, points, a reason sentence and an ATT&CK id.
Id
Fires when
Points
ATT&CK
R01
Host is a raw IP address
30
T1566.002
R02
URL contains @ (text before it is ignored by browsers)
25
T1566.002
R03
Punycode host (xn--), possible lookalike letters
25
T1036
R04
Brand name in subdomain or path, but not the registered domain
35
T1036
R05
Four or more subdomain levels
15
T1566.002
R06
Login or verify wording plus hyphens in the domain
20
T1566.002
R07
Known URL shortener
10
T1566.002
R08
No HTTPS
5
T1566.002
R09
From domain differs from Reply-To domain
30
T1566
R10
Display name names a brand, sender domain is not that brand
35
T1036
R11
SPF, DKIM or DMARC shows fail in the Authentication-Results header
30
T1566
R12
Urgency or threat wording ("account suspended", "within 24 hours")
15
T1566
R13
Link text shows one domain, the link goes to another
35
T1566.002
R14
Attachment name is risky: .html, .js, .exe, .iso, or a double extension
25
T1566.001
Look up each ATT&CK id on attack.mitre.org once before the interview so you can say what it means. T1566 is Phishing; .001 is attachment, .002 is link; T1036 is Masquerading.
Model. Logistic regression (scikit-learn) trained on the URL features from a public labelled phishing-URL dataset. It outputs a probability from 0 to 1. Logistic regression is the right choice today because you can explain it: each feature gets a weight, and you can print the weights.
Score
	•	rule_score = sum of points from fired rules, capped at 100.
	•	ml_score = model probability × 100. For an email, use the highest probability among its links.
	•	score = 0.5 × rule_score + 0.5 × ml_score.
	•	Below 40 is benign, 40 to 69 is suspicious, 70 and above is malicious. Pick the two cut-offs by trying a few values on the validation data.
Feedback loop
	•	Each result has two buttons: "verdict was right" and "verdict was wrong". The click is saved with the rules that fired.
	•	tune.py reads the saved feedback and computes, for each rule, how often it fired on something that was truly malicious (its precision).
	•	A rule with at least 5 hits and precision under 50% has its points halved. The new points are written to rule_weights.json, which the rule engine loads.
	•	To measure the effect today, evaluate.py replays the validation data as if it were analyst feedback, runs the tuning, and counts false positives on the test data before and after.
Stack and files
Plain Python with four libraries and a flat folder, so you can open any file and say what it does.
Stack: Python 3.11 or newer, FastAPI with one HTML page, SQLite (built into Python), scikit-learn, PyYAML, tldextract, pytest. Run with uvicorn app:app --reload. No Docker, no accounts.
File
What it does
features.py
Turns a URL string into a dictionary of features
email_parser.py
Reads pasted email text: From, Reply-To, Authentication-Results, body, links, attachment names
rules.yaml
The 14 rules as data
rules.py
Loads the rules and returns which ones fired, with reasons
model.py
train() fits and saves the model; predict(url) returns a probability
scorer.py
Combines rule points and model probability into score, verdict and reasons
db.py
SQLite tables: analyses (every check) and feedback
app.py
Web routes: home page, analyse URL, analyse email, feedback, history
templates/index.html
The one page: two input boxes, the result card, the history table
tune.py
Reads feedback, halves the points of noisy rules, writes rule_weights.json
evaluate.py
Prints precision, recall, false-positive rate for rules-only, model-only and hybrid, and the before/after tuning count
tests/
A few tests per module with made-up URLs and emails
data/
The dataset CSV (not committed)
Dataset. You need one CSV of URLs labelled phishing or legitimate. Search Kaggle or the UCI Machine Learning Repository for "phishing URL dataset" and pick one that has the raw URL and a label column. I have not checked a specific dataset today, so confirm which label value means phishing before training. Split it 70% train, 15% validation, 15% test.
Tasks for Claude Code
Seven tasks, one at a time, in this order. Save this doc as docs/PRD.md and put the new CLAUDE.md in the project folder first.
Read CLAUDE.md and docs/PRD.md. Do task T<n> only. Keep the code simple and comment the non-obvious parts. Run the tests, fix failures, then explain in plain words what each new function does.
Task
Build
Done when
T1
Project setup, requirements.txt, features.py with tests
Tests pass; a sample URL prints its feature dictionary
T2
rules.yaml, rules.py, email_parser.py with tests
A made-up phishing email fires R09, R12 and R13; a normal one fires nothing
T3
model.py and evaluate.py: split the data, train, print metrics for rules-only, model-only, hybrid
python evaluate.py prints a three-row metrics table
T4
scorer.py, db.py, app.py, templates/index.html
Paste a URL in the browser, see verdict, score, reasons and response time; it appears in history
T5
Email box on the page, feedback buttons, repeat-domain alert on the history page
Paste an email, get a verdict; click feedback and see it stored
T6
tune.py and the before/after false-positive count in evaluate.py
python evaluate.py prints false positives before and after tuning
T7
README: what it is, how to run, the metrics table, limitations, screenshot
Someone else could run it from the README
The last line of the prompt matters most: make Claude Code explain each function, and ask follow-ups until you could re-explain it without looking.
Today's schedule
About five hours of building and three of preparation, with a break between. Times are elapsed hours from when you start.
Elapsed
Do
Output
0:00–0:20
Create the folder, add CLAUDE.md and docs/PRD.md, download the dataset
Ready to build
0:20–1:00
T1
URL features
1:00–1:45
T2
Rules and email parsing
1:45–2:30
T3
Trained model and first metrics
2:30–3:30
T4
Working web page
3:30–4:15
T5
Email input, feedback, history
4:15–4:45
T6
Before/after false-positive numbers
4:45–5:15
T7, push to GitHub, update the résumé numbers
Finished project
Break
Eat, rest

+1 hour
Open each file and explain it aloud; run five URLs and two emails and explain each verdict
You can demo it
+1 hour
Answer the questions in "Interview prep" aloud, then in writing for the weak ones
Answers ready
+1 hour
Revise the concepts list and general security basics
Fundamentals fresh
If you fall behind, drop T5's repeat-domain alert first, then T6's tuning (keep the rules-only vs hybrid comparison). Do not drop the explain-it-aloud hour.
Numbers for the résumé
Use the numbers evaluate.py prints on the test data, whatever they are, so you can show the command that produced them.
Résumé claim
Where it comes from
"real-time"
The response time shown on the result page, in milliseconds
Detection figure
Precision and recall of the hybrid on the test split
"reduced false positives by X%"
False positives of rules-only vs hybrid after tuning, same test split
"event monitoring"
The history log and the repeat-domain alert
"feedback loops"
The feedback buttons and tune.py
Bullets to fill in
	•	Built a phishing-detection web app that analyses URLs and emails using 14 ATT&CK-mapped rules and a logistic-regression model, reaching [P]% precision and [R]% recall on a held-out test set of [N] URLs.
	•	Designed a hybrid rule-plus-ML score with a feedback loop that down-weights noisy rules, cutting false positives by [X]% compared with rules alone.
If the measured figures differ from 92% and 35%, change the résumé. An interviewer who asks "how did you get 92%?" is satisfied by a real number with a method and put off by a number you cannot reproduce.
Interview prep
You will be judged less on the app than on whether you understand why each part exists and where it fails.
The 60-second pitch. "Threat-Shield takes a URL or an email and returns a verdict with reasons. It has two detectors. Rules check for known phishing tricks, like a reply-to address that differs from the sender or a brand name in a subdomain. A logistic-regression model scores how much the URL resembles past phishing. I average the two, because rules alone raised too many false alarms and a model alone cannot explain itself. Analysts can mark a verdict wrong, and a script lowers the weight of rules that keep misfiring. On my test set it reached [P]% precision and [R]% recall. It only reads text and never visits the link, which is a safety choice and also its main limitation."
Likely questions
Question
Points to make
Why both rules and ML?
Rules are precise and explainable but miss new tricks; the model generalises but cannot say why. Together: fewer false alarms and readable reasons
Why not report accuracy?
Phishing is rare in real traffic. A detector that always says "benign" has high accuracy and catches nothing. Precision and recall show the real trade-off
What is a false positive, and why does it matter?
A legitimate item flagged as phishing. Too many and analysts stop trusting alerts
How would an attacker get past this?
A clean-looking new domain, a compromised legitimate site, a link shortener, text inside an image, a QR code. Text-only analysis cannot see the page
How would you improve it?
Visit the page in an isolated sandbox, add threat-intelligence lookups, check domain age, test on newer data than it was trained on
Why logistic regression?
Small, fast, and each feature's weight can be inspected. Have two or three top weights ready to quote
What are SPF, DKIM and DMARC?
See the concepts table
How does the feedback loop work?
Feedback is stored with the rules that fired; a script computes each rule's precision and halves the points of poor ones
What are the limits of your evaluation?
Public dataset, random split, so real-world performance would be lower; feedback was simulated with labelled data
Why never fetch the URL?
Visiting can expose your machine and IP and can tell the attacker the address is live. Safe fetching needs a sandbox
Concepts to be able to define in two sentences
Concept
Short definition
SPF
A DNS record listing which servers may send mail for a domain
DKIM
A cryptographic signature on the message, checked with a public key published in the domain's DNS
DMARC
A domain's policy that the visible From address must match a passing SPF or DKIM check, and what receivers should do if it does not
Registered domain
The part someone actually bought, such as example.com in login.example.com. Phishers put brand names in the subdomain instead
Punycode and homoglyphs
Encoding that lets lookalike characters from other alphabets appear in domain names
Precision and recall
Of everything flagged, how much was truly bad; of everything truly bad, how much was flagged
MITRE ATT&CK
A public catalogue of attacker techniques; phishing is T1566 under Initial Access
Indicator of compromise
A concrete trace of an attack, such as a domain, URL, IP address or file hash
Spear phishing vs phishing
Targeted at a specific person or organisation vs sent in bulk
General preparation for a security research intern interview. Be ready to walk through how you would investigate a suspicious email step by step, to describe one recent phishing technique you read about, and to say what you want to learn. When you do not know something, say how you would find out. Honest limits plus a clear next step reads as research thinking.
