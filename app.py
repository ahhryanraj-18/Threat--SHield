"""Web routes: home page, analyse URL, analyse email, feedback, history.

Run with:  uvicorn app:app --reload
SAFETY: a submitted URL is only ever treated as text. It is never fetched,
and it is shown defanged (hxxp://, example[.]com) so it cannot be clicked.
"""

import os
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from scorer import score_email, score_url

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_EMAIL_CHARS = 200_000  # stops someone pasting a huge blob into the page

app = FastAPI(title="Threat-Shield")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))
db.init_db()


def defang(text):
    """Make a URL or domain unclickable: 'http://a.com' -> 'hxxp://a[.]com'."""
    text = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return text.replace(".", "[.]")


# Lets the template write {{ value | defang }}.
templates.env.filters["defang"] = defang


def render(request, result=None, error=None, message=None):
    """Render the one page with an optional result, the alerts and the history table."""
    # Jinja escapes every {{ value }} in .html templates, so pasted text such
    # as <script> is shown as text, never run. Email HTML is never rendered.
    return templates.TemplateResponse(request, "index.html", {
        "result": result,
        "error": error,
        "message": message,
        "alerts": db.repeat_domains(),
        "history": db.recent_analyses(),
    })


@app.get("/")
def home(request: Request, saved: int = 0):
    """Show the page with the history table (and a note after feedback is saved)."""
    message = "Thanks, your feedback was saved." if saved else None
    return render(request, message=message)


@app.post("/analyse/url")
def analyse_url(request: Request, url: str = Form(...)):
    """Score a pasted URL, store the check, and show the result."""
    url = url.strip()
    if not url:
        return render(request, error="Please paste a URL.")

    start = time.perf_counter()
    result = score_url(url)
    elapsed_ms = (time.perf_counter() - start) * 1000

    result["elapsed_ms"] = round(elapsed_ms, 1)
    result["id"] = db.save_analysis("url", result, elapsed_ms)
    return render(request, result=result)


@app.post("/analyse/email")
def analyse_email(request: Request, email_text: str = Form(...)):
    """Score a pasted email (headers and body), store the check, and show the result."""
    if not email_text.strip():
        return render(request, error="Please paste an email.")
    if len(email_text) > MAX_EMAIL_CHARS:
        return render(request, error="That email is too long to check here.")

    start = time.perf_counter()
    result = score_email(email_text)
    elapsed_ms = (time.perf_counter() - start) * 1000

    result["elapsed_ms"] = round(elapsed_ms, 1)
    result["id"] = db.save_analysis("email", result, elapsed_ms)
    return render(request, result=result)


@app.post("/feedback")
def feedback(analysis_id: int = Form(...), correct: int = Form(...)):
    """Save a 'verdict was right / wrong' click, then go back to the home page."""
    db.save_feedback(analysis_id, correct == 1)
    # Redirect after POST, so refreshing the page does not save the click twice.
    return RedirectResponse("/?saved=1", status_code=303)
