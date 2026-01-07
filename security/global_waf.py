# security/global_waf.py
import os
import csv
from datetime import datetime
from urllib.parse import unquote

from flask import request, abort

import joblib

# Ensure data dir
os.makedirs("data", exist_ok=True)

QUARANTINE_THRESHOLD = 0.40
BLOCK_THRESHOLD = 0.65

# Load model and vectorizer once
global_model = joblib.load("models/global_model.joblib1")
global_vectorizer = joblib.load("models/global_vectorizer.joblib1")


def log_quarantine(request_text, score, layer):
    file_path = "data/global_quarantine.csv"
    file_exists = os.path.exists(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "layer", "request", "score"])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            layer,
            request_text,
            round(score, 4)
        ])


def extract_request_data(req):
    parts = []

    parts.append(req.method)
    parts.append(req.full_path)

    if req.query_string:
        parts.append(unquote(req.query_string.decode("utf-8", errors="ignore")))

    if req.data:
        parts.append(unquote(req.data.decode("utf-8", errors="ignore")))

    for key, value in req.headers.items():
        parts.append(f"{key}:{unquote(value)}")

    for key, value in req.cookies.items():
        parts.append(f"{key}={unquote(value)}")

    return " ".join(parts).lower()


def global_waf_middleware(SAFE_PATHS):
    """Call from @app.before_request in app.py"""
    if any(request.path.startswith(p) for p in SAFE_PATHS):
        return

    full_request = extract_request_data(request)
    vec = global_vectorizer.transform([full_request])
    probability = global_model.predict_proba(vec)[0][1]

    print("GLOBAL WAF SCORE:", probability)

    if probability >= QUARANTINE_THRESHOLD:
        log_quarantine(full_request, probability, "GLOBAL")

    if probability >= BLOCK_THRESHOLD:
        abort(403, description="Blocked by Global WAF")

    return None
