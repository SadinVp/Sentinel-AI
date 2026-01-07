# security/sqli_waf.py
import os
import csv
from datetime import datetime
from urllib.parse import unquote

from flask import request, abort
import joblib

os.makedirs("data", exist_ok=True)

SQLI_QUARANTINE_THRESHOLD = 0.35
SQLI_BLOCK_THRESHOLD = 0.70

sqli_model = joblib.load("models/sqli_model.joblib")
sqli_vectorizer = joblib.load("models/sqli_vectorizer.joblib")


def log_sqli_quarantine(payload, score):
    file_path = "data/sqli_quarantine.csv"
    file_exists = os.path.exists(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["timestamp", "context", "payload", "score"])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "REQUEST_PARAM",
            payload,
            round(score, 4)
        ])


def sqli_waf_middleware(SAFE_PATHS):
    """Call from @app.before_request in app.py"""
    if any(request.path.startswith(p) for p in SAFE_PATHS):
        return

    for _, value in {**request.args, **request.form}.items():
        decoded_value = unquote(value).lower().strip()
        if not decoded_value:
            continue

        vec = sqli_vectorizer.transform([decoded_value])
        probability = sqli_model.predict_proba(vec)[0][1]

        print("SQLI SCORE:", probability, "| PAYLOAD:", decoded_value)

        if probability >= SQLI_QUARANTINE_THRESHOLD:
            log_sqli_quarantine(decoded_value, probability)

        if probability >= SQLI_BLOCK_THRESHOLD:
            abort(403, description="SQL Injection detected")

    return None
