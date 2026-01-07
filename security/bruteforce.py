# security/bruteforce.py
import time
from collections import defaultdict
from flask import request, render_template

# In‑memory tracking (good for demo)
FAILED_LOGINS_IP = defaultdict(list)
FAILED_LOGINS_USER = defaultdict(list)

MAX_ATTEMPTS = 3         # allowed failures
WINDOW_SECONDS = 10 * 60  # 10 minutes window
BLOCK_SECONDS = 15 * 60   # block for 15 minutes

BLOCKED_IP = {}
BLOCKED_USER = {}


def _is_blocked(table, key):
    now = time.time()
    until = table.get(key)
    if until and now < until:
        return True
    if until and now >= until:
        del table[key]
    return False


def is_ip_blocked(ip: str) -> bool:
    return _is_blocked(BLOCKED_IP, ip)


def is_user_blocked(username: str) -> bool:
    if not username:
        return False
    return _is_blocked(BLOCKED_USER, username)


def register_failed_login(ip: str, username: str):
    """Call this from your login route when auth fails."""
    now = time.time()

    FAILED_LOGINS_IP[ip] = [t for t in FAILED_LOGINS_IP[ip] if now - t <= WINDOW_SECONDS]
    FAILED_LOGINS_USER[username] = [t for t in FAILED_LOGINS_USER[username] if now - t <= WINDOW_SECONDS]

    FAILED_LOGINS_IP[ip].append(now)
    FAILED_LOGINS_USER[username].append(now)

    if len(FAILED_LOGINS_IP[ip]) >= MAX_ATTEMPTS:
        BLOCKED_IP[ip] = now + BLOCK_SECONDS

    if len(FAILED_LOGINS_USER[username]) >= MAX_ATTEMPTS:
        BLOCKED_USER[username] = now + BLOCK_SECONDS


def bruteforce_waf(LOGIN_PATHS):
    """
    To be called from app.before_request in app.py.
    Returns a Flask response if blocked, else None.
    """
    if request.method != "POST":
        return None

    if not any(request.path.startswith(p) for p in LOGIN_PATHS):
        return None

    ip = request.remote_addr or "unknown"
    username = request.form.get("username", "").strip()

    if is_ip_blocked(ip) or is_user_blocked(username):
        return render_template(
            "bruteforce_error.html",
            msg="Too many failed login attempts. Please try again later."
        ), 429

    return None
