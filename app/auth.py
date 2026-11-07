"""Built-in DFM administrator authentication; secrets stay only in the mounted SQLite volume."""
import hashlib
import hmac
import http.cookies
import os
import re
import secrets
import sqlite3
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

COOKIE_NAME = 'dfm_session'
SESSION_SECONDS = 24 * 3600
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
_attempt_lock = threading.Lock()
_attempts = {}

class AuthError(ValueError):
    pass

def connect(db):
    c = sqlite3.connect(db, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=15000')
    return c

def initialize(db):
    c = connect(db)
    try:
        with c:
            c.execute("""CREATE TABLE IF NOT EXISTS auth_users(
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL)""")
            c.execute("""CREATE TABLE IF NOT EXISTS auth_sessions(
                token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
                csrf TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL)""")
            c.execute('CREATE INDEX IF NOT EXISTS auth_sessions_expiry ON auth_sessions(expires)')
    finally:
        c.close()

def has_admin(db):
    c = connect(db)
    try:
        return c.execute('SELECT 1 FROM auth_users LIMIT 1').fetchone() is not None
    finally:
        c.close()

def _check_credentials(username, password):
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,32}', username):
        raise AuthError('Username must be 3–32 letters, numbers, dots, underscores or hyphens')
    if not isinstance(password, str) or not (12 <= len(password) <= 1024):
        raise AuthError('Password must be between 12 and 1024 characters')

def setup(db, setup_token, username, password):
    configured = os.getenv('DFM_SETUP_TOKEN', '')
    if not configured or len(configured) < 24:
        raise AuthError('Configure DFM_SETUP_TOKEN (24+ random characters) before creating the administrator')
    if not isinstance(setup_token, str) or not hmac.compare_digest(setup_token, configured):
        raise AuthError('Invalid setup token')
    _check_credentials(username, password)
    password_hash = HASHER.hash(password)
    c = connect(db)
    try:
        with c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM auth_users LIMIT 1').fetchone():
                raise AuthError('Administrator is already configured')
            now = time.time()
            c.execute('INSERT INTO auth_users VALUES(?,?,?,?)',
                      (username, password_hash, now, now))
    finally:
        c.close()

def _rate_limited(ip):
    now = time.monotonic()
    with _attempt_lock:
        entries = [t for t in _attempts.get(ip, ()) if now-t < 900]
        _attempts[ip] = entries
        return len(entries) >= 8

def _failed_login(ip):
    now = time.monotonic()
    with _attempt_lock:
        _attempts.setdefault(ip, []).append(now)

def _successful_login(ip):
    with _attempt_lock:
        _attempts.pop(ip, None)

def login(db, username, password, ip):
    if _rate_limited(ip):
        raise AuthError('Too many login attempts. Try again in 15 minutes.')
    c = connect(db)
    try:
        row = c.execute('SELECT username,password_hash FROM auth_users WHERE username=?',
                        (username if isinstance(username, str) else '',)).fetchone()
        verified = False
        if row and isinstance(password, str):
            try:
                verified = HASHER.verify(row['password_hash'], password)
            except (VerifyMismatchError, VerificationError):
                pass
        if not verified:
            _failed_login(ip)
            raise AuthError('Invalid username or password')
        _successful_login(ip)
        return create_session(db, row['username'])
    finally:
        c.close()

def create_session(db, username):
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    now = time.time()
    c = connect(db)
    try:
        with c:
            c.execute('DELETE FROM auth_sessions WHERE expires<=?', (now,))
            c.execute('INSERT INTO auth_sessions VALUES(?,?,?,?,?)',
                      (_digest(token), username, csrf, now, now + SESSION_SECONDS))
    finally:
        c.close()
    return token, csrf

def _digest(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def get_session(db, cookie_header):
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header or '')
        token = cookie.get(COOKIE_NAME)
        raw = token.value if token else ''
    except (http.cookies.CookieError, ValueError):
        return None
    if not raw or len(raw) > 256:
        return None
    c = connect(db)
    try:
        row = c.execute('SELECT s.username,s.csrf,s.expires FROM auth_sessions s '
                        'JOIN auth_users u ON u.username=s.username '
                        'WHERE s.token_hash=? AND s.expires>?',
                        (_digest(raw), time.time())).fetchone()
        return dict(row) if row else None
    finally:
        c.close()

def revoke(db, cookie_header):
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header or '')
        token = cookie.get(COOKIE_NAME)
        raw = token.value if token else ''
    except (http.cookies.CookieError, ValueError):
        return
    if not raw:
        return
    c = connect(db)
    try:
        with c:
            c.execute('DELETE FROM auth_sessions WHERE token_hash=?', (_digest(raw),))
    finally:
        c.close()

def change_credentials(db, username, current_password, new_username, new_password):
    _check_credentials(new_username, new_password)
    c = connect(db)
    try:
        row = c.execute('SELECT password_hash FROM auth_users WHERE username=?', (username,)).fetchone()
        if not row:
            raise AuthError('Account not found')
        try:
            valid = HASHER.verify(row['password_hash'], current_password or '')
        except (VerifyMismatchError, VerificationError):
            valid = False
        if not valid:
            raise AuthError('Current password is incorrect')
        new_hash = HASHER.hash(new_password)
        with c:
            c.execute('UPDATE auth_users SET username=?,password_hash=?,updated=? WHERE username=?',
                      (new_username, new_hash, time.time(), username))
            c.execute('DELETE FROM auth_sessions')
    finally:
        c.close()

def cookie_header(token):
    cookie = f'{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}'
    if os.getenv('DFM_COOKIE_SECURE', 'true').lower() not in ('false','0','no'):
        cookie += '; Secure'
    return cookie

def clear_cookie_header():
    return f'{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure'

def metrics_authorized(header):
    expected = os.getenv('DFM_METRICS_TOKEN','')
    if len(expected) < 24 or not isinstance(header,str) or not header.startswith('Bearer '):
        return False
    return hmac.compare_digest(header[7:], expected)
