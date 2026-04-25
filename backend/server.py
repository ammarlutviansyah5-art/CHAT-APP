#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import queue
import secrets
import sqlite3
import smtplib
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from email.message import EmailMessage
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "chatapp.sqlite3"
UPLOADS = ROOT / "uploads"
DEV_OTP_LOG = ROOT / "data" / "dev_otp_log.txt"
SECRET = os.environ.get("CHATAPP_SECRET", "chatapp-dev-secret-change-me")
TOKEN_DAYS = int(os.environ.get("CHATAPP_TOKEN_DAYS", "30"))
OTP_MINUTES = int(os.environ.get("CHATAPP_OTP_MINUTES", "10"))
PRESENCE_STALE_SECONDS = int(os.environ.get("CHATAPP_PRESENCE_STALE_SECONDS", "45"))
PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@chatapp.local")

UPLOAD_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".txt", ".doc", ".docx", ".zip"}

EVENT_LOCK = threading.Lock()
EVENT_QUEUES: dict[str, list[queue.Queue]] = defaultdict(list)


def now_ts() -> int:
    return int(time.time())


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fmt_hm(ts: int | float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%H:%M")


def fmt_seen(ts: int | float | None) -> str:
    if not ts:
        return ""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
    return dt.strftime("terakhir terlihat %d/%m %H:%M")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def sign_token(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    body = b64url(raw)
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{b64url(sig)}"


def verify_token(token: str) -> dict | None:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(b64url(expected), sig):
            return None
        payload = json.loads(b64url_dec(body))
        if int(payload.get("exp", 0)) < now_ts():
            return None
        return payload
    except Exception:
        return None


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return b64url(salt), b64url(digest)


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = b64url_dec(salt_b64)
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, hash_b64)


def random_phone() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(6))


def random_token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(24)


def json_response(handler: BaseHTTPRequestHandler, payload: dict, status: int = 200, extra_headers: list[tuple[str, str]] | None = None):
    data = json.dumps(payload, ensure_ascii=False).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    for k, v in extra_headers or []:
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(data)


def text_response(handler: BaseHTTPRequestHandler, text: str, status: int = 200, content_type: str = "text/plain; charset=utf-8"):
    data = text.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(data)


def read_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    ctype = (handler.headers.get("Content-Type") or "").lower()
    if "application/json" in ctype:
        return json.loads(raw.decode() or "{}")
    if "application/x-www-form-urlencoded" in ctype:
        return {k: v[0] if len(v)==1 else v for k, v in parse_qs(raw.decode(), keep_blank_values=True).items()}
    if "multipart/form-data" in ctype:
        # This server accepts uploads through JSON base64/URL payloads in the bundled frontend.
        return {}
    try:
        return json.loads(raw.decode() or "{}")
    except Exception:
        return parse_qs(raw.decode(), keep_blank_values=True)


import io

class DB:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.init()

    def init(self):
        with self.lock:
            c = self.conn.cursor()
            c.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              email TEXT UNIQUE NOT NULL,
              password_salt TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              name TEXT NOT NULL,
              bio TEXT DEFAULT '',
              phone TEXT UNIQUE NOT NULL,
              avatar TEXT DEFAULT '',
              theme TEXT DEFAULT 'dark',
              online INTEGER DEFAULT 0,
              last_seen INTEGER DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS otp_codes (
              id TEXT PRIMARY KEY,
              email TEXT NOT NULL,
              code TEXT NOT NULL,
              purpose TEXT NOT NULL,
              payload TEXT DEFAULT '{}',
              expires_at INTEGER NOT NULL,
              verified INTEGER DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contacts (
              user_id TEXT NOT NULL,
              contact_user_id TEXT NOT NULL,
              blocked INTEGER DEFAULT 0,
              created_at INTEGER NOT NULL,
              PRIMARY KEY(user_id, contact_user_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
              id TEXT PRIMARY KEY,
              sender_id TEXT NOT NULL,
              receiver_id TEXT NOT NULL,
              thread_key TEXT NOT NULL,
              type TEXT NOT NULL,
              content TEXT DEFAULT '',
              media_url TEXT DEFAULT '',
              caption TEXT DEFAULT '',
              duration TEXT DEFAULT '',
              name TEXT DEFAULT '',
              size TEXT DEFAULT '',
              status TEXT DEFAULT 'sent',
              created_at INTEGER NOT NULL,
              delivered_at INTEGER DEFAULT 0,
              read_at INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS statuses (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              type TEXT NOT NULL,
              media_url TEXT DEFAULT '',
              caption TEXT DEFAULT '',
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocks (
              user_id TEXT NOT NULL,
              blocked_user_id TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              PRIMARY KEY(user_id, blocked_user_id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              from_user_id TEXT,
              type TEXT NOT NULL,
              text TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              read_at INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_messages_thread_created ON messages(thread_key, created_at);
            CREATE INDEX IF NOT EXISTS idx_statuses_user_created ON statuses(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_otp_email_purpose ON otp_codes(email, purpose, created_at);
            """)
            self.conn.commit()
            self.seed()

    def seed(self):
        demo = [
            ("demo1@example.com", "Demo Satu", "Rina Dewi", "Hai! 😊", "112233"),
            ("demo2@example.com", "Demo Dua", "Budi Santoso", "Sibuk kerja 💼", "223344"),
            ("demo3@example.com", "Demo Tiga", "Citra Lestari", "Suka jalan-jalan ✈️", "334455"),
            ("demo4@example.com", "Demo Empat", "Dani Pranata", "Gamer 🎮", "445566"),
            ("demo5@example.com", "Demo Lima", "Elsa Fitriani", "Coffee addict ☕", "556677"),
        ]
        with self.lock:
            for email, pw, name, bio, phone in demo:
                row = self.conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                if row:
                    continue
                uid = "u_" + secrets.token_hex(8)
                salt, h = hash_password(pw)
                self.conn.execute("INSERT INTO users(id,email,password_salt,password_hash,name,bio,phone,created_at,last_seen,online,theme) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (uid, email, salt, h, name, bio, phone, now_ts(), now_ts(), 1, "dark"))
            self.conn.commit()
            users = [dict(r) for r in self.conn.execute("SELECT id FROM users").fetchall()]
            ids = [r["id"] for r in users]
            me = self.conn.execute("SELECT id FROM users WHERE email='demo1@example.com'").fetchone()[0]
            for uid in ids:
                for cid in ids:
                    if uid == cid:
                        continue
                    self.conn.execute("INSERT OR IGNORE INTO contacts(user_id, contact_user_id, blocked, created_at) VALUES(?,?,0,?)", (uid, cid, now_ts()))
            self.conn.commit()
            # seed a few sample messages/statuses only once
            cnt = self.conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            if cnt == 0:
                others = [x for x in ids if x != me]
                if others:
                    rina = others[0]
                    self.add_message(me, rina, "text", content="Hai! Apa kabar?", status="read", created_at=now_ts()-3600)
                    self.add_message(rina, me, "text", content="Baik, kamu?", status="read", created_at=now_ts()-3550)
                    self.add_message(me, rina, "text", content="Lagi upgrade chat app.", status="delivered", created_at=now_ts()-3500)
                    self.conn.execute("INSERT OR IGNORE INTO statuses(id,user_id,type,media_url,caption,created_at) VALUES(?,?,?,?,?,?)", ("st_"+secrets.token_hex(8), rina, "photo", "/uploads/demo-status.jpg", "Liburan singkat", now_ts()-7200))
                    self.conn.commit()

    def fetch_user(self, *, user_id: str | None = None, email: str | None = None):
        with self.lock:
            if user_id:
                row = self.conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            else:
                row = self.conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            return dict(row) if row else None

    def fetch_session(self, token: str):
        with self.lock:
            row = self.conn.execute("SELECT * FROM sessions WHERE token=? AND expires_at>?", (token, now_ts())).fetchone()
            return dict(row) if row else None

    def create_session(self, user_id: str):
        token = sign_token({"uid": user_id, "exp": now_ts() + TOKEN_DAYS * 86400, "iat": now_ts()})
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)", (token, user_id, now_ts() + TOKEN_DAYS * 86400, now_ts()))
            self.conn.commit()
        return token

    def delete_session(self, token: str):
        with self.lock:
            self.conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            self.conn.commit()

    def set_user_online(self, user_id: str, online: bool):
        with self.lock:
            self.conn.execute("UPDATE users SET online=?, last_seen=? WHERE id=?", (1 if online else 0, now_ts(), user_id))
            self.conn.commit()
        self.emit("presence", {"userId": user_id, "online": online, "lastSeen": now_ts()})

    def touch_user(self, user_id: str):
        with self.lock:
            self.conn.execute("UPDATE users SET last_seen=?, online=1 WHERE id=?", (now_ts(), user_id))
            self.conn.commit()

    def otp_create(self, email: str, purpose: str, payload: dict | None = None) -> str:
        code = f"{secrets.randbelow(1000000):06d}"
        with self.lock:
            self.conn.execute(
                "INSERT INTO otp_codes(id,email,code,purpose,payload,expires_at,verified,created_at) VALUES(?,?,?,?,?,?,0,?)",
                ("otp_" + secrets.token_hex(8), email, code, purpose, json.dumps(payload or {}), now_ts() + OTP_MINUTES * 60, now_ts()),
            )
            self.conn.commit()
        return code

    def otp_verify(self, email: str, purpose: str, code: str):
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM otp_codes WHERE email=? AND purpose=? AND code=? AND verified=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1",
                (email, purpose, code, now_ts()),
            ).fetchone()
            if not row:
                return None
            self.conn.execute("UPDATE otp_codes SET verified=1 WHERE id=?", (row["id"],))
            self.conn.commit()
            return dict(row)

    def ensure_contact_rows(self, user_id: str):
        with self.lock:
            others = self.conn.execute("SELECT id FROM users WHERE id<>?", (user_id,)).fetchall()
            for r in others:
                self.conn.execute("INSERT OR IGNORE INTO contacts(user_id, contact_user_id, blocked, created_at) VALUES(?,?,0,?)", (user_id, r[0], now_ts()))
            self.conn.commit()

    def get_contacts(self, user_id: str):
        with self.lock:
            rows = self.conn.execute(
                "SELECT u.*, c.blocked AS contact_blocked FROM contacts c JOIN users u ON u.id = c.contact_user_id WHERE c.user_id=? ORDER BY u.name COLLATE NOCASE",
                (user_id,),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["blocked"] = bool(d.get("contact_blocked"))
                d["online"] = bool(d.get("online")) and (now_ts() - int(d.get("last_seen") or 0) < PRESENCE_STALE_SECONDS)
                result.append(self.user_public(d))
            return result

    def user_public(self, u: dict):
        if not u:
            return None
        name = u.get("name") or "User"
        return {
            "id": u["id"],
            "email": u.get("email", ""),
            "name": name,
            "bio": u.get("bio", ""),
            "phone": u.get("phone", ""),
            "avatar": u.get("avatar", ""),
            "avatarLetter": (name[:1] or "U").upper(),
            "theme": u.get("theme", "dark"),
            "online": bool(u.get("online")) and (now_ts() - int(u.get("last_seen") or 0) < PRESENCE_STALE_SECONDS),
            "lastSeen": int(u.get("last_seen") or 0),
            "lastSeenText": fmt_seen(u.get("last_seen")),
        }

    def thread_key(self, a: str, b: str) -> str:
        return "|".join(sorted([a, b]))

    def thread_partner(self, thread_key: str, user_id: str) -> str:
        a, b = thread_key.split("|", 1)
        return b if a == user_id else a

    def get_messages(self, user_id: str, contact_id: str):
        tk = self.thread_key(user_id, contact_id)
        rows = self.conn.execute("SELECT * FROM messages WHERE thread_key=? ORDER BY created_at ASC", (tk,)).fetchall()
        return [self.message_public(dict(r), user_id) for r in rows]

    def message_public(self, m: dict, viewer_id: str):
        out = m["sender_id"] == viewer_id
        return {
            "id": m["id"],
            "from": "me" if out else m["sender_id"],
            "type": m["type"],
            "content": m.get("content", ""),
            "src": m.get("media_url", ""),
            "caption": m.get("caption", ""),
            "duration": m.get("duration", ""),
            "name": m.get("name", ""),
            "size": m.get("size", ""),
            "time": fmt_hm(m["created_at"]),
            "status": m.get("status", "sent") if out else "read",
            "createdAt": m["created_at"],
            "deliveredAt": m.get("delivered_at", 0),
            "readAt": m.get("read_at", 0),
        }

    def add_message(self, sender_id: str, receiver_id: str, type_: str, *, content="", media_url="", caption="", duration="", name="", size="", status="sent", created_at=None):
        created_at = created_at or now_ts()
        msg_id = "m_" + secrets.token_hex(10)
        tk = self.thread_key(sender_id, receiver_id)
        with self.lock:
            self.conn.execute(
                "INSERT INTO messages(id,sender_id,receiver_id,thread_key,type,content,media_url,caption,duration,name,size,status,created_at,delivered_at,read_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (msg_id, sender_id, receiver_id, tk, type_, content, media_url, caption, duration, name, size, status, created_at, created_at if status in ("delivered","read") else 0, created_at if status == "read" else 0),
            )
            self.conn.execute("UPDATE users SET last_seen=? WHERE id IN (?,?)", (now_ts(), sender_id, receiver_id))
            self.conn.commit()
        return dict(self.conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone())

    def block_user(self, user_id: str, blocked_user_id: str, blocked: bool = True):
        with self.lock:
            if blocked:
                self.conn.execute("INSERT OR REPLACE INTO blocks(user_id,blocked_user_id,created_at) VALUES(?,?,?)", (user_id, blocked_user_id, now_ts()))
                self.conn.execute("INSERT OR REPLACE INTO contacts(user_id,contact_user_id,blocked,created_at) VALUES(?,?,1,?)", (user_id, blocked_user_id, now_ts()))
            else:
                self.conn.execute("DELETE FROM blocks WHERE user_id=? AND blocked_user_id=?", (user_id, blocked_user_id))
                self.conn.execute("INSERT OR REPLACE INTO contacts(user_id,contact_user_id,blocked,created_at) VALUES(?,?,0,?)", (user_id, blocked_user_id, now_ts()))
            self.conn.commit()
        self.emit("profile_update", {"userId": user_id, "blockedUserId": blocked_user_id, "blocked": blocked})

    def is_blocked(self, sender_id: str, receiver_id: str) -> bool:
        with self.lock:
            row = self.conn.execute("SELECT 1 FROM blocks WHERE user_id=? AND blocked_user_id=?", (receiver_id, sender_id)).fetchone()
            return bool(row)

    def get_profile(self, user_id: str):
        row = self.fetch_user(user_id=user_id)
        return self.user_public(row) if row else None

    def update_profile(self, user_id: str, *, name=None, bio=None, avatar=None, theme=None):
        parts, vals = [], []
        if name is not None:
            parts.append("name=?"); vals.append(name)
        if bio is not None:
            parts.append("bio=?"); vals.append(bio)
        if avatar is not None:
            parts.append("avatar=?"); vals.append(avatar)
        if theme is not None:
            parts.append("theme=?"); vals.append(theme)
        if not parts:
            return self.fetch_user(user_id=user_id)
        vals.append(user_id)
        with self.lock:
            self.conn.execute(f"UPDATE users SET {', '.join(parts)} WHERE id=?", vals)
            self.conn.commit()
        updated = self.fetch_user(user_id=user_id)
        self.emit("profile_update", {"userId": user_id, "profile": self.user_public(updated)})
        return updated

    def get_statuses(self, user_id: str):
        rows = self.conn.execute(
            "SELECT s.*, u.name, u.bio, u.phone, u.avatar, u.online, u.last_seen FROM statuses s JOIN users u ON u.id=s.user_id WHERE s.user_id IN (SELECT contact_user_id FROM contacts WHERE user_id=?) OR s.user_id=? ORDER BY s.created_at DESC LIMIT 50",
            (user_id, user_id),
        ).fetchall()
        return [self.status_public(dict(r), viewer_id=user_id) for r in rows]

    def status_public(self, s: dict, viewer_id: str):
        user_row = self.fetch_user(user_id=s["user_id"]) or {}
        user = self.user_public(user_row | {"id": s["user_id"], "name": s.get("name") or user_row.get("name", "User"), "bio": s.get("bio") or user_row.get("bio", ""), "phone": s.get("phone") or user_row.get("phone", ""), "avatar": s.get("avatar") or user_row.get("avatar", ""), "online": s.get("online", user_row.get("online", 0)), "last_seen": s.get("last_seen", user_row.get("last_seen", 0))})
        return {
            "id": s["id"],
            "userId": s["user_id"],
            "user": user,
            "type": s["type"],
            "src": s.get("media_url", ""),
            "caption": s.get("caption", ""),
            "time": fmt_hm(s["created_at"]),
            "createdAt": s["created_at"],
        }

    def add_status(self, user_id: str, type_: str, media_url: str, caption: str):
        sid = "st_" + secrets.token_hex(10)
        with self.lock:
            self.conn.execute("INSERT INTO statuses(id,user_id,type,media_url,caption,created_at) VALUES(?,?,?,?,?,?)", (sid, user_id, type_, media_url, caption, now_ts()))
            self.conn.commit()
        status = self.conn.execute("SELECT * FROM statuses WHERE id=?", (sid,)).fetchone()
        self.emit("status", {"status": self.status_public(dict(status), viewer_id=user_id)})
        return dict(status)

    def add_notification(self, user_id: str, from_user_id: str | None, type_: str, text: str):
        nid = "nt_" + secrets.token_hex(8)
        with self.lock:
            self.conn.execute("INSERT INTO notifications(id,user_id,from_user_id,type,text,created_at,read_at) VALUES(?,?,?,?,?,?,0)", (nid, user_id, from_user_id, type_, text, now_ts()))
            self.conn.commit()
        n = {"id": nid, "userId": user_id, "fromUserId": from_user_id, "type": type_, "text": text, "ts": now_ts()}
        self.emit("notification", n, user_id)
        return n

    def mark_read(self, user_id: str, contact_id: str):
        tk = self.thread_key(user_id, contact_id)
        with self.lock:
            self.conn.execute("UPDATE messages SET status='read', read_at=? WHERE thread_key=? AND receiver_id=?", (now_ts(), tk, user_id))
            self.conn.commit()
        self.emit("message_update", {"contactId": contact_id, "status": "read"}, user_id)

    def mark_delivered(self, msg_id: str):
        with self.lock:
            self.conn.execute("UPDATE messages SET status='delivered', delivered_at=? WHERE id=? AND status='sent'", (now_ts(), msg_id))
            self.conn.commit()

    def inbox_summary(self, user_id: str):
        contacts = self.get_contacts(user_id)
        chats = {}
        for c in contacts:
            tk = self.thread_key(user_id, c["id"])
            row = self.conn.execute("SELECT * FROM messages WHERE thread_key=? ORDER BY created_at DESC LIMIT 1", (tk,)).fetchone()
            unread = self.conn.execute("SELECT COUNT(*) FROM messages WHERE thread_key=? AND receiver_id=? AND read_at=0", (tk, user_id)).fetchone()[0]
            chats[c["id"]] = {
                "unread": unread,
                "lastMsg": self.last_msg_text(dict(row)) if row else "",
                "lastTime": fmt_hm(row["created_at"]) if row else "",
                "messages": self.get_messages(user_id, c["id"]),
            }
        return chats

    def last_msg_text(self, m: dict):
        if not m:
            return ""
        if m["type"] == "text": return m.get("content", "")
        if m["type"] == "image": return "📷 Foto"
        if m["type"] == "video": return "🎬 Video"
        if m["type"] == "audio": return "🎙️ Pesan suara"
        if m["type"] == "document": return "📎 Dokumen"
        return m.get("type", "")

    def bootstrap(self, user_id: str):
        me = self.get_profile(user_id)
        contacts = self.get_contacts(user_id)
        statuses = self.get_statuses(user_id)
        chats = self.inbox_summary(user_id)
        return {"me": me, "contacts": contacts, "statuses": statuses, "chats": chats}

    def emit(self, event_type: str, payload: dict, user_id: str | None = None):
        data = json.dumps({"type": event_type, "payload": payload}, ensure_ascii=False)
        with EVENT_LOCK:
            if user_id:
                for q in EVENT_QUEUES.get(user_id, []):
                    try: q.put_nowait(data)
                    except Exception: pass
            else:
                for qs in EVENT_QUEUES.values():
                    for q in qs:
                        try: q.put_nowait(data)
                        except Exception: pass


db = DB(DB_PATH)


def auth_from_request(handler: BaseHTTPRequestHandler):
    auth = handler.headers.get("Authorization", "")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        cookie = SimpleCookie(handler.headers.get("Cookie", ""))
        if "chatapp_token" in cookie:
            token = cookie["chatapp_token"].value
    if not token:
        return None, None
    session = db.fetch_session(token)
    if not session:
        return None, None
    payload = verify_token(token)
    if not payload:
        return None, None
    user = db.fetch_user(user_id=session["user_id"])
    if not user:
        return None, None
    return token, db.user_public(user)


def auth_cookie_header(token: str | None):
    if token:
        return ("Set-Cookie", f"chatapp_token={token}; HttpOnly; Path=/; Max-Age={TOKEN_DAYS * 86400}")
    return ("Set-Cookie", "chatapp_token=; HttpOnly; Path=/; Max-Age=0")


def send_otp_email(email: str, code: str, purpose: str):
    subject_map = {"signup": "Kode OTP pendaftaran", "login": "Kode OTP login", "reset": "Kode OTP reset password"}
    subject = subject_map.get(purpose, "Kode OTP ChatApp")
    body = (
        f"Kode OTP kamu: {code}\n\n"
        f"Jangan sebar kode ini pada siapapun.\n"
        f"Kode ini berlaku {OTP_MINUTES} menit.\n"
    )
    if SMTP_HOST and SMTP_USER:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls()
            if SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        DEV_OTP_LOG.parent.mkdir(parents=True, exist_ok=True)
        with DEV_OTP_LOG.open("a", encoding="utf-8") as f:
            f.write(f"{iso_now()} | {email} | {purpose} | {code}\n")


def save_upload(field, subdir: str = "misc") -> str:
    UPLOADS.mkdir(parents=True, exist_ok=True)
    original = getattr(field, "filename", None) or "file.bin"
    ext = Path(original).suffix.lower()
    if ext not in UPLOAD_EXT:
        ext = mimetypes.guess_extension(getattr(field, "type", "")) or ".bin"
    name = f"{subdir}_{secrets.token_hex(12)}{ext}"
    dst = UPLOADS / name
    data = field.file.read() if hasattr(field, "file") else field
    if isinstance(data, str):
        data = data.encode()
    dst.write_bytes(data)
    return f"/uploads/{name}"


def parse_json_or_form(handler: BaseHTTPRequestHandler):
    length = int(handler.headers.get("Content-Length", "0") or 0)
    ctype = (handler.headers.get("Content-Type") or "").lower()
    if length == 0:
        return {}
    if "multipart/form-data" in ctype:
        return {}
    raw = handler.rfile.read(length)
    if "application/json" in ctype:
        return json.loads(raw.decode() or "{}")
    return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(raw.decode(), keep_blank_values=True).items()}


class Handler(BaseHTTPRequestHandler):
    server_version = "ChatAppBackend/1.0"

    def log_message(self, fmt, *args):
        return

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/auth/me":
            _, user = auth_from_request(self)
            if not user:
                return json_response(self, {"ok": False, "authenticated": False}, 401)
            db.touch_user(user["id"])
            return json_response(self, {"ok": True, "authenticated": True, "user": user})
        token, user = auth_from_request(self)
        if path == "/api/bootstrap":
            if not user:
                return json_response(self, {"ok": False, "error": "unauthorized"}, 401)
            db.touch_user(user["id"])
            return json_response(self, {"ok": True, **db.bootstrap(user["id"]), "user": user})
        if path == "/api/status":
            if not user:
                return json_response(self, {"ok": False, "error": "unauthorized"}, 401)
            return json_response(self, {"ok": True, "items": db.get_statuses(user["id"])})
        if path == "/api/events":
            if not user:
                return json_response(self, {"ok": False, "error": "unauthorized"}, 401)
            return self.handle_sse(user["id"])
        if path == "/api/messages":
            if not user:
                return json_response(self, {"ok": False, "error": "unauthorized"}, 401)
            qs = parse_qs(parsed.query)
            contact_id = (qs.get("chatId") or qs.get("contactId") or [""])[0]
            if not contact_id:
                return json_response(self, {"ok": False, "error": "chatId required"}, 400)
            return json_response(self, {"ok": True, "messages": db.get_messages(user["id"], contact_id)})
        if path == "/api/profile":
            if not user:
                return json_response(self, {"ok": False, "error": "unauthorized"}, 401)
            return json_response(self, {"ok": True, "profile": db.get_profile(user["id"])})
        if path.startswith("/uploads/"):
            return self.serve_upload(path)
        if path == "/":
            return self.serve_index()
        # static frontend files
        rel = path.lstrip("/")
        local = ROOT.parent / rel if rel.startswith("frontend/") else (ROOT.parent / rel)
        if local.is_file():
            return self.serve_file(local)
        return self.serve_index()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/auth/"):
            return self.handle_auth(path)
        token, user = auth_from_request(self)
        if not user:
            return json_response(self, {"ok": False, "error": "unauthorized"}, 401)
        db.touch_user(user["id"])
        if path == "/api/messages/text":
            data = parse_json_or_form(self)
            chat_id = data.get("chatId")
            text = (data.get("text") or "").strip()
            if not chat_id or not text:
                return json_response(self, {"ok": False, "error": "invalid payload"}, 400)
            if db.is_blocked(user["id"], chat_id):
                return json_response(self, {"ok": False, "error": "blocked", "status": "blocked"}, 403)
            status = "delivered" if db.fetch_user(user_id=chat_id).get("online") else "sent"
            msg = db.add_message(user["id"], chat_id, "text", content=text, status=status)
            db.add_notification(chat_id, user["id"], "message", f"Pesan baru dari {user['name']}")
            db.emit("message", {"chatId": chat_id, "message": db.message_public(msg, user["id"])}, chat_id)
            if status == "delivered":
                db.emit("message_update", {"chatId": chat_id, "messageId": msg["id"], "status": "delivered"}, user["id"])
            return json_response(self, {"ok": True, "message": db.message_public(msg, user["id"])})
        if path == "/api/messages/media":
            data = parse_json_or_form(self)
            chat_id = data.get("chatId")
            type_ = data.get("type") or "image"
            media_url = data.get("mediaUrl") or data.get("src") or ""
            caption = data.get("caption") or ""
            if not chat_id:
                return json_response(self, {"ok": False, "error": "invalid payload"}, 400)
            if db.is_blocked(user["id"], chat_id):
                return json_response(self, {"ok": False, "error": "blocked"}, 403)
            msg = db.add_message(user["id"], chat_id, type_, media_url=media_url, caption=caption, name=data.get("name", ""), size=data.get("size", ""), duration=data.get("duration", ""), status="delivered")
            db.add_notification(chat_id, user["id"], "message", f"Media baru dari {user['name']}")
            db.emit("message", {"chatId": chat_id, "message": db.message_public(msg, user["id"])}, chat_id)
            return json_response(self, {"ok": True, "message": db.message_public(msg, user["id"])})
        if path == "/api/messages/audio":
            data = parse_json_or_form(self)
            chat_id = data.get("chatId")
            media_url = data.get("mediaUrl") or ""
            duration = data.get("duration") or "0:00"
            if not chat_id:
                return json_response(self, {"ok": False, "error": "invalid payload"}, 400)
            msg = db.add_message(user["id"], chat_id, "audio", media_url=media_url, duration=duration, status="delivered")
            db.add_notification(chat_id, user["id"], "message", f"Pesan suara dari {user['name']}")
            db.emit("message", {"chatId": chat_id, "message": db.message_public(msg, user["id"])}, chat_id)
            return json_response(self, {"ok": True, "message": db.message_public(msg, user["id"])})
        if path == "/api/messages/read":
            data = parse_json_or_form(self)
            chat_id = data.get("chatId")
            if chat_id:
                db.mark_read(user["id"], chat_id)
            return json_response(self, {"ok": True})
        if path == "/api/status/photo":
            data = parse_json_or_form(self)
            media = data.get("mediaUrl") or data.get("src") or data.get("file")
            media_url = media if isinstance(media, str) else ""
            if hasattr(media, "file"):
                media_url = save_upload(media, "status")
            caption = data.get("caption") or ""
            status = db.add_status(user["id"], "photo", media_url, caption)
            db.emit("status", {"status": db.status_public(status, user["id"])}, None)
            return json_response(self, {"ok": True, "status": db.status_public(status, user["id"])})
        if path == "/api/status/video":
            data = parse_json_or_form(self)
            media = data.get("mediaUrl") or data.get("src") or data.get("file")
            media_url = media if isinstance(media, str) else ""
            if hasattr(media, "file"):
                media_url = save_upload(media, "status")
            caption = data.get("caption") or ""
            status = db.add_status(user["id"], "video", media_url, caption)
            db.emit("status", {"status": db.status_public(status, user["id"])}, None)
            return json_response(self, {"ok": True, "status": db.status_public(status, user["id"])})
        if path == "/api/profile":
            data = parse_json_or_form(self)
            avatar = data.get("avatar")
            if hasattr(avatar, "file"):
                avatar = save_upload(avatar, "avatar")
            updated = db.update_profile(user["id"], name=data.get("name"), bio=data.get("bio"), avatar=avatar, theme=data.get("theme"))
            return json_response(self, {"ok": True, "profile": db.user_public(updated)})
        if path == "/api/block":
            data = parse_json_or_form(self)
            target = data.get("userId")
            if not target:
                return json_response(self, {"ok": False, "error": "userId required"}, 400)
            db.block_user(user["id"], target, bool(data.get("blocked", True)))
            return json_response(self, {"ok": True})
        if path == "/api/report":
            data = parse_json_or_form(self)
            target = data.get("userId")
            db.add_notification(user["id"], target, "report", f"Laporan dikirim untuk {target}")
            return json_response(self, {"ok": True})
        if path == "/api/presence":
            data = parse_json_or_form(self)
            db.set_user_online(user["id"], bool(data.get("online", True)))
            return json_response(self, {"ok": True})
        if path == "/api/calls/start":
            data = parse_json_or_form(self)
            target = data.get("userId")
            db.emit("call_offer", {"from": user["id"], "to": target, "kind": data.get("kind", "voice")}, target)
            return json_response(self, {"ok": True})
        return json_response(self, {"ok": False, "error": "not found"}, 404)

    def do_PUT(self):
        return self.do_POST()

    def handle_auth(self, path: str):
        data = parse_json_or_form(self)
        if path == "/api/auth/request-signup-otp":
            email = (data.get("email") or "").strip().lower()
            password = data.get("password") or ""
            name = (data.get("name") or "").strip() or email.split("@")[0]
            if not email or not password:
                return json_response(self, {"ok": False, "error": "email/password required"}, 400)
            if db.fetch_user(email=email):
                return json_response(self, {"ok": False, "error": "Email sudah terdaftar"}, 409)
            code = db.otp_create(email, "signup", {"password": password, "name": name})
            send_otp_email(email, code, "signup")
            return json_response(self, {"ok": True, "message": "OTP signup dikirim"})
        if path == "/api/auth/verify-signup-otp":
            email = (data.get("email") or "").strip().lower()
            code = (data.get("code") or "").strip()
            row = db.otp_verify(email, "signup", code)
            if not row:
                return json_response(self, {"ok": False, "error": "OTP tidak valid"}, 400)
            payload = json.loads(row["payload"] or "{}")
            if db.fetch_user(email=email):
                return json_response(self, {"ok": False, "error": "Email sudah terdaftar"}, 409)
            uid = "u_" + secrets.token_hex(8)
            salt, h = hash_password(payload.get("password") or "")
            phone = random_phone()
            with db.lock:
                db.conn.execute("INSERT INTO users(id,email,password_salt,password_hash,name,bio,phone,created_at,last_seen,online,theme) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (uid, email, salt, h, payload.get("name") or email.split("@")[0], "", phone, now_ts(), now_ts(), 1, "dark"))
                db.conn.commit()
            db.ensure_contact_rows(uid)
            token = db.create_session(uid)
            user = db.user_public(db.fetch_user(user_id=uid))
            db.emit("presence", {"userId": uid, "online": True, "lastSeen": now_ts()}, None)
            return json_response(self, {"ok": True, "token": token, "user": user}, extra_headers=[auth_cookie_header(token)])
        if path == "/api/auth/request-login-otp":
            email = (data.get("email") or "").strip().lower()
            password = data.get("password") or ""
            user = db.fetch_user(email=email)
            if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
                return json_response(self, {"ok": False, "error": "Email atau password salah"}, 401)
            code = db.otp_create(email, "login", {"userId": user["id"]})
            send_otp_email(email, code, "login")
            return json_response(self, {"ok": True, "message": "OTP login dikirim"})
        if path == "/api/auth/verify-login-otp":
            email = (data.get("email") or "").strip().lower()
            code = (data.get("code") or "").strip()
            row = db.otp_verify(email, "login", code)
            user = db.fetch_user(email=email)
            if not row or not user:
                return json_response(self, {"ok": False, "error": "OTP tidak valid"}, 400)
            token = db.create_session(user["id"])
            db.set_user_online(user["id"], True)
            return json_response(self, {"ok": True, "token": token, "user": db.user_public(user)}, extra_headers=[auth_cookie_header(token)])
        if path == "/api/auth/request-reset-otp":
            email = (data.get("email") or "").strip().lower()
            user = db.fetch_user(email=email)
            if not user:
                return json_response(self, {"ok": True})
            code = db.otp_create(email, "reset", {})
            send_otp_email(email, code, "reset")
            return json_response(self, {"ok": True, "message": "OTP reset dikirim"})
        if path == "/api/auth/reset-password":
            email = (data.get("email") or "").strip().lower()
            code = (data.get("code") or "").strip()
            new_password = data.get("newPassword") or ""
            row = db.otp_verify(email, "reset", code)
            if not row or not new_password:
                return json_response(self, {"ok": False, "error": "OTP tidak valid"}, 400)
            salt, h = hash_password(new_password)
            with db.lock:
                db.conn.execute("UPDATE users SET password_salt=?, password_hash=? WHERE email=?", (salt, h, email))
                db.conn.commit()
            return json_response(self, {"ok": True})
        if path == "/api/auth/logout":
            token, user = auth_from_request(self)
            if token and user:
                db.delete_session(token)
                db.set_user_online(user["id"], False)
            return json_response(self, {"ok": True}, extra_headers=[auth_cookie_header(None)])
        return json_response(self, {"ok": False, "error": "not found"}, 404)

    def handle_sse(self, user_id: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        q: queue.Queue = queue.Queue()
        with EVENT_LOCK:
            EVENT_QUEUES[user_id].append(q)
        try:
            self.wfile.write(b":ok\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = q.get(timeout=15)
                    payload = f"event: message\ndata: {event}\n\n".encode()
                except queue.Empty:
                    payload = b":ping\n\n"
                self.wfile.write(payload)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            with EVENT_LOCK:
                try:
                    EVENT_QUEUES[user_id].remove(q)
                except ValueError:
                    pass

    def serve_index(self):
        fp = ROOT.parent / "frontend" / "index.html"
        if not fp.exists():
            fp = ROOT.parent / "frontend" / "index.raw.html"
        return self.serve_file(fp)

    def serve_file(self, fp: Path):
        if not fp.exists():
            return text_response(self, "Not found", 404)
        data = fp.read_bytes()
        ctype, _ = mimetypes.guess_type(str(fp))
        ctype = ctype or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") or ctype in ("application/javascript", "application/json") else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def serve_upload(self, path: str):
        fp = UPLOADS / Path(path).name
        if not fp.exists():
            return text_response(self, "Not found", 404)
        return self.serve_file(fp)


def presence_reaper():
    while True:
        try:
            time.sleep(10)
            cutoff = now_ts() - PRESENCE_STALE_SECONDS
            with db.lock:
                rows = db.conn.execute("SELECT id,last_seen,online FROM users WHERE online=1").fetchall()
                for r in rows:
                    if int(r["last_seen"] or 0) < cutoff:
                        db.conn.execute("UPDATE users SET online=0 WHERE id=?", (r["id"],))
                        db.conn.commit()
                        db.emit("presence", {"userId": r["id"], "online": False, "lastSeen": int(r["last_seen"] or 0)}, None)
        except Exception:
            pass


def main():
    UPLOADS.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=presence_reaper, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ChatApp backend running on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
