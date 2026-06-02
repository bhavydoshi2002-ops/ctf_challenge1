"""
CTF Challenge 1 — The Invisible Admin
======================================
Vulnerability : JWT Algorithm Confusion (alg=none bypass)
Category      : Web
Difficulty    : Medium

Deploy on Railway / Render / Fly.io — no local machine needed.
"""

import os
import json
import base64
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, request, jsonify, render_template, make_response

app = Flask(__name__)

JWT_SECRET = "secret123"          # weak secret — intentional
FLAG       = "CTF{alg_n0ne_bypass_ez_clap}"


# ──────────────────────────────────────────────────────────────
#  VULNERABLE JWT DECODER
#  Accepts alg=none with no signature — this is the bug.
# ──────────────────────────────────────────────────────────────
def decode_jwt_unsafe(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode header
        header_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header     = json.loads(base64.urlsafe_b64decode(header_pad))

        # Decode payload
        payload_pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload     = json.loads(base64.urlsafe_b64decode(payload_pad))

        alg = header.get("alg", "").lower()

        if alg == "none":
            # ⚠️  BUG: no signature verification when alg=none
            return payload

        if alg == "hs256":
            return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        return None

    except Exception:
        return None


def get_token():
    """Pull token from cookie OR Authorization header."""
    token = request.cookies.get("token")
    if not token:
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
    return token or None


# ──────────────────────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────────────────────

@app.route("/")
def home():
    """
    Login page.
    Players who View Source will find the hidden comment
    pointing to /admin_debug.
    """
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or request.form
    username = (data or {}).get("username", "").strip()
    password = (data or {}).get("password", "").strip()

    # Real admin password is intentionally unreachable
    if username == "admin" and password == "y0u_w1ll_n3v3r_gu3ss_th1s_xD":
        payload = {
            "user": "admin",
            "role": "admin",
            "exp":  datetime.now(timezone.utc) + timedelta(hours=2)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        resp  = make_response(jsonify({"message": "Welcome admin!", "token": token}))
        resp.set_cookie("token", token, httponly=False)   # httponly=False so JS can read it
        return resp

    # Any other username → regular user token (not admin)
    if username:
        payload = {
            "user": username,
            "role": "user",
            "exp":  datetime.now(timezone.utc) + timedelta(hours=2)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        resp  = make_response(jsonify({
            "message": f"Logged in as {username}",
            "role":    "user",
            "token":   token,
            "note":    "You are not an admin. Admin panel is restricted."
        }))
        resp.set_cookie("token", token, httponly=False)
        return resp

    return jsonify({"error": "Username is required."}), 400


@app.route("/dashboard")
def dashboard():
    token   = get_token()
    if not token:
        return jsonify({"error": "No token. Please login first."}), 401
    payload = decode_jwt_unsafe(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token."}), 401

    return jsonify({
        "message": f"Welcome, {payload.get('user')}!",
        "role":    payload.get("role"),
        "note":    "Nothing interesting here for regular users. 🙃"
    })


@app.route("/admin_debug")
def admin_debug():
    """
    Hidden endpoint — hinted at in HTML source comment.
    Accepts JWT with alg=none (no real signature needed).
    Returns flag only if role == 'admin'.
    """
    token = get_token()
    if not token:
        return jsonify({"error": "No token provided."}), 401

    payload = decode_jwt_unsafe(token)
    if not payload:
        return jsonify({"error": "Invalid token."}), 401

    if payload.get("role") != "admin":
        return jsonify({
            "error": f"Admins only. Your role is: {payload.get('role')}",
            "hint":  "Maybe your token can be... modified? 👀"
        }), 403

    return jsonify({
        "status":  "debug_access_granted",
        "user":    payload.get("user"),
        "flag":    FLAG,
        "message": "🎉 You found the invisible admin panel!"
    })


# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=5000, debug=False)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
