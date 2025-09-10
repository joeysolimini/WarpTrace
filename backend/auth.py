import os, time, hashlib
import jwt
from flask import request, jsonify
from functools import wraps

SECRET_KEY = os.getenv("SECRET_KEY", "devsecret")
DEMO_USERNAME = os.getenv("DEMO_USERNAME", "admin")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "changeme")

def create_token(username: str):
    payload = {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + 60*60*12}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = auth.split(" ",1)[1]
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except Exception:
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper

def login_handler():
    data = request.get_json() or {}
    u = data.get("username","")
    p = data.get("password","")
    if u == DEMO_USERNAME and p == DEMO_PASSWORD:
        return jsonify({"token": create_token(u)})
    return jsonify({"error": "invalid credentials"}), 401
