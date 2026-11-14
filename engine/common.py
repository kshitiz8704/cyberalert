"""Shared helpers: config loading, entropy, and sending alerts to the backend."""
import json, math, os, socket, time
from collections import Counter
import requests

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json")))
HOST = socket.gethostname()
_last_sent = {}          # (type, source) -> time, used to avoid alert floods
COOLDOWN = 30            # seconds


def path(p):
    """Resolve a config path relative to the engine folder."""
    return p if os.path.isabs(p) else os.path.join(BASE, p)


def entropy(data: bytes) -> float:
    """Shannon entropy (0-8). Packed/encrypted files are usually > 7."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def send_alert(category, type_, severity, source, details=""):
    key = (type_, str(source))
    now = time.time()
    if now - _last_sent.get(key, 0) < COOLDOWN:
        return
    _last_sent[key] = now
    print(f"[ALERT][{severity:<8}] {category:<8} {type_} | {source} | {details}")
    payload = dict(category=category, type=type_, severity=severity,
                   source=str(source), host=HOST, details=details)
    try:
        requests.post(CFG["backend_url"] + "/alerts", json=payload,
                      headers={"x-api-key": CFG["api_key"]}, timeout=5)
    except requests.RequestException as e:
        print("[!] Could not reach backend:", e)
