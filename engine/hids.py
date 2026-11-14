"""Module B - Host-based IDS: file integrity, failed logins, suspicious processes."""
import hashlib, os, re, time
from collections import defaultdict, deque
import psutil
from common import CFG, path, send_alert

SENSITIVE = {".conf", ".ini", ".php", ".py", ".sh", ".exe", ".dll", ".env", ".config"}
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
FAIL_RE = re.compile(r"failed (password|login)|authentication failure|invalid user", re.I)


def snapshot(dirs):
    snap = {}
    for d in dirs:
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    snap[fp] = hashlib.sha256(open(fp, "rb").read()).hexdigest()
                except OSError:
                    pass
    return snap


def check_files(dirs, baseline):
    now = snapshot(dirs)
    for fp, h in now.items():
        ext = os.path.splitext(fp)[1].lower()
        if fp not in baseline:
            send_alert("Host", "New File Created", "Low", fp, "A new file appeared in a watched directory")
        elif baseline[fp] != h:
            send_alert("Host", "File Modified", "High" if ext in SENSITIVE else "Medium", fp, "File content hash changed")
    for fp in baseline:
        if fp not in now:
            send_alert("Host", "File Deleted", "High", fp, "Watched file was deleted")
    return now


class LoginMonitor:
    """Tails a log file and counts failed logins per IP inside a sliding window."""
    def __init__(self, logfile, threshold, window):
        self.file, self.th, self.win = logfile, threshold, window
        self.pos = os.path.getsize(logfile) if os.path.exists(logfile) else 0
        self.fails = defaultdict(deque)

    def check(self):
        if not os.path.exists(self.file):
            return
        size = os.path.getsize(self.file)
        if size < self.pos:
            self.pos = 0                                  # log rotated
        with open(self.file, errors="ignore") as f:
            f.seek(self.pos)
            lines = f.readlines()
            self.pos = f.tell()
        now = time.time()
        for line in lines:
            if FAIL_RE.search(line):
                m = IP_RE.search(line)
                self.fails[m.group(1) if m else "local"].append(now)
        for ip, dq in self.fails.items():
            while dq and now - dq[0] > self.win:
                dq.popleft()
            if len(dq) >= self.th:
                sev = "Critical" if len(dq) >= 2 * self.th else "High"
                send_alert("Host", "Brute Force Login", sev, ip, f"{len(dq)} failed logins in {self.win}s")


def check_processes(bad, seen):
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid, name, exe = p.info["pid"], (p.info["name"] or "").lower(), (p.info["exe"] or "").lower()
        except psutil.Error:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        base = name.rsplit(".", 1)[0]
        if base in bad:
            send_alert("Host", "Suspicious Process", "High", name, f"Blacklisted process running (pid {pid})")
        elif any(x in exe for x in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp")) and exe.endswith((".exe", ".sh", ".bin")):
            send_alert("Host", "Process From Temp Dir", "Medium", name, f"Executable running from temp folder: {exe}")


def run():
    cfg = CFG["hids"]
    dirs = [path(d) for d in cfg["watch_dirs"]]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    logfile = path(cfg["auth_log"])
    if not os.path.exists(logfile):
        open(logfile, "w").close()
    baseline = snapshot(dirs)
    login = LoginMonitor(logfile, cfg["failed_login_threshold"], cfg["failed_login_window"])
    seen = {p.pid for p in psutil.process_iter()}         # ignore processes already running at start
    print("[hids] watching", dirs, "| log:", logfile)
    while True:
        baseline = check_files(dirs, baseline)
        login.check()
        check_processes(set(cfg["bad_processes"]), seen)
        time.sleep(cfg["interval"])
