"""Safe attack simulator for demos. Usage: python simulate_attacks.py [malware|fim|login|portscan|dns|all]
Only touches the demo folders and (for portscan/dns) your own machine / a target you own."""
import os, socket, sys, time, random, string
BASE = os.path.dirname(os.path.abspath(__file__))
SCAN, WATCH = os.path.join(BASE, "demo/scan_folder"), os.path.join(BASE, "demo/watch_folder")
LOG = os.path.join(BASE, "demo/auth_demo.log")
for d in (SCAN, WATCH):
    os.makedirs(d, exist_ok=True)


def malware():
    open(os.path.join(SCAN, "known_bad.txt"), "w").write("CYBERALERT_KNOWN_BAD_FILE_FOR_DEMO\n")      # hash match
    open(os.path.join(SCAN, "test_marker.txt"), "w").write("hello CYBERALERT_TEST_MALWARE_SIGNATURE end")  # YARA
    open(os.path.join(SCAN, "dropper.ps1"), "w").write("powershell -enc AAAA; (New-Object Net.WebClient).DownloadString('x')")
    open(os.path.join(SCAN, "invoice.pdf.exe"), "wb").write(b"MZ" + os.urandom(4000))                   # double ext + entropy
    print("Created fake malware samples in demo/scan_folder")


def fim():
    f = os.path.join(WATCH, "config.ini")
    open(f, "w").write("setting=1\n"); time.sleep(6)
    open(f, "a").write("setting=HACKED\n"); time.sleep(6)
    os.remove(f)
    print("Created, modified and deleted demo/watch_folder/config.ini")


def login():
    with open(LOG, "a") as f:
        for i in range(12):
            f.write(f"Nov 12 10:00:{i:02d} server sshd[991]: Failed password for root from 192.168.1.50 port 22 ssh2\n")
    print("Wrote 12 failed-login lines to demo/auth_demo.log")


def portscan(target="127.0.0.1"):
    print("Scanning ports 1-40 on", target)
    for p in range(1, 41):
        s = socket.socket(); s.settimeout(0.05)
        try: s.connect((target, p))
        except OSError: pass
        s.close()


def dns():
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
    for d in (f"{rnd}.example.com", "www.evil.com"):
        try: socket.gethostbyname(d)
        except OSError: pass
    print("Sent suspicious DNS lookups")


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else "all"
    t = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    acts = {"malware": malware, "fim": fim, "login": login, "portscan": lambda: portscan(t), "dns": dns}
    for k in (acts if a == "all" else [a]):
        acts[k]()
