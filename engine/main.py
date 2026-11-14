"""Starts all detection modules, each in its own thread."""
import threading, time
from common import CFG
import malware_detector, hids, nids

MODS = {"malware": malware_detector.run, "hids": hids.run, "nids": nids.run}

if __name__ == "__main__":
    print("=== CyberAlert Detection Engine ===")
    for name, fn in MODS.items():
        if CFG["modules"].get(name):
            threading.Thread(target=fn, daemon=True, name=name).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
