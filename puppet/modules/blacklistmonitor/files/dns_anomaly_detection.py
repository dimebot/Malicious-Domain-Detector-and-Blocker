#!/usr/bin/env python3
"""
dns_vt_only.py

DNS anomaly detector that ONLY queries VirusTotal for each observed domain.
If VirusTotal marks a domain 'malicious' or 'suspicious', the domain is added
to the dnsmasq blacklist (addn-hosts style file), and dnsmasq is reloaded.

Features:
 - Persistent VT verdict cache (survives restarts)
 - Simple rate limiting to conserve API quota
 - Whitelist support
 - Atomic writes to blacklist file
"""

import re
import time
import argparse
import os
import tempfile
import shutil
import subprocess
import json
import logging
from collections import defaultdict
import requests

# ---------------- Config defaults ----------------
DEFAULT_LOG_FILE = "/var/log/dnsmasq.log"
DEFAULT_BLACKLIST = "/etc/dnsmasq-blacklist"
DETECT_LOG = "/var/log/dns_anomaly_detector.log"
DEFAULT_VT_CACHE = "/var/lib/dns_vt_cache.json"   # needs dir writable by root

# --------- HARDCODE YOUR VIRUSTOTAL API KEY HERE ----------
VT_API_KEY = "{api-key}"
# ---------------------------------------------------------

QUERY_RE = re.compile(r'query\[(?:[A-Z0-9_]+)\]\s+([^\s;]+)')
# Minimum delay between VT requests (seconds) to throttle requests
DEFAULT_MIN_VT_DELAY = 15.0  # e.g., ~4 requests/minute (adjust for your quota)


# ------------------ Helpers -----------------------
def atomic_write_lines(path, lines):
    dirn = os.path.dirname(path)
    os.makedirs(dirn, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=dirn)
    try:
        with os.fdopen(tmp_fd, "w") as tf:
            tf.write("\n".join(lines).strip() + ("\n" if lines else ""))
        # Preserve permissions if file exists
        if os.path.exists(path):
            st = os.stat(path)
            os.chown(tmp_path, st.st_uid, st.st_gid)
            os.chmod(tmp_path, st.st_mode)
        else:
            os.chmod(tmp_path, 0o644)
        shutil.move(tmp_path, path)
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

def reload_dnsmasq():
    blacklist_path = "/etc/dnsmasq-blacklist"

    try:
        subprocess.run(
            ["systemctl", "reload", "dnsmasq"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        subprocess.run(
            ["systemctl", "restart", "dnsmasq"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )




def read_blacklist(path):
    try:
        with open(path, "r") as f:
            lines = [ln.rstrip() for ln in f if ln.rstrip() and not ln.rstrip().startswith("#")]
            return lines
    except FileNotFoundError:
        return []


# ------------------ VT Cache persistence ----------------
def load_cache(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(path, cache):
    dirn = os.path.dirname(path)
    os.makedirs(dirn, exist_ok=True)
    tmp = None
    with tempfile.NamedTemporaryFile("w", delete=False, dir=dirn) as tf:
        json.dump(cache, tf)
        tmp = tf.name
    shutil.move(tmp, path)


# ------------------ VirusTotal lookup ----------------
def vt_check(domain, api_key, cache, min_delay, last_request_ts):
    """
    Return (verdict_bool, last_request_ts).
    verdict_bool: True if VT marks domain malicious or suspicious.
    cache: dict mapping domain-> { "verdict": bool, "time": epoch }
    min_delay: seconds to wait between VT requests
    last_request_ts: epoch time of last request (or 0)
    """
    domain = domain.lower().rstrip(".")
    if domain in cache:
        return bool(cache[domain].get("verdict")), last_request_ts

    # rate limit
    now = time.time()
    elapsed = now - last_request_ts
    if elapsed < min_delay:
        to_wait = min_delay - elapsed
        logging.debug("Throttling VT requests: sleeping %.2fs", to_wait)
        time.sleep(to_wait)
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    verdict = False
    try:
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            verdict = (malicious + suspicious) > 0
            logging.info("VT: %s => malicious=%d suspicious=%d (verdict=%s)",
                         domain, malicious, suspicious, verdict)
        else:
            logging.warning("VT HTTP %d for %s; treating as non-malicious for now", r.status_code, domain)
            verdict = False
    except Exception as e:
        logging.warning("VT query failed for %s: %s", domain, e)
        verdict = False

    cache[domain] = {"verdict": bool(verdict), "time": int(time.time())}
    last_request_ts = time.time()
    return bool(verdict), last_request_ts


# ------------------ Main detector ----------------
class VTOnlyDetector:
    def __init__(self, log_file, blacklist_file, vt_key, vt_cache_file, min_vt_delay=DEFAULT_MIN_VT_DELAY, whitelist=None):
        self.log_file = log_file
        self.blacklist_file = blacklist_file
        self.vt_key = vt_key
        self.cache_path = vt_cache_file
        self.min_vt_delay = float(min_vt_delay)
        self.whitelist = set(w.lower() for w in (whitelist or []))
        self.in_memory_cache = load_cache(self.cache_path)
        self.last_vt_ts = 0.0
        self.blacklisted = set([ln.split()[-1].lower() for ln in read_blacklist(self.blacklist_file)])
        logging.info("Loaded VT cache entries=%d, existing blacklisted=%d",
                     len(self.in_memory_cache), len(self.blacklisted))

    def tail_log(self):
        # tail the dnsmasq log like before
        with open(self.log_file, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                yield line

    def add_to_blacklist(self, domain):
        domain = domain.lower().rstrip(".")
        if domain in self.blacklisted:
            logging.debug("%s already blacklisted", domain)
            return False
        # read current file, append and write atomically
        existing = read_blacklist(self.blacklist_file)
        existing.append(f"0.0.0.0 {domain}")
        atomic_write_lines(self.blacklist_file, existing)
        self.blacklisted.add(domain)
        logging.info("Blacklisted domain: %s", domain)
        reload_dnsmasq()
        return True

    def run(self):
        logging.info("VT-only detector started (log=%s)", self.log_file)
        for line in self.tail_log():
            m = QUERY_RE.search(line)
            if not m:
                continue

            domain = m.group(1).lower().rstrip(".")

            # Skip obvious local/invalid stuff
            if any(x in domain for x in ("localhost", "localdomain", ".arpa")):
                continue
            if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
                continue

            if domain in self.whitelist:
                logging.debug("Whitelisted: %s", domain)
                continue
            if domain in self.blacklisted:
                logging.debug("Already blacklisted: %s", domain)
                continue

            # Query VT (cached)
            verdict, self.last_vt_ts = vt_check(domain, self.vt_key, self.in_memory_cache, self.min_vt_delay, self.last_vt_ts)
            # persist cache frequently to survive crashes (simple strategy)
            try:
                save_cache(self.cache_path, self.in_memory_cache)
            except Exception as e:
                logging.warning("Failed to persist VT cache: %s", e)

            if verdict:
                logging.info("VT marked %s malicious -> blacklisting", domain)
                self.add_to_blacklist(domain)
            else:
                logging.debug("VT marked %s clean (or unknown)", domain)


# ------------------ CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="dnsmasq VT-only detector")
    p.add_argument("--log-file", default=DEFAULT_LOG_FILE, help="dnsmasq log file to tail")
    p.add_argument("--blacklist-file", default=DEFAULT_BLACKLIST, help="dnsmasq addn-hosts file to update")
    p.add_argument("--vt-cache-file", default=DEFAULT_VT_CACHE, help="persistent VT cache (json)")
    p.add_argument("--min-vt-delay", type=float, default=DEFAULT_MIN_VT_DELAY, help="min seconds between VT requests")
    p.add_argument("--whitelist", nargs="*", default=[], help="domains to never block")
    p.add_argument("--debug", action="store_true", help="debug logging")
    return p.parse_args()


def main():
    args = parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(filename=DETECT_LOG, level=level, format="%(asctime)s %(levelname)s: %(message)s")
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logging.getLogger().addHandler(console)

    vt_key = VT_API_KEY
    if not vt_key or vt_key == "REPLACE_WITH_YOUR_VIRUSTOTAL_API_KEY":
        logging.error("VirusTotal API key not provided. Edit VT_API_KEY in the script.")
        return

    detector = VTOnlyDetector(
        log_file=args.log_file,
        blacklist_file=args.blacklist_file,
        vt_key=vt_key,
        vt_cache_file=args.vt_cache_file,
        min_vt_delay=args.min_vt_delay,
        whitelist=args.whitelist
    )

    try:
        detector.run()
    except KeyboardInterrupt:
        logging.info("Stopped by user, saving cache...")
        try:
            save_cache(detector.cache_path, detector.in_memory_cache)
        except Exception:
            pass
    except Exception as e:
        logging.exception("Detector crashed: %s", e)
        try:
            save_cache(detector.cache_path, detector.in_memory_cache)
        except Exception:
            pass


if __name__ == "__main__":
    main()
