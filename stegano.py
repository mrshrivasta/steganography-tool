#!/usr/bin/env python3
"""
Steganography Tool — Hide & Extract secrets in Images, Audio, Video, Binary files and Text
Author  : Karanam Shrivasta
GitHub  : https://github.com/mrshrivasta
LinkedIn: https://linkedin.com/in/karanam-shrivasta

DISCLAIMER
----------
This tool is for EDUCATIONAL and RESEARCH USE ONLY.
- Using steganography to hide illegal content is a criminal offence.
- Author accepts NO liability for misuse, data loss, or legal consequences.
- Do NOT expose this web interface outside localhost.
- Ensure you have explicit permission before analysing files you do not own.
- Not a substitute for professional security or forensic software.

Usage
-----
  pip install flask pillow numpy
  python stegano.py
  python stegano.py --port 8080 --db steg.db
"""

import os, sys, io, csv, json, wave, struct, hashlib, secrets
import sqlite3, datetime, base64, zipfile, struct, platform, argparse
import threading, textwrap
from pathlib import Path
from flask import (Flask, render_template_string, request, redirect,
                   url_for, flash, send_file, jsonify, make_response)

try:
    from PIL import Image
    import numpy as np
    PIL_OK = True
except ImportError:
    PIL_OK = False

VERSION  = "1.0.0"
AUTHOR   = "Karanam Shrivasta"
GITHUB   = "https://github.com/mrshrivasta"
LINKEDIN = "https://linkedin.com/in/karanam-shrivasta"
DB_FILE  = "stegano.db"
UPLOAD   = Path("uploads")
OUTPUT   = Path("outputs")
MAX_MB   = 50

UPLOAD.mkdir(exist_ok=True)
OUTPUT.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
# ENCRYPTION  (XOR + SHA-256 key stretching)
# ─────────────────────────────────────────────

def _key_bytes(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()   # 32 bytes

def xor_crypt(data: bytes, password: str) -> bytes:
    """Symmetric XOR cipher.  encrypt == decrypt."""
    kb = _key_bytes(password)
    return bytes(b ^ kb[i % 32] for i, b in enumerate(data))


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    op_type     TEXT    NOT NULL,
    steg_type   TEXT    NOT NULL,
    src_file    TEXT,
    out_file    TEXT,
    msg_length  INTEGER,
    encrypted   INTEGER DEFAULT 0,
    note        TEXT
);
"""

def get_db(path=DB_FILE):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn

_db_lock = threading.Lock()

def db_log(conn, op_type, steg_type, src="", out="", msg_len=0, encrypted=0, note=""):
    with _db_lock:
        conn.execute(
            "INSERT INTO operations(ts,op_type,steg_type,src_file,out_file,"
            "msg_length,encrypted,note) VALUES(?,?,?,?,?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec="seconds"),
             op_type, steg_type, src, out, msg_len, encrypted, note)
        )
        conn.commit()


# ─────────────────────────────────────────────
# CORE STEGANOGRAPHY ENGINES
# ─────────────────────────────────────────────

MAGIC = b"\xDE\xAD\xBE\xEF"   # 4-byte header magic

def _pack_payload(message: str, password: str = "") -> bytes:
    """Encode: [MAGIC 4B][encrypted_flag 1B][length 4B][data]"""
    raw = message.encode("utf-8")
    if password:
        raw = xor_crypt(raw, password)
        enc_flag = b"\x01"
    else:
        enc_flag = b"\x00"
    return MAGIC + enc_flag + len(raw).to_bytes(4, "big") + raw

def _unpack_payload(payload: bytes, password: str = "") -> str:
    if payload[:4] != MAGIC:
        raise ValueError("No steganographic data found (bad magic).")
    enc_flag = payload[4]
    length   = int.from_bytes(payload[5:9], "big")
    raw      = payload[9: 9 + length]
    if len(raw) != length:
        raise ValueError("Payload truncated — file may be corrupt.")
    if enc_flag == 1:
        if not password:
            raise ValueError("Data is encrypted. Provide the password.")
        raw = xor_crypt(raw, password)
    return raw.decode("utf-8")


# ── 1. IMAGE  (LSB on RGB channels) ──────────────────────────────────────────

def image_encode(src_path: str, message: str, out_path: str, password: str = "") -> int:
    if not PIL_OK:
        raise RuntimeError("Pillow not installed: pip install pillow numpy")
    img = Image.open(src_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten().copy()

    payload = _pack_payload(message, password)
    bits_needed = len(payload) * 8
    if bits_needed > len(flat):
        raise ValueError(
            f"Image too small ({len(flat)} pixels). "
            f"Need {bits_needed} bits for this message."
        )

    for i, byte in enumerate(payload):
        for bit in range(8):
            idx = i * 8 + bit
            bv  = (byte >> (7 - bit)) & 1
            flat[idx] = (flat[idx] & 0xFE) | bv

    Image.fromarray(flat.reshape(pixels.shape)).save(out_path, format="PNG")
    return len(payload)

def image_decode(src_path: str, password: str = "") -> str:
    if not PIL_OK:
        raise RuntimeError("Pillow not installed: pip install pillow numpy")
    img = Image.open(src_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()

    # Read magic (4B) + flag (1B) + length (4B) = 9 bytes = 72 bits
    header_bits = flat[:72] & 1
    header = bytes(
        sum(int(header_bits[i * 8 + b]) << (7 - b) for b in range(8))
        for i in range(9)
    )
    if header[:4] != MAGIC:
        raise ValueError("No hidden data found in this image.")
    length = int.from_bytes(header[5:9], "big")
    if length <= 0 or length > 10_000_000:
        raise ValueError("Invalid payload length — no data or corrupt.")

    total_bits = (9 + length) * 8
    all_bits   = flat[:total_bits] & 1
    payload    = bytes(
        sum(int(all_bits[i * 8 + b]) << (7 - b) for b in range(8))
        for i in range(9 + length)
    )
    return _unpack_payload(payload, password)


# ── 2. AUDIO  (LSB in WAV sample bytes) ──────────────────────────────────────

def audio_encode(src_path: str, message: str, out_path: str, password: str = "") -> int:
    with wave.open(src_path, "r") as w:
        params = w.getparams()
        frames = bytearray(w.readframes(w.getnframes()))

    payload = _pack_payload(message, password)
    bits_needed = len(payload) * 8
    if bits_needed > len(frames):
        raise ValueError(
            f"Audio too short ({len(frames)} bytes). "
            f"Need {bits_needed} bits."
        )

    for i, byte in enumerate(payload):
        for bit in range(8):
            idx = i * 8 + bit
            bv  = (byte >> (7 - bit)) & 1
            frames[idx] = (frames[idx] & 0xFE) | bv

    with wave.open(out_path, "w") as w:
        w.setparams(params)
        w.writeframes(bytes(frames))
    return len(payload)

def audio_decode(src_path: str, password: str = "") -> str:
    with wave.open(src_path, "r") as w:
        frames = bytearray(w.readframes(w.getnframes()))

    # Read 9-byte header
    header_bits = [frames[i] & 1 for i in range(72)]
    header = bytes(
        sum(header_bits[i * 8 + b] << (7 - b) for b in range(8))
        for i in range(9)
    )
    if header[:4] != MAGIC:
        raise ValueError("No hidden data found in this audio file.")
    length = int.from_bytes(header[5:9], "big")
    if length <= 0 or length > 5_000_000:
        raise ValueError("Invalid payload length — no data or corrupt.")

    total = (9 + length) * 8
    all_bits = [frames[i] & 1 for i in range(total)]
    payload  = bytes(
        sum(all_bits[i * 8 + b] << (7 - b) for b in range(8))
        for i in range(9 + length)
    )
    return _unpack_payload(payload, password)


# ── 3. VIDEO  (inject custom 'free' MP4 box at EOF) ──────────────────────────

def video_encode(src_path: str, message: str, out_path: str, password: str = "") -> int:
    with open(src_path, "rb") as f:
        original = f.read()

    payload = _pack_payload(message, password)
    # Wrap in a valid MP4 'free' box (ignored by all players)
    box_data = payload
    box_size = 8 + len(box_data)
    box      = struct.pack(">I", box_size) + b"free" + box_data

    with open(out_path, "wb") as f:
        f.write(original + box)
    return len(payload)

def video_decode(src_path: str, password: str = "") -> str:
    with open(src_path, "rb") as f:
        data = f.read()

    # Walk MP4 boxes from the end to find our 'free' box with MAGIC
    pos = len(data) - 8
    while pos >= 0:
        try:
            size = struct.unpack_from(">I", data, pos)[0]
            btype = data[pos + 4: pos + 8]
            if btype == b"free" and size >= 8:
                box_data = data[pos + 8: pos + size]
                if box_data[:4] == MAGIC:
                    return _unpack_payload(box_data, password)
        except Exception:
            pass
        pos -= 1
        if pos < len(data) - 10_000_000:   # don't scan whole file
            break

    raise ValueError("No hidden data found in this video file.")


# ── 4. BINARY  (APK, EXE, PDF, ZIP — append after file) ─────────────────────

_BIN_START = b"\x00\xCA\xFE\xBA\xBE\x00"
_BIN_END   = b"\x00\xDE\xAD\xC0\xDE\x00"

def binary_encode(src_path: str, message: str, out_path: str, password: str = "") -> int:
    with open(src_path, "rb") as f:
        original = f.read()

    payload = _pack_payload(message, password)
    length  = len(payload).to_bytes(4, "big")
    wrapper = _BIN_START + length + payload + _BIN_END

    with open(out_path, "wb") as f:
        f.write(original + wrapper)
    return len(payload)

def binary_decode(src_path: str, password: str = "") -> str:
    with open(src_path, "rb") as f:
        data = f.read()

    start = data.rfind(_BIN_START)
    if start == -1:
        raise ValueError("No hidden data found in this binary file.")
    end = data.rfind(_BIN_END)
    if end <= start:
        raise ValueError("Binary steganography markers corrupt.")

    inner = data[start + len(_BIN_START): end]
    if len(inner) < 4:
        raise ValueError("Payload too short.")
    length  = int.from_bytes(inner[:4], "big")
    payload = inner[4: 4 + length]
    if len(payload) != length:
        raise ValueError("Payload truncated.")
    return _unpack_payload(payload, password)


# ── 5. TEXT  (zero-width Unicode characters) ─────────────────────────────────

_ZW0   = "\u200B"   # Zero Width Space      → bit 0
_ZW1   = "\u200C"   # Zero Width Non-Joiner → bit 1
_ZWDEL = "\u200D"   # Zero Width Joiner     → delimiter

def text_encode(cover_text: str, message: str, password: str = "") -> str:
    payload = _pack_payload(message, password)

    bits = []
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    hidden = _ZWDEL + "".join(_ZW0 if b == 0 else _ZW1 for b in bits) + _ZWDEL

    # Insert after first word so it's not at position 0
    parts = cover_text.split(" ", 1)
    if len(parts) == 1:
        return parts[0] + hidden
    return parts[0] + hidden + " " + parts[1]

def text_decode(stego_text: str, password: str = "") -> str:
    start = stego_text.find(_ZWDEL)
    end   = stego_text.find(_ZWDEL, start + 1)
    if start == -1 or end == -1:
        raise ValueError("No hidden data found in this text.")

    hidden = stego_text[start + 1: end]
    bits   = [0 if c == _ZW0 else 1 for c in hidden if c in (_ZW0, _ZW1)]

    if len(bits) < 72:
        raise ValueError("Hidden data too short.")

    payload = bytes(
        sum(bits[i * 8 + b] << (7 - b) for b in range(8))
        for i in range(len(bits) // 8)
    )
    return _unpack_payload(payload, password)


# ─────────────────────────────────────────────
# CAPACITY HELPERS
# ─────────────────────────────────────────────

def image_capacity(path: str) -> int:
    """Max message bytes storable in image."""
    try:
        img = Image.open(path).convert("RGB")
        w, h = img.size
        return (w * h * 3) // 8 - 9   # 3 channels, 1 bit each, minus 9B header
    except Exception:
        return 0

def audio_capacity(path: str) -> int:
    try:
        with wave.open(path, "r") as w:
            return w.getnframes() * w.getnchannels() * w.getsampwidth() // 8 - 9
    except Exception:
        return 0


# ─────────────────────────────────────────────
# FLASK WEB APPLICATION
# ─────────────────────────────────────────────

CSS = """<style>
:root{--bg:#0d1117;--card:#161b22;--border:#21262d;--accent:#58a6ff;
      --green:#3fb950;--red:#f85149;--warn:#d29922;--text:#c9d1d9;--muted:#6e7681;
      --font:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
nav{background:var(--card);border-bottom:1px solid var(--border);
    display:flex;align-items:center;flex-wrap:wrap;padding:0 1.5rem;min-height:52px;
    position:sticky;top:0;z-index:100}
.nav-brand{font-weight:700;font-size:.95rem;color:var(--accent);margin-right:1.5rem;
           padding:.8rem 0;white-space:nowrap}
nav a.nav-link{color:var(--muted);font-size:.78rem;padding:0 .65rem;line-height:52px;
    border-bottom:2px solid transparent;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
nav a.nav-link:hover,nav a.nav-link.on{color:var(--text);border-bottom-color:var(--accent);text-decoration:none}
main{max-width:1000px;margin:0 auto;padding:1.8rem 1.2rem}
h1{font-size:1.3rem;font-weight:700;margin-bottom:.25rem}
.sub{color:var(--muted);font-size:.83rem;margin-bottom:1.3rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1rem}
.card h2{font-size:.95rem;font-weight:700;margin-bottom:.9rem;color:var(--text)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}
.stat-n{font-size:1.8rem;font-weight:700;line-height:1}
.stat-l{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:.2rem}
.fl{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.fl-end{display:flex;justify-content:flex-end;gap:.5rem;flex-wrap:wrap}
label{font-size:.75rem;color:var(--muted);display:block;margin-bottom:3px;
      text-transform:uppercase;letter-spacing:.06em}
input[type=text],input[type=password],input[type=file],select,textarea{
  background:#1c2128;border:1px solid var(--border);color:var(--text);
  font-family:var(--font);font-size:.85rem;padding:8px 10px;border-radius:5px;width:100%}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
textarea{resize:vertical;min-height:100px}
.fg{margin-bottom:.9rem}
.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 16px;border-radius:5px;
     font-family:var(--font);font-size:.82rem;font-weight:600;cursor:pointer;
     border:none;transition:opacity .15s;text-decoration:none;white-space:nowrap}
.btn:hover{opacity:.82;text-decoration:none}
.btn-p{background:var(--accent);color:#0d1117}
.btn-g{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.btn-d{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn-sm{padding:4px 10px;font-size:.75rem}
.pill{display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:600;white-space:nowrap}
.p-green{background:rgba(63,185,80,.12);color:var(--green)}
.p-blue{background:rgba(88,166,255,.12);color:var(--accent)}
.p-red{background:rgba(248,81,73,.12);color:var(--red)}
.p-warn{background:rgba(210,153,34,.12);color:var(--warn)}
.p-gray{background:rgba(110,118,129,.15);color:var(--muted)}
.disc{background:rgba(210,153,34,.06);border:1px solid rgba(210,153,34,.25);
      border-left:4px solid var(--warn);border-radius:6px;padding:.9rem 1rem;margin-bottom:1.1rem}
.disc h4{font-size:.72rem;color:var(--warn);text-transform:uppercase;letter-spacing:.1em;margin-bottom:.35rem}
.disc p,.disc li{font-size:.78rem;color:#9a8050;line-height:1.7}
.disc ul{padding-left:1rem;margin-top:.2rem}
.alert{padding:.65rem .9rem;border-radius:5px;margin-bottom:.8rem;font-size:.82rem}
.a-ok{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.25);color:var(--green)}
.a-err{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.25);color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{padding:8px 10px;text-align:left;font-size:.7rem;color:var(--muted);
   text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.mono{font-family:monospace;font-size:.8rem}
.result-box{background:#1c2128;border:1px solid var(--border);border-radius:5px;
            padding:1rem;font-family:monospace;font-size:.85rem;white-space:pre-wrap;
            word-break:break-all;max-height:200px;overflow-y:auto;color:var(--green)}
.empty{text-align:center;padding:2.5rem;color:var(--muted)}
footer{text-align:center;padding:1.8rem;font-size:.72rem;color:var(--muted);
       border-top:1px solid var(--border);margin-top:2rem}
footer a{color:var(--accent)}
@media(max-width:640px){.grid2,.grid3{grid-template-columns:1fr}main{padding:1rem}}
</style>"""

NAV_T = """<nav>
  <span class="nav-brand">🔏 StegaTool</span>
  <a href="/" class="nav-link {{ 'on' if pg=='home' }}">Home</a>
  <a href="/image" class="nav-link {{ 'on' if pg=='image' }}">Image</a>
  <a href="/audio" class="nav-link {{ 'on' if pg=='audio' }}">Audio</a>
  <a href="/video" class="nav-link {{ 'on' if pg=='video' }}">Video</a>
  <a href="/binary" class="nav-link {{ 'on' if pg=='binary' }}">Binary/APK</a>
  <a href="/text" class="nav-link {{ 'on' if pg=='text' }}">Text</a>
  <a href="/history" class="nav-link {{ 'on' if pg=='history' }}">History</a>
</nav>"""

BASE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} — StegaTool</title>
""" + CSS + """
</head>
<body>""" + NAV_T + """
<main>
{% with msgs = get_flashed_messages(with_categories=true) %}
{% for cat,msg in msgs %}
<div class="alert {{ 'a-ok' if cat=='ok' else 'a-err' }}">{{ msg }}</div>
{% endfor %}{% endwith %}
{{ content }}
</main>
<footer>
  StegaTool v{{ ver }} &nbsp;·&nbsp;
  <a href="{{ github }}" target="_blank">github.com/mrshrivasta</a> &nbsp;·&nbsp;
  <a href="{{ linkedin }}" target="_blank">Karanam Shrivasta</a><br>
  ⚠ Educational &amp; research use only · No warranty · Do not expose outside localhost
</footer>
</body></html>"""


# ── shared disclaimer block ───────────────────────────────────────────────────
DISC = """<div class="disc">
  <h4>⚠ Disclaimer</h4>
  <ul>
    <li>For <strong>educational and research purposes only</strong>.</li>
    <li>Hiding illegal content using steganography is a criminal offence in most jurisdictions.</li>
    <li>Only analyse or modify files you own or have explicit written permission to modify.</li>
    <li>Author (Karanam Shrivasta) accepts <strong>no liability</strong> for misuse or consequences.</li>
    <li>All processing is <strong>local only</strong> — no data leaves your machine.</li>
  </ul>
</div>"""


# ── page builders ─────────────────────────────────────────────────────────────

def _steg_page(title, icon, accept, encode_url, decode_url, extra_note=""):
    """Generic encode/decode page template for image/audio/video/binary."""
    return f"""
<h1>{icon} {title} Steganography</h1>
<p class="sub">Hide or extract a secret message in a {title.lower()} file.</p>
{DISC}
{extra_note}
<div class="grid2">
  <div class="card">
    <h2>🔒 Encode — Hide a message</h2>
    <form method="post" action="{encode_url}" enctype="multipart/form-data">
      <div class="fg"><label>Carrier file ({accept})</label>
        <input type="file" name="carrier" accept="{accept}" required></div>
      <div class="fg"><label>Secret message</label>
        <textarea name="message" placeholder="Type your secret message here…" required></textarea></div>
      <div class="fg"><label>Password (optional — for encryption)</label>
        <input type="password" name="password" placeholder="Leave blank for no encryption"></div>
      <button class="btn btn-p" type="submit">🔒 Encode & Download</button>
    </form>
  </div>
  <div class="card">
    <h2>🔓 Decode — Extract a message</h2>
    <form method="post" action="{decode_url}" enctype="multipart/form-data">
      <div class="fg"><label>Stego file ({accept})</label>
        <input type="file" name="stego" accept="{accept}" required></div>
      <div class="fg"><label>Password (if encrypted)</label>
        <input type="password" name="password" placeholder="Leave blank if not encrypted"></div>
      <button class="btn btn-g" type="submit">🔓 Decode & Extract</button>
    </form>
    {{% if decoded_msg %}}
    <div style="margin-top:1rem">
      <label>Extracted message</label>
      <div class="result-box">{{{{ decoded_msg }}}}</div>
      <div class="fl-end" style="margin-top:.5rem">
        <a href="{{{{ download_txt }}}}" class="btn btn-ghost btn-sm">⬇ .txt</a>
        <a href="{{{{ download_json }}}}" class="btn btn-ghost btn-sm">⬇ .json</a>
        <a href="{{{{ download_csv }}}}" class="btn btn-ghost btn-sm">⬇ .csv</a>
      </div>
    </div>
    {{% endif %}}
  </div>
</div>"""


HOME_CONTENT = f"""
<h1>🔏 StegaTool</h1>
<p class="sub">Hide secret messages inside Images, Audio, Video, Binary files and Text — locally, no API keys.</p>
{DISC}
<div class="grid3" style="margin-bottom:1rem">
  <div class="card" style="text-align:center">
    <div class="stat-n" style="color:var(--accent)">{{{{ total_ops }}}}</div>
    <div class="stat-l">Total Operations</div>
  </div>
  <div class="card" style="text-align:center">
    <div class="stat-n" style="color:var(--green)">{{{{ encode_ops }}}}</div>
    <div class="stat-l">Encode Operations</div>
  </div>
  <div class="card" style="text-align:center">
    <div class="stat-n" style="color:var(--warn)">{{{{ decode_ops }}}}</div>
    <div class="stat-l">Decode Operations</div>
  </div>
</div>
<div class="grid3">
  <a href="/image" class="card" style="text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
    <div style="font-size:1.8rem">🖼️</div>
    <strong style="display:block;margin:.4rem 0 .2rem">Image</strong>
    <span style="font-size:.78rem;color:var(--muted)">LSB on PNG / BMP / TIFF pixels. Invisible to the human eye.</span>
  </a>
  <a href="/audio" class="card" style="text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
    <div style="font-size:1.8rem">🎵</div>
    <strong style="display:block;margin:.4rem 0 .2rem">Audio</strong>
    <span style="font-size:.78rem;color:var(--muted)">LSB in WAV sample bytes. Inaudible difference.</span>
  </a>
  <a href="/video" class="card" style="text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
    <div style="font-size:1.8rem">🎬</div>
    <strong style="display:block;margin:.4rem 0 .2rem">Video</strong>
    <span style="font-size:.78rem;color:var(--muted)">MP4 free-box injection. File plays normally.</span>
  </a>
  <a href="/binary" class="card" style="text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
    <div style="font-size:1.8rem">📦</div>
    <strong style="display:block;margin:.4rem 0 .2rem">Binary / APK</strong>
    <span style="font-size:.78rem;color:var(--muted)">Appended payload in APK, EXE, PDF, ZIP, and any binary.</span>
  </a>
  <a href="/text" class="card" style="text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
    <div style="font-size:1.8rem">📄</div>
    <strong style="display:block;margin:.4rem 0 .2rem">Text</strong>
    <span style="font-size:.78rem;color:var(--muted)">Zero-width Unicode characters. Invisible in any text.</span>
  </a>
  <a href="/history" class="card" style="text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
    <div style="font-size:1.8rem">📋</div>
    <strong style="display:block;margin:.4rem 0 .2rem">History</strong>
    <span style="font-size:.78rem;color:var(--muted)">All operations logged. Export as CSV or JSON.</span>
  </a>
</div>
<div class="card" style="margin-top:.5rem">
  <table>
    <tr><th>Method</th><th>Carrier</th><th>Technique</th><th>Capacity</th><th>Detectability</th></tr>
    <tr><td>Image LSB</td><td>PNG, BMP, TIFF</td><td>Least Significant Bit in RGB channels</td><td>~1/8 of image size</td><td><span class="pill p-green">Very Low</span></td></tr>
    <tr><td>Audio LSB</td><td>WAV</td><td>LSB in PCM sample bytes</td><td>~1/8 of audio size</td><td><span class="pill p-green">Very Low</span></td></tr>
    <tr><td>Video Box</td><td>MP4, MOV, AVI</td><td>MP4 free-atom injection at EOF</td><td>Unlimited</td><td><span class="pill p-blue">Low</span></td></tr>
    <tr><td>Binary Append</td><td>APK, EXE, PDF, ZIP, any</td><td>Marker-delimited append after EOF</td><td>Unlimited</td><td><span class="pill p-warn">Medium</span></td></tr>
    <tr><td>Text ZWC</td><td>TXT, HTML, any text</td><td>Zero-width Unicode chars between words</td><td>Limited by word count</td><td><span class="pill p-green">Very Low</span></td></tr>
  </table>
</div>"""


IMAGE_CONTENT = _steg_page(
    "Image", "🖼️", ".png,.bmp,.tiff,.tif",
    "/image/encode", "/image/decode",
    """<div class="card" style="padding:.8rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:var(--muted)">
    ⚙ <strong style="color:var(--text)">How it works:</strong>
    Each pixel's RGB values are stored as 8-bit integers.
    We overwrite the least significant bit of each byte.
    A 1000×1000 image (3 million bytes) can hold ~375 KB of data.
    Output is always PNG (lossless) to preserve hidden bits.
    </div>"""
)

AUDIO_CONTENT = _steg_page(
    "Audio", "🎵", ".wav",
    "/audio/encode", "/audio/decode",
    """<div class="card" style="padding:.8rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:var(--muted)">
    ⚙ <strong style="color:var(--text)">How it works:</strong>
    WAV files store raw PCM samples as bytes.
    We modify the least significant bit of each sample byte.
    A 44100 Hz 16-bit mono WAV has 88200 bytes/second — enough for ~11 KB/s of hidden data.
    Output WAV is identical in size and sounds the same to human ears.
    </div>"""
)

VIDEO_CONTENT = _steg_page(
    "Video", "🎬", ".mp4,.mov,.avi,.mkv",
    "/video/encode", "/video/decode",
    """<div class="card" style="padding:.8rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:var(--muted)">
    ⚙ <strong style="color:var(--text)">How it works:</strong>
    MP4/MOV containers use a box (atom) structure.
    We append a valid 'free' box at the end of the file.
    Media players ignore 'free' boxes — the video plays normally.
    Capacity: unlimited (no pixel or sample constraint).
    </div>"""
)

BINARY_CONTENT = _steg_page(
    "Binary / APK / PDF", "📦",
    ".apk,.exe,.pdf,.zip,.jar,.bin,.iso,.dll,.so,.dex",
    "/binary/encode", "/binary/decode",
    """<div class="card" style="padding:.8rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:var(--muted)">
    ⚙ <strong style="color:var(--text)">How it works:</strong>
    Most binary formats (ZIP/APK/JAR/EXE) ignore trailing data after their logical EOF.
    We append a marker-delimited payload at the end of the file.
    APKs still install normally. ZIPs still open. PDFs still render.
    Works on any binary file format.
    </div>"""
)

TEXT_CONTENT = f"""
<h1>📄 Text Steganography</h1>
<p class="sub">Hide a secret message inside plain text using invisible zero-width Unicode characters.</p>
{DISC}
<div class="card" style="padding:.8rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:var(--muted)">
  ⚙ <strong style="color:var(--text)">How it works:</strong>
  Unicode contains zero-width characters (U+200B, U+200C, U+200D) that are invisible in all
  text renderers, editors, and browsers. We encode message bits as sequences of these characters
  and insert them after the first word of the cover text. The text looks and reads identically.
</div>
<div class="grid2">
  <div class="card">
    <h2>🔒 Encode — Hide in text</h2>
    <form method="post" action="/text/encode">
      <div class="fg"><label>Cover text (public, innocent-looking text)</label>
        <textarea name="cover" rows="5" placeholder="The quick brown fox jumps over the lazy dog…" required></textarea></div>
      <div class="fg"><label>Secret message</label>
        <textarea name="message" rows="4" placeholder="Your secret message here…" required></textarea></div>
      <div class="fg"><label>Password (optional)</label>
        <input type="password" name="password" placeholder="Leave blank for no encryption"></div>
      <button class="btn btn-p" type="submit">🔒 Encode</button>
    </form>
    {{{{ encoded_text_block | safe }}}}
  </div>
  <div class="card">
    <h2>🔓 Decode — Extract from text</h2>
    <form method="post" action="/text/decode">
      <div class="fg"><label>Stego text (paste text with hidden data)</label>
        <textarea name="stego" rows="5" placeholder="Paste the text that contains a hidden message…" required></textarea></div>
      <div class="fg"><label>Password (if encrypted)</label>
        <input type="password" name="password" placeholder="Leave blank if not encrypted"></div>
      <button class="btn btn-g" type="submit">🔓 Decode</button>
    </form>
    {{% if decoded_msg %}}
    <div style="margin-top:1rem">
      <label>Extracted message</label>
      <div class="result-box">{{{{ decoded_msg }}}}</div>
      <div class="fl-end" style="margin-top:.5rem">
        <a href="{{{{ download_txt }}}}" class="btn btn-ghost btn-sm">⬇ .txt</a>
        <a href="{{{{ download_json }}}}" class="btn btn-ghost btn-sm">⬇ .json</a>
        <a href="{{{{ download_csv }}}}" class="btn btn-ghost btn-sm">⬇ .csv</a>
      </div>
    </div>
    {{% endif %}}
  </div>
</div>"""

HISTORY_CONTENT = """
<div class="fl" style="justify-content:space-between;margin-bottom:1rem">
  <div>
    <h1>📋 Operation History</h1>
    <p class="sub">Every encode/decode operation logged in SQLite.</p>
  </div>
  <div class="fl">
    <a href="/history/export/csv" class="btn btn-ghost btn-sm">⬇ CSV</a>
    <a href="/history/export/json" class="btn btn-ghost btn-sm">⬇ JSON</a>
    <form method="post" action="/history/clear"
          onsubmit="return confirm('Clear all history?')">
      <button class="btn btn-d btn-sm">🗑 Clear</button>
    </form>
  </div>
</div>
{% if rows %}
<div class="card" style="padding:0;overflow-x:auto">
<table>
  <tr>
    <th>#</th><th>Timestamp</th><th>Op</th><th>Type</th>
    <th>Source file</th><th>Output file</th><th>Msg len</th><th>Enc</th>
  </tr>
  {% for r in rows %}
  <tr>
    <td class="mono" style="color:var(--muted)">{{ r.id }}</td>
    <td style="white-space:nowrap;color:var(--muted);font-size:.78rem">{{ r.ts }}</td>
    <td>
      {% if r.op_type == 'encode' %}<span class="pill p-blue">encode</span>
      {% else %}<span class="pill p-green">decode</span>{% endif %}
    </td>
    <td><span class="pill p-gray">{{ r.steg_type }}</span></td>
    <td class="mono" style="color:var(--muted);font-size:.75rem">{{ r.src_file or '—' }}</td>
    <td class="mono" style="color:var(--muted);font-size:.75rem">{{ r.out_file or '—' }}</td>
    <td style="color:var(--muted)">{{ r.msg_length or '—' }}</td>
    <td>{% if r.encrypted %}<span class="pill p-warn">🔑 yes</span>{% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
</table>
</div>
<p style="font-size:.75rem;color:var(--muted);margin-top:.5rem">{{ rows|length }} record(s)</p>
{% else %}
<div class="card"><p class="empty">No operations yet. Try encoding a file!</p></div>
{% endif %}"""


def create_app(db_path=DB_FILE):
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(24)
    app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024

    conn = get_db(db_path)

    # ── helpers ───────────────────────────────────────────────────────────────

    def render(template, pg, title, **kw):
        kw.update(ver=VERSION, github=GITHUB, linkedin=LINKEDIN,
                  author=AUTHOR, pg=pg, title=title)
        return render_template_string(
            BASE.replace("{{ content }}", template), **kw
        )

    def save_file(file_storage, subdir="uploads"):
        fname = secrets.token_hex(8) + "_" + file_storage.filename
        path  = UPLOAD / fname
        file_storage.save(str(path))
        return str(path), file_storage.filename

    def save_output(data: bytes, ext: str) -> str:
        fname = secrets.token_hex(8) + ext
        path  = OUTPUT / fname
        with open(str(path), "wb") as f:
            f.write(data)
        return str(path)

    def result_downloads(message: str, steg_type: str):
        """Save decoded message in txt/json/csv and return download URLs."""
        token = secrets.token_hex(6)
        # txt
        txt_path = OUTPUT / f"{token}.txt"
        txt_path.write_text(message, encoding="utf-8")
        # json
        jsn_path = OUTPUT / f"{token}.json"
        jsn_path.write_text(json.dumps({"steg_type": steg_type,
                                         "message": message,
                                         "extracted_at": datetime.datetime.now().isoformat()},
                                        indent=2), encoding="utf-8")
        # csv
        csv_path = OUTPUT / f"{token}.csv"
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["steg_type", "message", "extracted_at"])
        w.writerow([steg_type, message, datetime.datetime.now().isoformat()])
        csv_path.write_text(out.getvalue(), encoding="utf-8")

        return (f"/download/{txt_path.name}",
                f"/download/{jsn_path.name}",
                f"/download/{csv_path.name}")

    # ── download ──────────────────────────────────────────────────────────────

    @app.route("/download/<fname>")
    def download(fname):
        path = OUTPUT / fname
        if not path.exists():
            path = UPLOAD / fname
        if not path.exists():
            flash("File not found.", "err")
            return redirect("/")
        return send_file(str(path), as_attachment=True, download_name=path.name)

    # ── home ──────────────────────────────────────────────────────────────────

    @app.route("/")
    def home():
        total   = conn.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        encodes = conn.execute("SELECT COUNT(*) FROM operations WHERE op_type='encode'").fetchone()[0]
        decodes = conn.execute("SELECT COUNT(*) FROM operations WHERE op_type='decode'").fetchone()[0]
        return render(HOME_CONTENT, "home", "Home",
                      total_ops=total, encode_ops=encodes, decode_ops=decodes)

    # ── IMAGE ─────────────────────────────────────────────────────────────────

    @app.route("/image")
    def image_page():
        return render(IMAGE_CONTENT, "image", "Image")

    @app.route("/image/encode", methods=["POST"])
    def image_encode_route():
        if not PIL_OK:
            flash("Pillow not installed. Run: pip install pillow numpy", "err")
            return redirect("/image")
        carrier  = request.files.get("carrier")
        message  = request.form.get("message", "").strip()
        password = request.form.get("password", "").strip()
        if not carrier or not message:
            flash("Carrier file and message are required.", "err")
            return redirect("/image")
        try:
            src_path, orig_name = save_file(carrier)
            out_path = save_output(b"", ".png")
            image_encode(src_path, message, out_path, password)
            db_log(conn, "encode", "image", orig_name, Path(out_path).name,
                   len(message), 1 if password else 0)
            flash(f"✓ Message encoded. Downloading stego image.", "ok")
            return send_file(out_path, as_attachment=True,
                             download_name="stego_" + Path(orig_name).stem + ".png")
        except Exception as e:
            flash(f"Encode error: {e}", "err")
            return redirect("/image")

    @app.route("/image/decode", methods=["POST"])
    def image_decode_route():
        if not PIL_OK:
            flash("Pillow not installed. Run: pip install pillow numpy", "err")
            return redirect("/image")
        stego    = request.files.get("stego")
        password = request.form.get("password", "").strip()
        if not stego:
            flash("Stego file required.", "err")
            return redirect("/image")
        try:
            src_path, orig_name = save_file(stego)
            msg = image_decode(src_path, password)
            db_log(conn, "decode", "image", orig_name, "", len(msg), 1 if password else 0)
            dtxt, djson, dcsv = result_downloads(msg, "image")
            flash("✓ Message extracted successfully.", "ok")
            return render(IMAGE_CONTENT, "image", "Image",
                          decoded_msg=msg, download_txt=dtxt,
                          download_json=djson, download_csv=dcsv)
        except Exception as e:
            flash(f"Decode error: {e}", "err")
            return redirect("/image")

    # ── AUDIO ─────────────────────────────────────────────────────────────────

    @app.route("/audio")
    def audio_page():
        return render(AUDIO_CONTENT, "audio", "Audio")

    @app.route("/audio/encode", methods=["POST"])
    def audio_encode_route():
        carrier  = request.files.get("carrier")
        message  = request.form.get("message", "").strip()
        password = request.form.get("password", "").strip()
        if not carrier or not message:
            flash("Carrier file and message required.", "err")
            return redirect("/audio")
        try:
            src_path, orig_name = save_file(carrier)
            out_path = save_output(b"", ".wav")
            audio_encode(src_path, message, out_path, password)
            db_log(conn, "encode", "audio", orig_name, Path(out_path).name,
                   len(message), 1 if password else 0)
            flash("✓ Message encoded in audio.", "ok")
            return send_file(out_path, as_attachment=True,
                             download_name="stego_" + Path(orig_name).stem + ".wav")
        except Exception as e:
            flash(f"Encode error: {e}", "err")
            return redirect("/audio")

    @app.route("/audio/decode", methods=["POST"])
    def audio_decode_route():
        stego    = request.files.get("stego")
        password = request.form.get("password", "").strip()
        if not stego:
            flash("Stego file required.", "err")
            return redirect("/audio")
        try:
            src_path, orig_name = save_file(stego)
            msg = audio_decode(src_path, password)
            db_log(conn, "decode", "audio", orig_name, "", len(msg), 1 if password else 0)
            dtxt, djson, dcsv = result_downloads(msg, "audio")
            flash("✓ Message extracted.", "ok")
            return render(AUDIO_CONTENT, "audio", "Audio",
                          decoded_msg=msg, download_txt=dtxt,
                          download_json=djson, download_csv=dcsv)
        except Exception as e:
            flash(f"Decode error: {e}", "err")
            return redirect("/audio")

    # ── VIDEO ─────────────────────────────────────────────────────────────────

    @app.route("/video")
    def video_page():
        return render(VIDEO_CONTENT, "video", "Video")

    @app.route("/video/encode", methods=["POST"])
    def video_encode_route():
        carrier  = request.files.get("carrier")
        message  = request.form.get("message", "").strip()
        password = request.form.get("password", "").strip()
        if not carrier or not message:
            flash("Carrier file and message required.", "err")
            return redirect("/video")
        try:
            src_path, orig_name = save_file(carrier)
            ext = Path(orig_name).suffix or ".mp4"
            out_path = save_output(b"", ext)
            video_encode(src_path, message, out_path, password)
            db_log(conn, "encode", "video", orig_name, Path(out_path).name,
                   len(message), 1 if password else 0)
            flash("✓ Message encoded in video.", "ok")
            return send_file(out_path, as_attachment=True,
                             download_name="stego_" + orig_name)
        except Exception as e:
            flash(f"Encode error: {e}", "err")
            return redirect("/video")

    @app.route("/video/decode", methods=["POST"])
    def video_decode_route():
        stego    = request.files.get("stego")
        password = request.form.get("password", "").strip()
        if not stego:
            flash("Stego file required.", "err")
            return redirect("/video")
        try:
            src_path, orig_name = save_file(stego)
            msg = video_decode(src_path, password)
            db_log(conn, "decode", "video", orig_name, "", len(msg), 1 if password else 0)
            dtxt, djson, dcsv = result_downloads(msg, "video")
            flash("✓ Message extracted.", "ok")
            return render(VIDEO_CONTENT, "video", "Video",
                          decoded_msg=msg, download_txt=dtxt,
                          download_json=djson, download_csv=dcsv)
        except Exception as e:
            flash(f"Decode error: {e}", "err")
            return redirect("/video")

    # ── BINARY ────────────────────────────────────────────────────────────────

    @app.route("/binary")
    def binary_page():
        return render(BINARY_CONTENT, "binary", "Binary / APK")

    @app.route("/binary/encode", methods=["POST"])
    def binary_encode_route():
        carrier  = request.files.get("carrier")
        message  = request.form.get("message", "").strip()
        password = request.form.get("password", "").strip()
        if not carrier or not message:
            flash("Carrier file and message required.", "err")
            return redirect("/binary")
        try:
            src_path, orig_name = save_file(carrier)
            ext = Path(orig_name).suffix or ".bin"
            out_path = save_output(b"", ext)
            binary_encode(src_path, message, out_path, password)
            db_log(conn, "encode", "binary", orig_name, Path(out_path).name,
                   len(message), 1 if password else 0)
            flash("✓ Message encoded in binary.", "ok")
            return send_file(out_path, as_attachment=True,
                             download_name="stego_" + orig_name)
        except Exception as e:
            flash(f"Encode error: {e}", "err")
            return redirect("/binary")

    @app.route("/binary/decode", methods=["POST"])
    def binary_decode_route():
        stego    = request.files.get("stego")
        password = request.form.get("password", "").strip()
        if not stego:
            flash("Stego file required.", "err")
            return redirect("/binary")
        try:
            src_path, orig_name = save_file(stego)
            msg = binary_decode(src_path, password)
            db_log(conn, "decode", "binary", orig_name, "", len(msg), 1 if password else 0)
            dtxt, djson, dcsv = result_downloads(msg, "binary")
            flash("✓ Message extracted.", "ok")
            return render(BINARY_CONTENT, "binary", "Binary / APK",
                          decoded_msg=msg, download_txt=dtxt,
                          download_json=djson, download_csv=dcsv)
        except Exception as e:
            flash(f"Decode error: {e}", "err")
            return redirect("/binary")

    # ── TEXT ──────────────────────────────────────────────────────────────────

    @app.route("/text")
    def text_page():
        return render(TEXT_CONTENT, "text", "Text", encoded_text_block="")

    @app.route("/text/encode", methods=["POST"])
    def text_encode_route():
        cover    = request.form.get("cover", "").strip()
        message  = request.form.get("message", "").strip()
        password = request.form.get("password", "").strip()
        if not cover or not message:
            flash("Cover text and secret message required.", "err")
            return redirect("/text")
        try:
            stego = text_encode(cover, message, password)
            db_log(conn, "encode", "text", "(text input)", "(text output)",
                   len(message), 1 if password else 0)

            # Save outputs
            token = secrets.token_hex(6)
            (OUTPUT / f"{token}.txt").write_text(stego, encoding="utf-8")
            (OUTPUT / f"{token}.json").write_text(
                json.dumps({"cover": cover, "stego": stego,
                            "message_length": len(message)}, indent=2),
                encoding="utf-8"
            )
            out = io.StringIO()
            csv.writer(out).writerows([
                ["field","value"],
                ["stego_text", stego],
                ["original_cover", cover],
                ["message_length", len(message)],
            ])
            (OUTPUT / f"{token}.csv").write_text(out.getvalue(), encoding="utf-8")

            block = f"""<div style="margin-top:1rem">
              <label>Stego text (copy & share — looks identical to cover)</label>
              <div class="result-box">{stego}</div>
              <div class="fl-end" style="margin-top:.5rem">
                <a href="/download/{token}.txt" class="btn btn-ghost btn-sm">⬇ .txt</a>
                <a href="/download/{token}.json" class="btn btn-ghost btn-sm">⬇ .json</a>
                <a href="/download/{token}.csv" class="btn btn-ghost btn-sm">⬇ .csv</a>
              </div></div>"""
            flash("✓ Message encoded in text.", "ok")
            return render(TEXT_CONTENT, "text", "Text", encoded_text_block=block)
        except Exception as e:
            flash(f"Encode error: {e}", "err")
            return redirect("/text")

    @app.route("/text/decode", methods=["POST"])
    def text_decode_route():
        stego_text = request.form.get("stego", "")
        password   = request.form.get("password", "").strip()
        if not stego_text:
            flash("Stego text required.", "err")
            return redirect("/text")
        try:
            msg = text_decode(stego_text, password)
            db_log(conn, "decode", "text", "(text input)", "", len(msg), 1 if password else 0)
            dtxt, djson, dcsv = result_downloads(msg, "text")
            flash("✓ Message extracted.", "ok")
            return render(TEXT_CONTENT, "text", "Text",
                          encoded_text_block="",
                          decoded_msg=msg, download_txt=dtxt,
                          download_json=djson, download_csv=dcsv)
        except Exception as e:
            flash(f"Decode error: {e}", "err")
            return redirect("/text")

    # ── HISTORY ───────────────────────────────────────────────────────────────

    @app.route("/history")
    def history_page():
        rows = conn.execute(
            "SELECT * FROM operations ORDER BY id DESC LIMIT 500"
        ).fetchall()
        return render(HISTORY_CONTENT, "history", "History", rows=rows)

    @app.route("/history/export/csv")
    def history_csv():
        rows = conn.execute("SELECT * FROM operations ORDER BY id DESC").fetchall()
        out  = io.StringIO()
        w    = csv.writer(out)
        w.writerow(["id","ts","op_type","steg_type","src_file",
                    "out_file","msg_length","encrypted","note"])
        for r in rows:
            w.writerow(list(r))
        resp = make_response(out.getvalue())
        resp.headers["Content-Type"] = "text/csv"
        resp.headers["Content-Disposition"] = "attachment; filename=stegano_history.csv"
        return resp

    @app.route("/history/export/json")
    def history_json():
        rows = conn.execute("SELECT * FROM operations ORDER BY id DESC").fetchall()
        data = [dict(r) for r in rows]
        resp = make_response(json.dumps(data, indent=2))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = "attachment; filename=stegano_history.json"
        return resp

    @app.route("/history/clear", methods=["POST"])
    def history_clear():
        conn.execute("DELETE FROM operations")
        conn.commit()
        flash("History cleared.", "ok")
        return redirect("/history")

    # ── API ───────────────────────────────────────────────────────────────────

    @app.route("/api/stats")
    def api_stats():
        rows = conn.execute(
            "SELECT op_type, steg_type, COUNT(*) as cnt "
            "FROM operations GROUP BY op_type, steg_type"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    return app


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="StegaTool — Steganography Web App")
    p.add_argument("--host",  default="127.0.0.1")
    p.add_argument("--port",  type=int, default=5000)
    p.add_argument("--db",    default=DB_FILE)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    if not PIL_OK:
        print("⚠  WARNING: Pillow not installed — Image steganography disabled.")
        print("   Install with:  pip install pillow numpy\n")

    print(f"""
  ╔═══════════════════════════════════════════╗
  ║  StegaTool v{VERSION:<28} ║
  ║  {AUTHOR:<39} ║
  ╚═══════════════════════════════════════════╝

  ⚠  Educational & research use only.
     LOCALHOST ONLY — do not expose publicly.
     Author accepts no liability for misuse.

  Web UI  →  http://{args.host}:{args.port}
  Database→  {os.path.abspath(args.db)}
  Uploads →  {UPLOAD.resolve()}
  Outputs →  {OUTPUT.resolve()}
    """)

    app = create_app(db_path=args.db)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
