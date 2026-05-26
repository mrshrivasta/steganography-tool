# 🔏 StegaTool — Advanced Multi-Format Steganography Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-black?style=for-the-badge&logo=flask)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Steganography-red?style=for-the-badge)
![SQLite](https://img.shields.io/badge/SQLite-Logging-success?style=for-the-badge)
![Open Source](https://img.shields.io/badge/Open%20Source-GitHub-181717?style=for-the-badge&logo=github)
![Cross Platform](https://img.shields.io/badge/Cross%20Platform-Windows%20%7C%20Linux%20%7C%20macOS-orange?style=for-the-badge)

<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=24&pause=1000&color=58A6FF&center=true&vCenter=true&width=1200&lines=Advanced+Steganography+Toolkit;Hide+Secrets+Inside+Images+Audio+Video;Cybersecurity+%2B+Digital+Forensics+Project;Python+Flask+Steganography+Dashboard;Educational+Security+Research+Tool" />

### 🔥 Multi-Format Steganography & Secret Data Hiding Tool

### ⚡ Images • Audio • Video • APK • EXE • PDF • Text • Encryption

</div>

---

# 📌 Overview

StegaTool is an advanced cybersecurity-inspired steganography platform built using Python and Flask.

It allows users to:

✅ Hide secret messages inside files  
✅ Extract hidden messages  
✅ Encrypt hidden payloads  
✅ Perform multi-format steganography  
✅ Track operations using SQLite  
✅ Use a modern Flask dashboard  

---

# ⚠️ IMPORTANT DISCLAIMER

```txt
THIS PROJECT IS STRICTLY FOR:

- educational purposes
- cybersecurity learning
- digital forensics research
- steganography experimentation
- ethical security testing
- authorized file analysis

DO NOT:
- hide illegal material
- violate privacy laws
- misuse encryption/steganography
- distribute malicious hidden payloads
- analyze files without permission

Using steganography for illegal purposes may violate laws.

The author accepts ZERO liability for:
- misuse
- legal consequences
- data loss
- corrupted files
- security incidents
```

---

# 🚀 Features

# 🖼️ Image Steganography

Hide messages inside:

- PNG
- BMP
- TIFF

Using:

```txt
LSB (Least Significant Bit) encoding
```

---

# 🎵 Audio Steganography

Supports:

- WAV audio files

Technique:

```txt
LSB audio sample encoding
```

---

# 🎬 Video Steganography

Supports:

- MP4
- MOV
- AVI
- MKV

Technique:

```txt
MP4 free-box injection
```

---

# 📦 Binary Steganography

Hide messages inside:

- APK
- EXE
- PDF
- ZIP
- DLL
- ISO
- BIN
- JAR

---

# 📄 Text Steganography

Uses:

```txt
Invisible zero-width Unicode characters
```

to hide messages in plain text.

---

# 🔒 Optional Encryption

Supports:

```txt
XOR encryption + SHA-256 key stretching
```

for hidden messages.

---

# 📋 SQLite Logging

Stores:

- encode history
- decode history
- timestamps
- file types
- encryption usage

---

# 🌐 Flask Web Dashboard

Modern dashboard includes:

✅ Image tools  
✅ Audio tools  
✅ Video tools  
✅ Binary/APK tools  
✅ Text tools  
✅ History panel  

---

# ⚡ Real Features

This project includes:

✅ Local-only processing  
✅ No cloud APIs  
✅ No external AI  
✅ Offline functionality  
✅ Cross-platform support  
✅ Downloadable outputs  

---

# 🌍 Cross Platform Support

Works on:

✅ Windows  
✅ Linux  
✅ macOS  

---

# 🔐 Steganography Engines

# 🖼️ 1. Image LSB Engine

Uses:

```txt
Least Significant Bit encoding
```

inside RGB pixel channels.

---

# 🎵 2. Audio LSB Engine

Modifies:

```txt
PCM sample bytes
```

inside WAV audio.

---

# 🎬 3. Video Free-Box Injection

Injects hidden payloads into:

```txt
MP4 free atoms
```

without affecting playback.

---

# 📦 4. Binary File Injection

Appends hidden payloads after:

```txt
logical EOF
```

for executable and archive formats.

---

# 📄 5. Zero-Width Unicode Engine

Uses invisible characters:

```txt
U+200B
U+200C
U+200D
```

to encode hidden data.

---

# 🧠 Educational Concepts

Learn about:

- steganography
- hidden data encoding
- file structures
- media internals
- LSB encoding
- Unicode tricks
- encryption
- Flask engineering
- SQLite databases
- cybersecurity workflows

---

# 📂 Project Structure

```txt
stegano.py
stegano.db
uploads/
outputs/
README.md
```

---

# 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core backend |
| Flask | Web dashboard |
| SQLite | Logging |
| Pillow | Image processing |
| NumPy | Pixel operations |
| wave | WAV audio handling |
| hashlib | Encryption support |
| threading | Concurrent logging |

---

# 📥 Installation Guide

# 🐍 Step 1 — Install Python

Download Python:

🔗 https://www.python.org/downloads/

IMPORTANT:

Enable:

```txt
Add Python to PATH
```

---

# 📦 Step 2 — Install Required Libraries

```bash
pip install flask pillow numpy
```

---

# 📂 Step 3 — Clone Repository

```bash
git clone https://github.com/mrshrivasta/steganography-tool.git
```

---

# 📁 Step 4 — Open Project Folder

```bash
cd steganography-tool
```

---

# 🚀 Step 5 — Run Application

```bash
python stegano.py
```

---

# 🌐 Step 6 — Open Dashboard

```txt
http://127.0.0.1:5000
```

---

# ⚡ Quick Start

```bash
pip install flask pillow numpy
python stegano.py
```

---

# 🖥️ CLI Usage

# Default Mode

```bash
python stegano.py
```

---

# Custom Port

```bash
python stegano.py --port 8080
```

---

# Custom Database

```bash
python stegano.py --db steg.db
```

---

# Enable Debug Mode

```bash
python stegano.py --debug
```

---

# Full Example

```bash
python stegano.py --host 127.0.0.1 --port 5000 --db steg.db
```

---

# 🌐 Web Dashboard Features

# 🖼️ Image Panel

Supports:

- encode hidden image messages
- decode image secrets
- PNG stego generation

---

# 🎵 Audio Panel

Supports:

- WAV secret embedding
- WAV secret extraction

---

# 🎬 Video Panel

Supports:

- MP4 hidden payloads
- MOV hidden payloads
- video message extraction

---

# 📦 Binary/APK Panel

Supports:

- APK secret injection
- EXE payload hiding
- ZIP hidden messages
- PDF payload injection

---

# 📄 Text Panel

Supports:

- invisible text encoding
- zero-width hidden messages
- invisible Unicode payloads

---

# 📋 History Dashboard

Tracks:

- encode operations
- decode operations
- timestamps
- encryption usage
- file names

---

# 🔐 Encryption System

Uses:

```txt
SHA-256 key stretching
```

combined with:

```txt
XOR symmetric encryption
```

---

# 🧠 Payload Architecture

Payload format:

```txt
[MAGIC HEADER]
[ENCRYPTION FLAG]
[LENGTH]
[PAYLOAD DATA]
```

---

# 📊 Supported Formats

| Category | Supported Formats |
|---|---|
| Images | PNG, BMP, TIFF |
| Audio | WAV |
| Video | MP4, MOV, AVI, MKV |
| Binary | APK, EXE, PDF, ZIP, DLL |
| Text | TXT, Unicode Text |

---

# 🔥 Why This Project?

This is NOT a basic beginner steganography tool.

This project demonstrates:

✅ file internals  
✅ media manipulation  
✅ binary payload injection  
✅ Unicode steganography  
✅ Flask engineering  
✅ encryption workflows  
✅ SQLite logging  

---

# 🌍 Use Cases

Useful for:

- cybersecurity learning
- digital forensics labs
- steganography education
- security research
- ethical hacking practice
- payload analysis
- hidden data experiments

---

# ⚠️ Security Notes

```txt
IMPORTANT:

- Do NOT expose dashboard publicly
- Localhost only
- Use only on files you own
- Hidden payloads may trigger AV scanners
- Some platforms may strip hidden metadata
```

---

# 🛠️ Troubleshooting

# ❌ Python not recognized

Reinstall Python and enable:

```txt
Add Python to PATH
```

---

# ❌ Flask missing

```bash
pip install flask
```

---

# ❌ Pillow missing

```bash
pip install pillow numpy
```

---

# ❌ WAV decoding fails

Ensure:

```txt
Input file is PCM WAV
```

---

# ❌ Hidden data not found

Possible reasons:

- wrong password
- corrupted file
- unsupported format
- no embedded payload

---

# 📡 API Endpoint

# `/api/stats`

Returns:

- operation counts
- steganography statistics
- encode/decode metrics

---

# 🚀 Future Improvements

Planned features:

- AES encryption
- drag & drop uploads
- live entropy graphs
- stego detection engine
- metadata analysis
- steganalysis tools
- Docker deployment
- authentication system

---

# 📈 SEO Keywords

Steganography Tool Python, Flask Steganography Dashboard, Image LSB Steganography, Audio Steganography Python, Video Steganography Tool, APK Payload Injection, Binary File Steganography, Zero Width Unicode Steganography, Cybersecurity Python Project, Digital Forensics Tool, Secret Message Hiding Tool, Ethical Hacking Python Project

---

# 🤝 Contributing

Pull requests are welcome.

Steps:

1. Fork repository
2. Create branch
3. Commit changes
4. Push changes
5. Open pull request

---

# ⭐ Support

If you like this project:

⭐ Star the repository  
🍴 Fork the repository  
📢 Share with cybersecurity learners  

---

# 👨‍💻 Author

# Karanam Shrivasta

### 🌐 GitHub

:contentReference[oaicite:0]{index=0}

### 💼 LinkedIn

:contentReference[oaicite:1]{index=1}

---

# 📜 License

MIT License

---

# 📚 Educational Note

This project is intended for:

- cybersecurity students
- digital forensics learners
- ethical hackers
- reverse engineering enthusiasts
- Flask developers
- Python security researchers

---

# 🔥 Fun Fact

This advanced multi-format steganography dashboard runs from:

```txt
One Python file.
```

---

# 📄 Source Reference

Core project includes:

- image LSB steganography
- WAV audio encoding
- MP4 free-box injection
- APK/binary payload injection
- zero-width Unicode text hiding
- Flask dashboard
- SQLite operation logging
- SHA-256 password system
- downloadable outputs :contentReference[oaicite:2]{index=2}

---

<div align="center">

# 🔏 StegaTool

### ⚡ Advanced Steganography Toolkit

### 🚀 Built With Python + Flask

<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=20&pause=1000&color=58A6FF&center=true&vCenter=true&width=1000&lines=Made+By+Karanam+Shrivasta;Advanced+Cybersecurity+Project;Multi-Format+Steganography+Tool;Educational+Security+Research+Platform" />

</div>
