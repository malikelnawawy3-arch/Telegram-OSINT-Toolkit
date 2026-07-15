# Telegram OSINT Toolkit

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Telegram](https://img.shields.io/badge/Telegram-OSINT-orange)

**High-end, local, production-ready Telegram intelligence gathering tool** built for **OSINT**, cybersecurity research, law enforcement, and military intelligence applications.

Developed with **Telethon** — supports **proxy/Tor**, **bulk monitoring**, advanced keyword search, full chat exports, member enumeration, and persistent SQLite storage.

---

## ✨ Features

- 🔍 **Advanced Keyword Search** (single + bulk across multiple channels/groups)
- 📡 **Bulk Monitoring** from a list of channels (TXT/JSON)
- 📤 **Full Chat Export** (JSON / CSV) with optional media + EXIF metadata
- 👥 **Member Enumeration** & detailed user profiling
- 🌐 **Proxy / Tor Support** (SOCKS5, HTTP) for OPSEC
- 💾 **SQLite Database** for long-term searchable archive
- 📊 **Beautiful Rich CLI** with progress bars and tables
- ⚡ Rate-limit aware with built-in safety delays
- 🔄 Persistent session (no repeated logins)

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/AnuragRoy485/Telegram-OSINT-Toolkit.git
cd Telegram-OSINT-Toolkit
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API Credentials
```bash
cp config.example.env .env
```

Edit `.env` with your credentials:
```env
TG_API_ID=your_api_id
TG_API_HASH=your_api_hash
```

**Get API ID & Hash**: [https://my.telegram.org](https://my.telegram.org) → API development tools

---

## 📖 Usage Examples

### Basic Search
```bash
python telegram_osint.py search @durov telegram --limit 50
```

### Bulk Search (Recommended for Intelligence)
```bash
python telegram_osint.py bulk-search channels.txt "malware OR APT36 OR ransomware" --limit 100 --since 2026-01-01 --output intel_report.json
```

### Export Chat History
```bash
python telegram_osint.py export @channelname --limit 2000 --format json --media
```

### Enumerate Group Members
```bash
python telegram_osint.py members @groupname --limit 500
```

### User Profile Lookup
```bash
python telegram_osint.py profile @username
```

### With Proxy / Tor
```bash
python telegram_osint.py bulk-search channels.txt "keyword" --proxy socks5://127.0.0.1:9050
```

---

## 📁 Project Structure

```
Telegram-OSINT-Toolkit/
├── telegram_osint.py          # Main Script
├── requirements.txt
├── config.example.env
├── .gitignore
├── README.md
└── media_* /                  # Auto-created for downloaded media
```

---

## ⚠️ Important Notes

- Use **only on public channels/groups** or those you are authorized to access.
- Respect Telegram's **Terms of Service** and rate limits.
- For sensitive operations, always use a dedicated account + proxy/Tor.
- This tool is intended for **defensive, research, and law enforcement** purposes.

---

## 🛠️ Technologies Used

- **Telethon** — Telegram MTProto Client
- **Rich** — Beautiful terminal interface
- **SQLite** — Local persistent storage
- Python 3.8+

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Anurag Roy**  
Cybersecurity Researcher  
GitHub: [@AnuragRoy485](https://github.com/AnuragRoy485)

---

⭐ **Star** this repository if you find it useful!  
🍴 Feel free to **Fork** and contribute improvements.

For feature requests, bug reports, or custom integrations (Docker + Tor, automated reporting, etc.), open an **Issue** or **Pull Request**.
