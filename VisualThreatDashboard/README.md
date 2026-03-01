# 🛡 Visual Threat Detection Dashboard (VSTD)

Enterprise-grade cybersecurity dashboard with real-time threat monitoring, multi-tool scanning, and encrypted API key management.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?logo=fastapi)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-4169E1?logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Features

- **Real-time Threat Dashboard** — Live monitoring with threat timeline, risk categories, and security score
- **Multi-tool Scanning** — Nmap, OWASP ZAP, VirusTotal API, and Custom Python analyzer
- **Encrypted API Key Storage** — Fernet encryption with masked display
- **JWT Authentication** — Secure token-based auth for all API endpoints
- **Async Scanning** — Background task processing with live status polling
- **Threat Scoring** — Automated 0-100 threat score with Low/Medium/High risk levels
- **Scan History** — Persistent database storage with full audit trail
- **Device Scanner** — System-level hardware and process monitoring

---

## 🏗 Architecture

```
┌─────────────────────┐     ┌─────────────────────┐
│   Flask Frontend    │────▶│   FastAPI Backend    │
│   (Port 5000)       │     │   (Port 8000)        │
│                     │     │                      │
│  • Dashboard        │     │  • /auth (JWT)       │
│  • Scan Tools Page  │     │  • /scans (CRUD)     │
│  • Settings Page    │     │  • /api-keys (CRUD)  │
│  • Global Threats   │     │  • /tools (list)     │
│  • Traffic Analysis │     │  • /health           │
│  • Reports          │     │                      │
└─────────────────────┘     └──────────┬───────────┘
                                       │
                            ┌──────────▼───────────┐
                            │  PostgreSQL / SQLite  │
                            │  (vstd_db)            │
                            └──────────────────────┘
```

---

## 📁 Project Structure

```
VisualThreatDashboard/
├── app.py                    # Flask frontend server
├── backend/
│   ├── main.py               # FastAPI entry point
│   ├── database.py           # SQLAlchemy engine (PostgreSQL + SQLite fallback)
│   ├── models.py             # ORM models (User, ScanResult, APIKey, Tool)
│   ├── schemas.py            # Pydantic validation schemas
│   ├── auth.py               # JWT authentication
│   ├── routers/
│   │   ├── scans.py          # POST /scans/scan, GET /scans
│   │   └── api_keys.py       # POST/GET/DELETE /api-keys
│   └── services/
│       ├── scanner.py        # Nmap, ZAP, VirusTotal, Custom analyzer
│       └── crypto.py         # Fernet encryption for API keys
├── templates/                # Jinja2 HTML templates
│   ├── base.html
│   ├── scan_tools.html       # Multi-tool scanning page
│   ├── settings.html         # Settings + API key management
│   └── ...
├── alembic/                  # Database migrations
├── requirements.txt
├── setup.sh                  # One-click setup script
├── .env                      # Environment variables
└── WSL_SETUP.md             # WSL installation guide
```

---

## ⚡ Quick Start (One Command)

### On WSL (Kali/Ubuntu):
```bash
cd /mnt/c/Users/saik2/pranathiMojerProject/VSTD-project/VisualThreatDashboard
chmod +x setup.sh
./setup.sh
```

This installs everything: system packages, PostgreSQL, Python venv, pip dependencies, and runs migrations.

---

## 🔧 Manual Setup

### Prerequisites

| Tool       | Version | Required |
|------------|---------|----------|
| Python     | 3.10+   | ✅       |
| PostgreSQL | 13+     | Optional (SQLite fallback) |
| Nmap       | 7+      | Optional (for port scanning) |
| pip        | 21+     | ✅       |

### Step 1: Clone & Navigate

```bash
git clone <your-repo-url>
cd VisualThreatDashboard
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv

# Linux/Mac
source venv/bin/activate

# Windows PowerShell
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment

```bash
# Edit .env file with your settings
cp .env.example .env   # or edit existing .env
```

Key variables in `.env`:
```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/vstd_db
SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-key
ENCRYPTION_KEY=your-encryption-key-for-api-keys
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

> **Note:** If PostgreSQL is not available, the app automatically uses SQLite (`instance/vstd.db`).

### Step 5: Setup Database

```bash
# If using PostgreSQL:
sudo service postgresql start
sudo -u postgres psql -c "CREATE DATABASE vstd_db;"

# Run migrations
alembic revision --autogenerate -m "Initial tables"
alembic upgrade head
```

### Step 6: Start the Servers

**Terminal 1 — FastAPI Backend:**
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Flask Frontend:**
```bash
python app.py
```

### Step 7: Open in Browser

- **Dashboard:** http://localhost:5000
- **API Docs:** http://localhost:8000/docs

---

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login → JWT token |
| GET | `/auth/me` | Get current user |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scans/scan` | Start a new scan |
| GET | `/scans` | Scan history (paginated) |
| GET | `/scans/{id}` | Single scan result |

### API Keys
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api-keys` | Save encrypted API key |
| GET | `/api-keys` | List keys (masked) |
| DELETE | `/api-keys/{id}` | Delete a key |

### Other
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/tools` | List available scan tools |
| GET | `/health` | Health check |

---

## 🔍 Scanning Tools

| Tool | Description | Requirements |
|------|-------------|-------------|
| **Nmap** | Port scanning & service detection | `nmap` installed |
| **OWASP ZAP** | Web vulnerability scanning | `zap-cli` installed |
| **VirusTotal** | Threat intelligence API lookup | API key in `.env` |
| **Custom Analyzer** | DNS resolution, port probing, SSL certificate check | None (built-in Python) |

### Example: Run a Scan

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test@1234"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. Run scan
curl -X POST http://localhost:8000/scans/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","selected_tool":"custom"}'

# 3. View results
curl http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🗄 Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `users` | User accounts with roles and auth data |
| `scan_results` | Scan output, threat scores, risk levels |
| `api_keys` | Encrypted third-party API keys |
| `tools` | Available scanning tools |

### `scan_results` Columns
`id` · `target` · `selected_tool` · `raw_output` · `parsed_result` · `threat_score` · `risk_level` · `status` · `created_at` · `user_id`

---

## 🔐 Security Features

- **JWT Authentication** — All API endpoints require Bearer token
- **Password Hashing** — Werkzeug PBKDF2-SHA256
- **API Key Encryption** — Fernet symmetric encryption (AES-128-CBC)
- **Input Sanitization** — Regex validation prevents command injection
- **CORS Protection** — Configurable allowed origins
- **Masked Display** — API keys shown as `abc1**********y456`

---

## 🛠 Development

### Run with Hot Reload
```bash
uvicorn backend.main:app --reload --port 8000
```

### Generate New Migration
```bash
alembic revision --autogenerate -m "description of change"
alembic upgrade head
```

### Run on Different Ports
```bash
# Backend on port 8001
uvicorn backend.main:app --port 8001

# Update API_BASE in scan_tools.html and settings.html to match
```

---

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Flask + Jinja2 + Bootstrap 5 + Chart.js |
| Backend API | FastAPI + Pydantic |
| Database | PostgreSQL (prod) / SQLite (dev) |
| ORM | SQLAlchemy 2.0 |
| Migrations | Alembic |
| Auth | JWT (python-jose) |
| Encryption | Fernet (cryptography) |
| HTTP Client | httpx (async) |
| Scanning | Nmap, OWASP ZAP, VirusTotal API |

---

## 👤 Default Login

After running `setup.sh` or registering via the app:

| Field | Value |
|-------|-------|
| Email | admin@threatdashboard.com |
| Password | Admin@123 |

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
