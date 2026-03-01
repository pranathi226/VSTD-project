# WSL Kali Linux Setup Guide — Visual Threat Detection Dashboard

Complete installation guide for running the VSTD project on **Kali Linux (WSL)**.

---

## 1. System Update

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 2. Python (Use Built-in Python 3)

Kali already includes Python 3. Just verify and install pip + venv:

```bash
python3 --version   # Should show 3.12+ on Kali

# Install pip and venv
sudo apt install -y python3-pip python3-venv python3-dev
```

> **Note:** Do NOT try to install Python 3.11 from deadsnakes PPA — that only works on Ubuntu.

---

## 3. PostgreSQL

```bash
sudo apt install -y postgresql postgresql-contrib

# Start PostgreSQL
sudo service postgresql start

# Create database and set password
sudo -u postgres psql -c "CREATE DATABASE vstd_db;"
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'password';"

# Verify
sudo -u postgres psql -c "\l"
```

---

## 4. Nmap (Pre-installed on Kali)

```bash
nmap --version   # Should already be installed on Kali
# If not: sudo apt install -y nmap
```

---

## 5. Project Setup

### Navigate to Project
```bash
cd /mnt/c/Users/saik2/pranathiMojerProject/VSTD-project/VisualThreatDashboard
```

### Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Configure Environment
```bash
# Edit .env file — verify these settings:
nano .env

# DATABASE_URL=postgresql://postgres:password@localhost:5432/vstd_db
# SECRET_KEY=your-secret-key
# JWT_SECRET=your-jwt-secret
# ENCRYPTION_KEY=your-encryption-key-here!
# VIRUSTOTAL_API_KEY=your-virustotal-key
```

---

## 6. Run Database Migrations

```bash
# Make sure PostgreSQL is running
sudo service postgresql start

# Generate and apply migration
alembic revision --autogenerate -m "Initial tables"
alembic upgrade head
```

---

## 7. Running the Application

### Terminal 1 — FastAPI Backend (port 8000)
```bash
source venv/bin/activate
cd /mnt/c/Users/saik2/pranathiMojerProject/VSTD-project/VisualThreatDashboard
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Terminal 2 — Flask Frontend (port 5000)
```bash
source venv/bin/activate
cd /mnt/c/Users/saik2/pranathiMojerProject/VSTD-project/VisualThreatDashboard
python app.py
```

---

## 8. Verify Everything Works

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. Register user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","name":"Test","password":"Test@1234","confirm_password":"Test@1234"}'

# 3. Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test@1234"}'

# 4. Open browser: http://localhost:5000
```

---

## Quick Reference

| Service    | Start                          | Stop         |
|------------|--------------------------------|--------------|
| PostgreSQL | `sudo service postgresql start`| `sudo service postgresql stop` |
| FastAPI    | `uvicorn backend.main:app --reload` | `Ctrl+C` |
| Flask      | `python app.py`                | `Ctrl+C`     |
