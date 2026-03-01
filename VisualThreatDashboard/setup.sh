#!/bin/bash
# ============================================
# VSTD Project — Auto Setup Script for Kali/Ubuntu WSL
# Run: chmod +x setup.sh && ./setup.sh
# ============================================

set -e
echo "=========================================="
echo "  VSTD — Visual Threat Dashboard Setup"
echo "=========================================="

# ── 1. System packages ──
echo ""
echo "[1/6] Installing system packages..."
sudo apt update
sudo apt install -y python3-pip python3-venv python3-dev nmap postgresql postgresql-contrib curl git

# ── 2. Start PostgreSQL ──
echo ""
echo "[2/6] Setting up PostgreSQL..."
sudo service postgresql start
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='vstd_db'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE vstd_db;"
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'password';" 2>/dev/null
echo "  ✔ PostgreSQL running, database 'vstd_db' ready"

# ── 3. Python virtual environment ──
echo ""
echo "[3/6] Creating Python virtual environment..."
cd /mnt/c/Users/saik2/pranathiMojerProject/VSTD-project/VisualThreatDashboard

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "  ✔ Virtual environment created"
else
    echo "  ✔ Virtual environment already exists"
fi

source venv/bin/activate

# ── 4. Install Python dependencies ──
echo ""
echo "[4/6] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "  ✔ All Python packages installed"

# ── 5. Run database migrations ──
echo ""
echo "[5/6] Running database migrations..."
if [ ! -d "alembic/versions" ] || [ -z "$(ls -A alembic/versions/*.py 2>/dev/null)" ]; then
    alembic revision --autogenerate -m "Initial tables"
fi
alembic upgrade head
echo "  ✔ Database tables created"

# ── 6. Done ──
echo ""
echo "=========================================="
echo "  ✔ Setup Complete!"
echo "=========================================="
echo ""
echo "  To start the backend:"
echo "    source venv/bin/activate"
echo "    uvicorn backend.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "  To start the frontend (new terminal):"
echo "    source venv/bin/activate"
echo "    python app.py"
echo ""
echo "  Then open: http://localhost:5000"
echo "=========================================="
