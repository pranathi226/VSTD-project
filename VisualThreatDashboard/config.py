"""
Configuration settings for Visual Threat Detection Dashboard
"""

import os

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'threat-detection-secret-key-2025'
    DEBUG = True
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = 'sqlite:///threat_detection.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    THREATS_FILE = os.path.join(DATA_DIR, 'threats.json')
    LOGS_FILE = os.path.join(DATA_DIR, 'logs.json')
    MODEL_FILE = os.path.join(BASE_DIR, 'model/saved/threat_model.pkl')
    
    # Authentication settings
    JWT_SECRET_KEY = 'jwt-secret-key-2025'
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    
    # Detection settings
    DETECTION_THRESHOLD = 0.7
    HIGH_SEVERITY_THRESHOLD = 0.85
    MONITORING_INTERVAL = 30  # seconds
    
    # Device scanning settings
    SCAN_DEPTH = 3  # How deep to scan files (1=shallow, 5=deep)
    MAX_FILE_SIZE = 10485760  # 10MB max file size to scan
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'json', 'log'}
    
    # Threat types
    THREAT_TYPES = [
        "Malware Detection",
        "Suspicious Process",
        "Unauthorized Access",
        "Data Exfiltration",
        "Network Intrusion",
        "System Vulnerability",
        "Privilege Escalation",
        "File Tampering",
        "Registry Modification",
        "Memory Corruption"
    ]
    
    # Severity levels
    SEVERITY_LEVELS = {
        "critical": {"color": "#ef4444", "weight": 1.0},
        "high": {"color": "#f97316", "weight": 0.8},
        "medium": {"color": "#eab308", "weight": 0.5},
        "low": {"color": "#22c55e", "weight": 0.2}
    }
    
    # Security scoring
    SECURITY_SCORE_WEIGHTS = {
        "device_scan": 0.3,
        "network_analysis": 0.3,
        "threat_history": 0.2,
        "user_behavior": 0.2
    }
    
    # Notification settings
    ENABLE_PUSH_NOTIFICATIONS = True
    NOTIFICATION_COOLDOWN = 300  # 5 minutes
    
    # Dashboard settings
    REFRESH_INTERVALS = {
        "stats": 10000,      # 10 seconds
        "threats": 15000,    # 15 seconds
        "logs": 20000,       # 20 seconds
        "network": 30000,    # 30 seconds
        "monitoring": 5000   # 5 seconds for real-time monitoring
    }

# Export configuration
config = Config()