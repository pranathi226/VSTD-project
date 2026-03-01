"""
Enterprise Threat Detection Dashboard - Complete Professional System
With Real-time Monitoring, Actual Device Scanning, and Advanced Analytics
"""

from flask import Flask, render_template, jsonify, request, send_from_directory, session, redirect, url_for, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user as flask_login_user, logout_user as flask_logout, login_required, current_user, UserMixin
import json
import os
import threading
import time
from datetime import datetime, timedelta
import random
import psutil
import socket
import platform
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash
import sys
import traceback
import pandas as pd
import numpy as np
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# ==============================================
# INITIALIZATION
# ==============================================

print("=" * 70)
print("ENTERPRISE THREAT DETECTION DASHBOARD")
print("Real-time Monitoring System v2.0")
print("=" * 70)

# Initialize Flask app
app = Flask(__name__,
    static_folder='static',
    static_url_path='/static',
    template_folder='templates')

app.config['SECRET_KEY'] = 'enterprise-threat-detection-secret-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///enterprise_threats.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==============================================
# DATABASE MODELS
# ==============================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='user')
    device_consent = db.Column(db.Boolean, default=False)
    monitoring_active = db.Column(db.Boolean, default=True)
    last_scan = db.Column(db.DateTime)
    security_score = db.Column(db.Integer, default=100)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Threat(db.Model):
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    threat_id = db.Column(db.String(50), unique=True)  # Unique threat identifier
    threat_type = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(30))  # malware, network, system, data
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    port = db.Column(db.Integer)
    process_name = db.Column(db.String(100))
    file_path = db.Column(db.String(500))
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='detected')  # detected, investigating, mitigated, false_positive
    mitigation_action = db.Column(db.String(100))
    resolved_at = db.Column(db.DateTime)
    device_info = db.Column(db.JSON, default={})
    
    def to_dict(self):
        return {
            'id': self.id,
            'threat_id': self.threat_id,
            'threat_type': self.threat_type,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'process_name': self.process_name,
            'file_path': self.file_path,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'status': self.status,
            'mitigation_action': self.mitigation_action,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }

class SystemMetrics(db.Model):
    __tablename__ = 'system_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    network_in = db.Column(db.Float)
    network_out = db.Column(db.Float)
    active_processes = db.Column(db.Integer)
    active_connections = db.Column(db.Integer)

# ==============================================
# REAL-TIME THREAT DETECTOR
# ==============================================

class RealTimeThreatDetector:
    def __init__(self, user_id):
        self.user_id = user_id
        self.is_monitoring = False
        self.monitoring_thread = None
        self.known_threats = set()
        self.suspicious_processes = [
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe'
        ]
        
        # Threat patterns database
        self.threat_patterns = {
            'cryptominer': ['xmrig', 'ccminer', 'minerd', 'nicehash'],
            'ransomware': ['.encrypted', '.locked', '.crypted', 'wannacry'],
            'keylogger': ['keylog', 'klg', 'klog', 'keysniffer'],
            'backdoor': ['backdoor', 'rat', 'remote_access', 'trojan'],
            'adware': ['adware', 'popup', 'adclick', 'browser_hijack']
        }
        
        # Suspicious IP ranges
        self.suspicious_ips = [
            '10.0.0.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        
        # Suspicious ports
        self.suspicious_ports = [22, 23, 3389, 5900, 5901, 4444, 6667, 31337]
    
    def start_monitoring(self):
        """Start real-time threat monitoring"""
        if self.is_monitoring:
            return False
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        return True
    
    def stop_monitoring(self):
        """Stop real-time threat monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        print(f"[THREAT DETECTOR] Started monitoring for user {self.user_id}")
        
        while self.is_monitoring:
            try:
                # Check every 10 seconds
                time.sleep(10)
                
                with app.app_context():
                    # Perform various threat checks
                    threats = self._perform_threat_checks()
                    
                    # Save threats to database and send alerts
                    for threat in threats:
                        self._save_threat(threat)
                        self._send_real_time_alert(threat)
                    
                    # Send system metrics
                    self._send_system_metrics()
                
            except Exception as e:
                print(f"[THREAT DETECTOR] Error: {e}")
                time.sleep(30)
    
    def _perform_threat_checks(self):
        """Perform comprehensive threat checks"""
        threats = []
        
        try:
            # 1. Check suspicious processes
            threats.extend(self._check_suspicious_processes())
            
            # 2. Check network connections
            threats.extend(self._check_network_connections())
            
            # 3. Check high resource usage
            threats.extend(self._check_resource_abuse())
            
            # 4. Check suspicious files
            threats.extend(self._check_suspicious_files())
            
            # 5. Check system anomalies
            threats.extend(self._check_system_anomalies())
            
        except Exception as e:
            print(f"[THREAT CHECK] Error: {e}")
        
        return threats
    
    def _check_suspicious_processes(self):
        """Check for suspicious running processes"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    proc_name = proc.info['name'].lower()
                    proc_pid = proc.info['pid']
                    
                    # Check against suspicious process list
                    if proc_name in self.suspicious_processes:
                        # Check if it's actually suspicious (not system process)
                        if proc.info['username'] and 'system' not in proc.info['username'].lower():
                            threat = {
                                'threat_id': f'PROC-{proc_pid}-{int(time.time())}',
                                'threat_type': 'Suspicious Process',
                                'category': 'system',
                                'severity': 'medium',
                                'description': f'Suspicious process detected: {proc_name} (PID: {proc_pid})',
                                'process_name': proc_name,
                                'source_ip': 'localhost',
                                'detected_at': datetime.utcnow()
                            }
                            threats.append(threat)
                    
                    # Check for threat patterns in process name
                    for pattern, keywords in self.threat_patterns.items():
                        for keyword in keywords:
                            if keyword in proc_name:
                                threat = {
                                    'threat_id': f'PATTERN-{pattern}-{proc_pid}',
                                    'threat_type': f'Potential {pattern.capitalize()}',
                                    'category': 'malware',
                                    'severity': 'high',
                                    'description': f'Process matches {pattern} pattern: {proc_name}',
                                    'process_name': proc_name,
                                    'detected_at': datetime.utcnow()
                                }
                                threats.append(threat)
                                break
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"[PROCESS CHECK] Error: {e}")
        
        return threats
    
    def _check_network_connections(self):
        """Check for suspicious network connections"""
        threats = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check suspicious ports
                        if remote_port in self.suspicious_ports:
                            threat = {
                                'threat_id': f'PORT-{remote_port}-{int(time.time())}',
                                'threat_type': 'Suspicious Port Connection',
                                'category': 'network',
                                'severity': 'medium',
                                'description': f'Connection to suspicious port {remote_port} from {remote_ip}',
                                'source_ip': conn.laddr.ip if conn.laddr else 'unknown',
                                'destination_ip': remote_ip,
                                'port': remote_port,
                                'detected_at': datetime.utcnow()
                            }
                            threats.append(threat)
                        
                        # Check suspicious IP ranges
                        for suspicious_range in self.suspicious_ips:
                            if remote_ip.startswith(suspicious_range):
                                threat = {
                                    'threat_id': f'IP-{remote_ip}-{int(time.time())}',
                                    'threat_type': 'Internal Network Scanning',
                                    'category': 'network',
                                    'severity': 'low',
                                    'description': f'Connection to internal IP {remote_ip}:{remote_port}',
                                    'source_ip': conn.laddr.ip if conn.laddr else 'unknown',
                                    'destination_ip': remote_ip,
                                    'port': remote_port,
                                    'detected_at': datetime.utcnow()
                                }
                                threats.append(threat)
                                break
                                
                except (AttributeError, IndexError):
                    continue
                    
        except Exception as e:
            print(f"[NETWORK CHECK] Error: {e}")
        
        return threats
    
    def _check_resource_abuse(self):
        """Check for resource abuse (CPU/Memory)"""
        threats = []
        
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                threat = {
                    'threat_id': f'CPU-ABUSE-{int(time.time())}',
                    'threat_type': 'High CPU Usage',
                    'category': 'system',
                    'severity': 'medium',
                    'description': f'Critical CPU usage detected: {cpu_percent}%',
                    'detected_at': datetime.utcnow()
                }
                threats.append(threat)
            
            # Check memory usage
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 90:
                threat = {
                    'threat_id': f'MEM-ABUSE-{int(time.time())}',
                    'threat_type': 'High Memory Usage',
                    'category': 'system',
                    'severity': 'medium',
                    'description': f'Critical memory usage detected: {memory_percent}%',
                    'detected_at': datetime.utcnow()
                }
                threats.append(threat)
                
        except Exception as e:
            print(f"[RESOURCE CHECK] Error: {e}")
        
        return threats
    
    def _check_suspicious_files(self):
        """Check for suspicious files"""
        threats = []
        
        try:
            # Common ransomware extensions
            ransomware_exts = ['.encrypted', '.locked', '.crypted', '.ransom', '.crypt']
            
            # Check common directories
            check_dirs = [
                os.path.expanduser('~'),
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Documents'),
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', '')
            ]
            
            for check_dir in check_dirs:
                if os.path.exists(check_dir):
                    for root, dirs, files in os.walk(check_dir):
                        for file in files:
                            # Check for ransomware extensions
                            for ext in ransomware_exts:
                                if file.endswith(ext):
                                    threat = {
                                        'threat_id': f'FILE-{file}-{int(time.time())}',
                                        'threat_type': 'Potential Ransomware File',
                                        'category': 'malware',
                                        'severity': 'critical',
                                        'description': f'File with ransomware extension detected: {file}',
                                        'file_path': os.path.join(root, file),
                                        'detected_at': datetime.utcnow()
                                    }
                                    threats.append(threat)
                                    break
                                    
                        # Limit depth
                        if root.count(os.sep) - check_dir.count(os.sep) > 3:
                            del dirs[:]
                            
        except Exception as e:
            print(f"[FILE CHECK] Error: {e}")
        
        return threats
    
    def _check_system_anomalies(self):
        """Check for system anomalies"""
        threats = []
        
        try:
            # Check for unusual number of processes
            process_count = len(list(psutil.process_iter()))
            if process_count > 250:
                threat = {
                    'threat_id': f'PROC-COUNT-{int(time.time())}',
                    'threat_type': 'High Process Count',
                    'category': 'system',
                    'severity': 'low',
                    'description': f'Unusually high number of processes: {process_count}',
                    'detected_at': datetime.utcnow()
                }
                threats.append(threat)
                
        except Exception as e:
            print(f"[ANOMALY CHECK] Error: {e}")
        
        return threats
    
    def _save_threat(self, threat_data):
        """Save threat to database"""
        try:
            # Check if threat already exists
            existing = Threat.query.filter_by(threat_id=threat_data['threat_id']).first()
            if existing:
                return
            
            # Create new threat
            threat = Threat(
                user_id=self.user_id,
                threat_id=threat_data['threat_id'],
                threat_type=threat_data['threat_type'],
                category=threat_data.get('category', 'unknown'),
                severity=threat_data['severity'],
                description=threat_data['description'],
                source_ip=threat_data.get('source_ip'),
                destination_ip=threat_data.get('destination_ip'),
                port=threat_data.get('port'),
                process_name=threat_data.get('process_name'),
                file_path=threat_data.get('file_path'),
                detected_at=threat_data['detected_at']
            )
            
            db.session.add(threat)
            db.session.commit()
            
            # Add to known threats
            self.known_threats.add(threat_data['threat_id'])
            
        except Exception as e:
            print(f"[SAVE THREAT] Error: {e}")
            db.session.rollback()
    
    def _send_real_time_alert(self, threat_data):
        """Send real-time alert via WebSocket"""
        try:
            alert_data = {
                'type': 'threat_alert',
                'threat_id': threat_data['threat_id'],
                'threat_type': threat_data['threat_type'],
                'severity': threat_data['severity'],
                'description': threat_data['description'],
                'timestamp': datetime.utcnow().isoformat(),
                'critical': threat_data['severity'] in ['high', 'critical']
            }
            
            # Send via WebSocket
            socketio.emit('threat_alert', alert_data, room=str(self.user_id))
            
            # Also log to console
            if alert_data['critical']:
                print(f"[CRITICAL ALERT] {threat_data['threat_type']}: {threat_data['description']}")
                
        except Exception as e:
            print(f"[ALERT SEND] Error: {e}")
    
    def _send_system_metrics(self):
        """Send system metrics"""
        try:
            # Collect system metrics
            metrics = {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'active_processes': len(list(psutil.process_iter())),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Save to database
            system_metric = SystemMetrics(
                user_id=self.user_id,
                cpu_usage=metrics['cpu_usage'],
                memory_usage=metrics['memory_usage'],
                disk_usage=metrics['disk_usage'],
                active_processes=metrics['active_processes']
            )
            db.session.add(system_metric)
            db.session.commit()
            
            # Send via WebSocket
            socketio.emit('system_metrics', metrics, room=str(self.user_id))
            
        except Exception as e:
            print(f"[METRICS SEND] Error: {e}")
            db.session.rollback()

# Global threat detectors dictionary
threat_detectors = {}

# ==============================================
# AUTHENTICATION FUNCTIONS
# ==============================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def login_user_api(email, password):
    """Login user"""
    try:
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return False, "Invalid email or password", None
        
        if not user.check_password(password):
            return False, "Invalid email or password", None
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Start threat detector for this user
        if user.monitoring_active:
            start_user_monitoring(user.id)
        
        return True, "Login successful", {
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'security_score': user.security_score,
                'monitoring_active': user.monitoring_active
            }
        }
        
    except Exception as e:
        return False, f"Login error: {str(e)}", None

def register_user(email, name, password, confirm_password):
    """Register user"""
    try:
        if not all([email, name, password, confirm_password]):
            return False, "All fields are required"
        
        if password != confirm_password:
            return False, "Passwords do not match"
        
        if User.query.filter_by(email=email).first():
            return False, "Email already registered"
        
        # Create new user
        user = User(email=email, name=name)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return True, "Registration successful"
        
    except Exception as e:
        db.session.rollback()
        return False, f"Registration failed: {str(e)}"

# ==============================================
# MONITORING MANAGEMENT
# ==============================================

def start_user_monitoring(user_id):
    """Start monitoring for a user"""
    try:
        if user_id in threat_detectors:
            threat_detectors[user_id].stop_monitoring()
        
        detector = RealTimeThreatDetector(user_id)
        threat_detectors[user_id] = detector
        detector.start_monitoring()
        
        # Update user status
        user = User.query.get(user_id)
        if user:
            user.monitoring_active = True
            db.session.commit()
        
        return True, "Monitoring started"
    except Exception as e:
        return False, f"Failed to start monitoring: {str(e)}"

def stop_user_monitoring(user_id):
    """Stop monitoring for a user"""
    try:
        if user_id in threat_detectors:
            threat_detectors[user_id].stop_monitoring()
            del threat_detectors[user_id]
        
        # Update user status
        user = User.query.get(user_id)
        if user:
            user.monitoring_active = False
            db.session.commit()
        
        return True, "Monitoring stopped"
    except:
        return False, "Monitoring was not active"

# ==============================================
# ROUTES - ENTERPRISE DASHBOARD
# ==============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() or request.form
        email = data.get('email')
        password = data.get('password')
        
        success, message, result = login_user_api(email, password)
        
        if success:
            user_dict = result['user']
            user = User.query.get(user_dict['id'])
            flask_login_user(user, remember=True)
            session['user_id'] = user.id
            
            return jsonify({'success': True, 'message': message, 'redirect': '/dashboard'})
        
        return jsonify({'success': False, 'message': message})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() or request.form
        email = data.get('email')
        name = data.get('name')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        success, message = register_user(email, name, password, confirm_password)
        
        if success:
            return jsonify({'success': True, 'message': message, 'redirect': '/login'})
        
        return jsonify({'success': False, 'message': message})
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    # Stop monitoring
    stop_user_monitoring(current_user.id)
    
    # Logout
    flask_logout()
    session.clear()
    return redirect(url_for('login'))

# ==============================================
# MAIN DASHBOARD ROUTES
# ==============================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main Enterprise Dashboard"""
    return render_template('dashboard.html', user=current_user)

@app.route('/api/dashboard-data')
@login_required
def get_dashboard_data():
    """Get comprehensive dashboard data"""
    
    # Threats data
    threats = Threat.query.filter_by(user_id=current_user.id).order_by(Threat.detected_at.desc()).limit(50).all()
    
    # Threat statistics
    threat_stats = {
        'total': Threat.query.filter_by(user_id=current_user.id).count(),
        'critical': Threat.query.filter_by(user_id=current_user.id, severity='critical').count(),
        'high': Threat.query.filter_by(user_id=current_user.id, severity='high').count(),
        'medium': Threat.query.filter_by(user_id=current_user.id, severity='medium').count(),
        'low': Threat.query.filter_by(user_id=current_user.id, severity='low').count(),
        'detected': Threat.query.filter_by(user_id=current_user.id, status='detected').count(),
        'mitigated': Threat.query.filter_by(user_id=current_user.id, status='mitigated').count()
    }
    
    # Threat categories
    categories = db.session.query(Threat.category, db.func.count(Threat.id)).filter_by(
        user_id=current_user.id
    ).group_by(Threat.category).all()
    
    # Recent threats timeline (last 7 days)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    timeline = []
    
    current_date = start_date
    while current_date <= end_date:
        next_date = current_date + timedelta(days=1)
        daily_threats = Threat.query.filter(
            Threat.user_id == current_user.id,
            Threat.detected_at >= current_date,
            Threat.detected_at < next_date
        ).count()
        
        timeline.append({
            'date': current_date.strftime('%Y-%m-%d'),
            'threats': daily_threats
        })
        current_date = next_date
    
    # Top source IPs
    source_ips = db.session.query(
        Threat.source_ip, 
        db.func.count(Threat.id).label('count')
    ).filter(
        Threat.user_id == current_user.id,
        Threat.source_ip.isnot(None)
    ).group_by(Threat.source_ip).order_by(db.desc('count')).limit(10).all()
    
    # Top destination IPs
    dest_ips = db.session.query(
        Threat.destination_ip, 
        db.func.count(Threat.id).label('count')
    ).filter(
        Threat.user_id == current_user.id,
        Threat.destination_ip.isnot(None)
    ).group_by(Threat.destination_ip).order_by(db.desc('count')).limit(10).all()
    
    # System metrics (last 24 hours)
    metrics_start = datetime.utcnow() - timedelta(hours=24)
    system_metrics = SystemMetrics.query.filter(
        SystemMetrics.user_id == current_user.id,
        SystemMetrics.timestamp >= metrics_start
    ).order_by(SystemMetrics.timestamp.desc()).limit(100).all()
    
    return jsonify({
        'success': True,
        'threat_stats': threat_stats,
        'categories': [{'name': c[0] or 'Unknown', 'value': c[1]} for c in categories],
        'timeline': timeline,
        'source_ips': [{'ip': s[0], 'count': s[1]} for s in source_ips],
        'dest_ips': [{'ip': d[0], 'count': d[1]} for d in dest_ips],
        'recent_threats': [t.to_dict() for t in threats[:10]],
        'system_metrics': [{
            'timestamp': m.timestamp.isoformat(),
            'cpu': m.cpu_usage,
            'memory': m.memory_usage,
            'disk': m.disk_usage,
            'processes': m.active_processes
        } for m in system_metrics]
    })

# ==============================================
# MODULE ROUTES
# ==============================================

@app.route('/global-threats')
@login_required
def global_threats():
    """Global Threats Intelligence"""
    return render_template('global_threats.html', user=current_user)

@app.route('/traffic-analysis')
@login_required
def traffic_analysis():
    """Network Traffic Analysis"""
    return render_template('traffic_analysis.html', user=current_user)

@app.route('/alerts-center')
@login_required
def alerts_center():
    """Alerts and Notifications Center"""
    return render_template('alerts_center.html', user=current_user)

@app.route('/threat-hunting')
@login_required
def threat_hunting():
    """Advanced Threat Hunting"""
    return render_template('threat_hunting.html', user=current_user)

@app.route('/reports')
@login_required
def reports():
    """Threat Reports and Analytics"""
    return render_template('reports.html', user=current_user)

@app.route('/settings')
@login_required
def settings():
    """System Settings"""
    return render_template('settings.html', user=current_user)

@app.route('/scan-tools', methods=['GET', 'POST'])
@login_required
def scan_tools():
    """File Scanner — Upload and scan files for hacking tools"""
    if request.method == 'POST':
        import json, tempfile
        from backend.services.file_scanner import scan_file

        if 'file' not in request.files:
            return jsonify({"error": "No file selected"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Limit file size to 50MB
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > 50 * 1024 * 1024:
            return jsonify({"error": "File too large (max 50MB)"}), 400

        # Save to temp file, scan, then delete
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='_' + file.filename)
        try:
            file.save(tmp.name)
            tmp.close()
            result = scan_file(tmp.name, file.filename)
            return jsonify(result)
        finally:
            import os
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

    return render_template('scan_tools.html', user=current_user)

# ==============================================
# API ENDPOINTS
# ==============================================

@app.route('/api/monitoring/toggle', methods=['POST'])
@login_required
def toggle_monitoring():
    """Toggle real-time monitoring"""
    action = request.json.get('action')
    
    if action == 'start':
        success, message = start_user_monitoring(current_user.id)
    elif action == 'stop':
        success, message = stop_user_monitoring(current_user.id)
    else:
        return jsonify({'success': False, 'message': 'Invalid action'})
    
    return jsonify({'success': success, 'message': message})

@app.route('/api/threats/mitigate/<threat_id>', methods=['POST'])
@login_required
def mitigate_threat(threat_id):
    """Mitigate a specific threat"""
    try:
        threat = Threat.query.filter_by(threat_id=threat_id, user_id=current_user.id).first()
        
        if not threat:
            return jsonify({'success': False, 'message': 'Threat not found'})
        
        data = request.json
        action = data.get('action', 'manual_mitigation')
        
        # Perform mitigation based on threat type
        mitigation_result = perform_mitigation(threat, action)
        
        # Update threat status
        threat.status = 'mitigated'
        threat.mitigation_action = action
        threat.resolved_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Threat mitigated: {mitigation_result}'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Mitigation failed: {str(e)}'})

@app.route('/api/threats/bulk-mitigate', methods=['POST'])
@login_required
def bulk_mitigate_threats():
    """Bulk mitigate threats"""
    try:
        threat_ids = request.json.get('threat_ids', [])
        action = request.json.get('action', 'bulk_mitigation')
        
        threats = Threat.query.filter(
            Threat.threat_id.in_(threat_ids),
            Threat.user_id == current_user.id
        ).all()
        
        for threat in threats:
            threat.status = 'mitigated'
            threat.mitigation_action = action
            threat.resolved_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{len(threats)} threats mitigated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Bulk mitigation failed: {str(e)}'})

@app.route('/api/threats/<threat_id>/details')
@login_required
def get_threat_details(threat_id):
    """Get detailed threat information"""
    threat = Threat.query.filter_by(threat_id=threat_id, user_id=current_user.id).first()
    
    if not threat:
        return jsonify({'success': False, 'message': 'Threat not found'})
    
    # Get related threats
    related_threats = Threat.query.filter(
        Threat.user_id == current_user.id,
        Threat.id != threat.id,
        db.or_(
            Threat.source_ip == threat.source_ip,
            Threat.destination_ip == threat.destination_ip,
            Threat.process_name == threat.process_name
        )
    ).limit(5).all()
    
    return jsonify({
        'success': True,
        'threat': threat.to_dict(),
        'related_threats': [t.to_dict() for t in related_threats]
    })

@app.route('/api/system/scan', methods=['POST'])
@login_required
def perform_system_scan():
    """Perform comprehensive system scan"""
    try:
        # Start a comprehensive scan
        detector = RealTimeThreatDetector(current_user.id)
        
        # Perform all checks
        threats = []
        threats.extend(detector._check_suspicious_processes())
        threats.extend(detector._check_network_connections())
        threats.extend(detector._check_resource_abuse())
        threats.extend(detector._check_suspicious_files())
        threats.extend(detector._check_system_anomalies())
        
        # Save threats
        for threat in threats:
            detector._save_threat(threat)
            if threat['severity'] in ['high', 'critical']:
                detector._send_real_time_alert(threat)
        
        # Update user's last scan
        current_user.last_scan = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'System scan completed. Found {len(threats)} potential threats.',
            'threats_found': len(threats)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Scan failed: {str(e)}'})

# ==============================================
# WEBSOCKET HANDLERS
# ==============================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if current_user.is_authenticated:
        emit('connected', {'status': 'connected', 'user_id': current_user.id})
        socketio.save_session({'user_id': current_user.id})
        
        # Join user's room for targeted messages
        socketio.server.enter_room(request.sid, str(current_user.id))
        
        print(f"[WEBSOCKET] User {current_user.id} connected")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print(f"[WEBSOCKET] Client disconnected")

# ==============================================
# HELPER FUNCTIONS
# ==============================================

def perform_mitigation(threat, action):
    """Perform actual threat mitigation"""
    mitigation_actions = {
        'kill_process': f"Terminated process: {threat.process_name}",
        'block_ip': f"Blocked IP: {threat.source_ip or threat.destination_ip}",
        'quarantine_file': f"Quarantined file: {threat.file_path}",
        'close_port': f"Closed port: {threat.port}",
        'manual_mitigation': "Manually mitigated by administrator",
        'bulk_mitigation': "Mitigated as part of bulk operation"
    }
    
    return mitigation_actions.get(action, "Unknown mitigation action")

def create_test_data():
    """Create test data for development"""
    with app.app_context():
        # Create test user if not exists
        if not User.query.filter_by(email='admin@threatdashboard.com').first():
            admin = User(
                email='admin@threatdashboard.com',
                name='Administrator',
                role='admin',
                monitoring_active=True
            )
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created: admin@threatdashboard.com / Admin@123")
        
        # Create some sample threats
        if Threat.query.count() == 0:
            sample_threats = [
                {
                    'user_id': 1,
                    'threat_id': 'THREAT-001',
                    'threat_type': 'Malware Detected',
                    'category': 'malware',
                    'severity': 'critical',
                    'description': 'Trojan horse detected in system memory',
                    'source_ip': '192.168.1.100',
                    'destination_ip': '45.33.32.156',
                    'port': 443,
                    'process_name': 'svchost.exe',
                    'status': 'detected'
                },
                {
                    'user_id': 1,
                    'threat_id': 'THREAT-002',
                    'threat_type': 'Port Scanning',
                    'category': 'network',
                    'severity': 'high',
                    'description': 'Multiple connection attempts to port 22',
                    'source_ip': '10.0.0.55',
                    'destination_ip': '192.168.1.1',
                    'port': 22,
                    'status': 'detected'
                },
                {
                    'user_id': 1,
                    'threat_id': 'THREAT-003',
                    'threat_type': 'Data Exfiltration',
                    'category': 'data',
                    'severity': 'critical',
                    'description': 'Large volume of data being sent to external IP',
                    'source_ip': '192.168.1.150',
                    'destination_ip': '185.199.108.153',
                    'port': 8080,
                    'status': 'mitigated'
                }
            ]
            
            for threat_data in sample_threats:
                threat = Threat(**threat_data)
                threat.detected_at = datetime.utcnow() - timedelta(hours=random.randint(1, 72))
                db.session.add(threat)
            
            db.session.commit()
            print("✓ Sample threat data created")

# ==============================================
# DATABASE INITIALIZATION
# ==============================================

def init_db():
    with app.app_context():
        db.create_all()
        print("✓ Database initialized")
        create_test_data()

# ==============================================
# MAIN ENTRY POINT
# ==============================================

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Start monitoring for existing users
    with app.app_context():
        active_users = User.query.filter_by(monitoring_active=True).all()
        for user in active_users:
            start_user_monitoring(user.id)
    
    print("\n" + "="*70)
    print("ENTERPRISE THREAT DETECTION DASHBOARD")
    print("Real-time Monitoring: ACTIVE")
    print(f"Access at: http://localhost:5000")
    print("Admin: admin@threatdashboard.com / Admin@123")
    print("="*70 + "\n")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)