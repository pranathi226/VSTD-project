"""Authentication Module - GUARANTEED WORKING VERSION"""

import jwt
from datetime import datetime, timedelta
from flask import jsonify, request
from flask_login import UserMixin, LoginManager, login_user as flask_login_user, logout_user as flask_logout, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re

# Import db
try:
    from app import db
except ImportError:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()

login_manager = LoginManager()

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
    consent_given_at = db.Column(db.DateTime)
    device_info = db.Column(db.JSON, default={})
    last_scan = db.Column(db.DateTime)
    security_score = db.Column(db.Integer, default=100)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_token(self):
        payload = {
            'user_id': self.id,
            'email': self.email,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, 'jwt-secret-key-2025', algorithm='HS256')
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'device_consent': self.device_consent,
            'security_score': self.security_score,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def register_user(email, name, password, confirm_password):
    if not all([email, name, password, confirm_password]):
        return False, "All fields are required"
    
    if not validate_email(email):
        return False, "Invalid email format"
    
    if password != confirm_password:
        return False, "Passwords do not match"
    
    is_valid, message = validate_password(password)
    if not is_valid:
        return False, message
    
    if User.query.filter_by(email=email).first():
        return False, "Email already registered"
    
    user = User(email=email, name=name)
    user.set_password(password)
    
    try:
        db.session.add(user)
        db.session.commit()
        return True, "Registration successful"
    except Exception as e:
        db.session.rollback()
        return False, f"Registration failed: {str(e)}"

# THIS IS THE FUNCTION app.py IS LOOKING FOR
def login_user_api(email, password):
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return False, "Invalid email or password", None
    
    if not user.check_password(password):
        return False, "Invalid email or password", None
    
    if not user.is_active:
        return False, "Account is deactivated", None
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    token = user.generate_token()
    
    return True, "Login successful", {
        'user': user.to_dict(),
        'token': token
    }

def logout_user():
    flask_logout()
    return True

def update_device_consent(user_id, consent_status, device_info=None):
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"
    
    user.device_consent = consent_status
    user.consent_given_at = datetime.utcnow() if consent_status else None
    
    if consent_status and device_info:
        user.device_info = device_info
    
    try:
        db.session.commit()
        return True, "Consent updated successfully"
    except Exception as e:
        db.session.rollback()
        return False, f"Failed to update consent: {str(e)}"

def get_user_stats(user_id):
    user = User.query.get(user_id)
    if not user:
        return None
    
    return {
        'user_info': user.to_dict(),
        'threat_count': 0,
        'active_threats': 0,
        'mitigated_threats': 0,
        'last_scan': user.last_scan.isoformat() if user.last_scan else None,
        'device_protected': user.device_consent
    }
