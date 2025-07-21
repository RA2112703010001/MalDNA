import os
import uuid
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Security & Cryptography
import bcrypt
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash

# MongoDB & Validation
from mongoengine import (
    Document, StringField, BooleanField, DateTimeField, ListField, DictField,
    EmbeddedDocument, EmbeddedDocumentField, ValidationError, IntField
)

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --------------------------------------------
# 📌 **Embedded Document: Security Log**
# --------------------------------------------
class SecurityLog(EmbeddedDocument):
    log_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = StringField(required=True, choices=[
        "login_attempt", "password_change", "mfa_setup", "api_key_generated", "suspicious_activity"
    ])
    timestamp = DateTimeField(default=datetime.utcnow)
    ip_address = StringField()
    details = DictField(default={})
    severity = StringField(choices=["low", "medium", "high", "critical"], default="low")

    def clean(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow()

# --------------------------------------------
# 📌 **User Model: Authentication & Security**
# --------------------------------------------
class User(Document):
    user_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    username = StringField(required=True, unique=True, max_length=50)
    email = StringField(required=True, unique=True, regex=r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    password = StringField(required=True)
    role = StringField(choices=["admin", "analyst", "user", "guest"], default="user")
    
    # 🔐 Account Status
    is_active = BooleanField(default=True)
    is_locked = BooleanField(default=False)
    failed_login_attempts = IntField(default=0)
    account_locked_until = DateTimeField()

    # 🧠 Security Enhancements
    password_history = ListField(StringField())  # bcrypt-hashed
    last_password_change = DateTimeField()
    email_verification_attempts = IntField(default=0)
    mfa_verification_attempts = IntField(default=0)

    # 🔑 MFA
    mfa_secret = StringField()
    mfa_enabled = BooleanField(default=False)

    # 🔑 API & Session
    session_tokens = ListField(StringField())
    api_keys = ListField(StringField())

    # ✅ Email Verification
    email_verified = BooleanField(default=False)
    verification_token = StringField()
    verification_token_expiry = DateTimeField()

    # 🔄 Password Reset
    reset_token = StringField()
    reset_token_expiry = DateTimeField()

    # 📊 Logs
    security_logs = ListField(EmbeddedDocumentField(SecurityLog))
    login_history = ListField(DictField())

    # 🔏 Preferences & Permissions
    permissions = ListField(StringField())
    preferences = DictField(default={"notification_preferences": {}, "dashboard_layout": {}, "theme": "default"})

    # 🛡️ Compliance
    gdpr_consent = BooleanField(default=False)
    data_removal_requested = BooleanField(default=False)

    # 📅 Timestamps
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        "indexes": [
            {"fields": ["user_id"], "unique": True},
            {"fields": ["email"], "unique": True},
            {"fields": ["role"]},
            {"fields": ["is_active", "role"]},
            {"fields": ["email_verified", "is_active"]}
        ],
        "ordering": ["-created_at"],
        "strict": True
    }

    # --------------------------------------------
    # 🔐 Password Handling
    # --------------------------------------------
    def clean(self):
        self.updated_at = datetime.utcnow()
        if not self.email:
            raise ValidationError("Email is required")

    def set_password(self, password: str) -> None:
        try:
            self._validate_password(password)
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            if hashed in self.password_history:
                raise ValueError("This password was recently used. Choose a new one.")
            self.password = hashed
            self.last_password_change = datetime.utcnow()
            self.password_history.insert(0, hashed)
            self.password_history = self.password_history[:5]
        except Exception as e:
            logger.error(f"Password set failed: {e}")
            raise

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode(), self.password.encode())
        except Exception as e:
            logger.error(f"Password check failed: {e}")
            return False

    def _validate_password(self, password: str) -> None:
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")

        complexity_checks = [
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password)
        ]
        if sum(complexity_checks) < 3:
            raise ValueError("Password must include uppercase, lowercase, number, and special character")

    # --------------------------------------------
    # 🔑 MFA
    # --------------------------------------------
    def generate_mfa_secret(self) -> str:
        try:
            self.mfa_secret = pyotp.random_base32()
            self.mfa_enabled = True
            self.save()
            return self.mfa_secret
        except Exception as e:
            logger.error(f"MFA secret generation failed: {e}")
            raise

    def verify_mfa(self, mfa_code: str) -> bool:
        try:
            if not self.mfa_enabled or not self.mfa_secret:
                raise ValueError("MFA not enabled")
            totp = pyotp.TOTP(self.mfa_secret)
            result = totp.verify(mfa_code)
            if not result:
                self.mfa_verification_attempts += 1
                self.save()
            else:
                self.mfa_verification_attempts = 0
                self.save()
            return result
        except Exception as e:
            logger.error(f"MFA verification failed: {e}")
            return False

    # --------------------------------------------
    # 🔐 API Keys
    # --------------------------------------------
    def generate_api_key(self) -> str:
        try:
            api_key = secrets.token_urlsafe(32)
            self.api_keys.append(api_key)
            self.save()
            self._log_security_event("api_key_generated", {"api_key_count": len(self.api_keys)})
            return api_key
        except Exception as e:
            logger.error(f"API key generation failed: {e}")
            raise

    # --------------------------------------------
    # 📊 Security Logs
    # --------------------------------------------
    def _log_security_event(self, event_type: str, details: Dict[str, Any] = None, severity: str = "low") -> None:
        try:
            log_entry = SecurityLog(event_type=event_type, details=details or {}, severity=severity)
            self.security_logs.append(log_entry)
            self.save()
        except Exception as e:
            logger.error(f"Security event logging failed: {e}")

# --------------------------------------------
# 🎯 Utility Function: User Creation
# --------------------------------------------
def create_user(username: str, email: str, password: str, role: str = "user", is_active: bool = True) -> User:
    try:
        user = User(username=username, email=email, role=role, is_active=is_active)
        user.set_password(password)
        user.save()
        return user
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        raise

