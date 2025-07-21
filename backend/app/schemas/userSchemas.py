import os
import json
import logging
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field, EmailStr, validator

# MongoDB Integration
from mongoengine import (
    Document, StringField, BooleanField, DateTimeField, ListField, DictField, ValidationError
)

# Security & Encryption
import bcrypt
import secrets

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **User Authentication Schema**
# --------------------------------------------
class UserAuthSchema(BaseModel):
    """Pydantic schema for user authentication requests"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password for authentication")

    @validator("password")
    def validate_password(cls, v):
        """Ensure password meets security requirements"""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")

        complexity_checks = [
            any(c.isupper() for c in v),
            any(c.islower() for c in v),
            any(c.isdigit() for c in v),
            any(not c.isalnum() for c in v)
        ]

        if sum(complexity_checks) < 3:
            raise ValueError("Password must include uppercase, lowercase, number, and special character")

        return v

# --------------------------------------------
# 📌 **MongoDB Model for User Management**
# --------------------------------------------
class User(Document):
    """
    MongoDB model for user accounts.
    """
    user_id = StringField(primary_key=True, required=True, unique=True)
    username = StringField(required=True, unique=True, max_length=50)
    email = StringField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(choices=["admin", "analyst", "user", "guest"], default="user")
    is_active = BooleanField(default=True)
    permissions = ListField(StringField())
    security_logs = ListField(DictField())

    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "user_accounts",
        "indexes": ["user_id", "email", "-created_at"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert user data to dictionary.
        """
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "permissions": self.permissions,
            "security_logs": self.security_logs,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def set_password(self, password: str) -> None:
        """
        Hash and set user password securely.
        """
        self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.save()

    def check_password(self, password: str) -> bool:
        """
        Validate the password against stored hash.
        """
        return bcrypt.checkpw(password.encode(), self.password.encode())

# --------------------------------------------
# 📌 **Role & Permission Modification Schema**
# --------------------------------------------
class RoleModificationSchema(BaseModel):
    """Pydantic schema for modifying user roles"""
    user_id: str = Field(..., description="Unique user identifier")
    new_role: str = Field(..., description="New role to be assigned")

    @validator("new_role")
    def validate_role(cls, v):
        """Ensure role is valid"""
        valid_roles = ["admin", "analyst", "user", "guest"]
        if v.lower() not in valid_roles:
            raise ValueError(f"Invalid role: {v}")
        return v

class PermissionModificationSchema(BaseModel):
    """Pydantic schema for modifying user permissions"""
    user_id: str = Field(..., description="Unique user identifier")
    permissions: List[str] = Field(..., description="List of permissions to assign")

# --------------------------------------------
# 📌 **Security Anomaly Detection Schema**
# --------------------------------------------
class SecurityAnomalySchema(BaseModel):
    """Pydantic schema for security anomaly detection validation"""
    anomaly_id: str = Field(..., description="Unique anomaly identifier")
    user_id: str = Field(..., description="Unique user identifier")
    event_type: str = Field(..., description="Type of detected anomaly")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: str = Field(..., description="Severity level of anomaly")
    details: Dict[str, Any] = Field(..., description="Additional details of anomaly event")

    @validator("severity")
    def validate_severity(cls, v):
        """Ensure severity is valid"""
        valid_severity = ["low", "medium", "high", "critical"]
        if v.lower() not in valid_severity:
            raise ValueError(f"Invalid severity level: {v}")
        return v

# --------------------------------------------
# 🔥 **CLI Utility for User Management**
# --------------------------------------------
def create_user(username: str, email: str, password: str, role: str = "user") -> Dict[str, Any]:
    """
    Create a new user in the database.
    """
    logger.info(f"🚀 Creating user {username}...")

    user_data = User(
        user_id=str(secrets.token_hex(8)),
        username=username,
        email=email,
        role=role
    )
    user_data.set_password(password)
    user_data.save()

    logger.info(f"✅ User {username} created successfully")
    return user_data.to_dict()

def modify_user_role(user_id: str, new_role: str) -> Dict[str, Any]:
    """
    Modify user role in the database.
    """
    logger.info(f"🔄 Updating role for user {user_id} to {new_role}...")

    user_record = User.objects(user_id=user_id).first()
    if not user_record:
        return {"error": "User not found"}

    user_record.role = new_role
    user_record.save()

    logger.info(f"✅ User {user_id} role updated to {new_role}")
    return user_record.to_dict()

def log_security_anomaly(anomaly_id: str, user_id: str, event_type: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Log security anomaly for a user.
    """
    logger.info(f"⚠️ Logging security anomaly {anomaly_id} for user {user_id}...")

    anomaly_data = SecurityAnomalySchema(
        anomaly_id=anomaly_id,
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        details=details
    )

    user_record = User.objects(user_id=user_id).first()
    if not user_record:
        return {"error": "User not found"}

    user_record.security_logs.append(anomaly_data.dict())
    user_record.save()

    logger.info(f"✅ Security anomaly {anomaly_id} logged successfully")
    return user_record.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User Management & Security")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Create User
    create_parser = subparsers.add_parser("create", help="Create a new user")
    create_parser.add_argument("--username", required=True, help="Username")
    create_parser.add_argument("--email", required=True, help="Email Address")
    create_parser.add_argument("--password", required=True, help="Password")
    create_parser.add_argument("--role", default="user", help="User Role")

    # 📌 Modify User Role
    role_parser = subparsers.add_parser("modify_role", help="Modify user role")
    role_parser.add_argument("--user_id", required=True, help="User ID")
    role_parser.add_argument("--new_role", required=True, help="New Role")

    args = parser.parse_args()

    # Execute Command
    if args.command == "create":
        user_data = create_user(args.username, args.email, args.password, args.role)
        print(json.dumps(user_data, indent=4))

    elif args.command == "modify_role":
        user_data = modify_user_role(args.user_id, args.new_role)
        print(json.dumps(user_data, indent=4))
