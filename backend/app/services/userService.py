import os
import logging
import argparse
import bcrypt
import jwt
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dotenv import load_dotenv
from pymongo import MongoClient
from flask import Blueprint, request, jsonify

# Internal dependencies
from app.models.userModel import User, SecurityLog
from app.utils.securityUtils import validate_email, validate_password, sanitize_input

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# MongoDB Client Setup
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
client = MongoClient(MONGO_URI)
db = client["MalDNA"]
logger.info("✅ Connected to MongoDB")

class UserService:
    def __init__(self):
        """Initialize User Service."""
        try:
            self.jwt_secret = os.getenv("JWT_SECRET_KEY")
            if not self.jwt_secret:
                raise ValueError("JWT Secret Key not configured")
            logger.info("User service initialized successfully")
            
            # MongoDB Client Setup
            self.client = MongoClient(os.getenv("MONGO_URI"))
            self.db = self.client.get_database(os.getenv("DB_NAME"))
            self.user_collection = self.db["users"]  # MongoDB collection for users
        except Exception as e:
            logger.error(f"User service initialization failed: {e}")
            raise

    ### **🔑 User Management Functions**
    def create_user(self, name: str, email: str, password: str, role: str = "user") -> Dict[str, Any]:
        """Create a new user."""
        try:
            sanitized_name = sanitize_input(name)
            validate_email(email)
            validate_password(password)

            # Check if the user already exists in the MongoDB collection
            if self.user_collection.find_one({"email": email}):
                raise ValueError("User already exists")

            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Create the user document
            user = {
                "name": sanitized_name,
                "email": email,
                "password": hashed_password,
                "role": role,
                "is_active": True,
                "created_at": datetime.utcnow()
            }

            # Insert the user document into MongoDB
            self.user_collection.insert_one(user)

            return {"message": "User created successfully"}
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            raise

    def update_user(self, email: str, updates: Dict[str, Any]) -> Dict[str, str]:
        """Update user details."""
        try:
            # Find the user in MongoDB
            user = self.user_collection.find_one({"email": email})
            if not user:
                raise ValueError("User not found")

            # Update the user fields
            update_result = self.user_collection.update_one(
                {"email": email}, 
                {"$set": updates}
            )

            if update_result.matched_count == 0:
                raise ValueError("User not updated")

            return {"message": "User updated successfully"}
        except Exception as e:
            logger.error(f"User update failed: {e}")
            raise

    def deactivate_user(self, email: str) -> Dict[str, str]:
        """Deactivate user account."""
        try:
            user = self.user_collection.find_one({"email": email})
            if not user:
                raise ValueError("User not found")

            # Deactivate the user and save the deactivation timestamp
            self.user_collection.update_one(
                {"email": email},
                {"$set": {"is_active": False, "deactivated_at": datetime.utcnow()}}
            )

            return {"message": "User deactivated successfully"}
        except Exception as e:
            logger.error(f"User deactivation failed: {e}")
            raise

    ### **📜 User Logs & Security Monitoring**
    def get_user_logs(self, email: str) -> List[Dict[str, Any]]:
        """Retrieve user activity logs."""
        try:
            # Assuming SecurityLog is a MongoDB collection
            logs = SecurityLog.objects(email=email)
            return [log.to_json() for log in logs]
        except Exception as e:
            logger.error(f"Fetching user logs failed: {e}")
            raise

    def detect_security_anomalies(self, email: str) -> Dict[str, Any]:
        """Detect anomalies in user behavior."""
        try:
            logs = SecurityLog.objects(email=email)
            # Example of anomaly detection logic, such as multiple failed login attempts
            unusual_attempts = [log for log in logs if log.event == "failed_login"]
            if len(unusual_attempts) > 5:  # Example threshold
                return {"message": "Security anomaly detected", "unusual_attempts": len(unusual_attempts)}
            return {"message": "No anomalies detected", "unusual_attempts": len(unusual_attempts)}
        except Exception as e:
            logger.error(f"Security anomaly detection failed: {e}")
            raise

    ### **🔑 CLI Functions**
    def cli_create_user(self, args):
        """CLI wrapper for creating a new user."""
        result = self.create_user(args.name, args.email, args.password, args.role)
        print(json.dumps(result, indent=4))

    def cli_update_user(self, args):
        """CLI wrapper for updating a user."""
        updates = {}
        if args.name:
            updates["name"] = args.name
        if args.role:
            updates["role"] = args.role

        result = self.update_user(args.email, updates)
        print(json.dumps(result, indent=4))

    def cli_deactivate_user(self, args):
        """CLI wrapper for deactivating a user."""
        result = self.deactivate_user(args.email)
        print(json.dumps(result, indent=4))

    def cli_get_user_logs(self, args):
        """CLI wrapper for fetching user logs."""
        result = self.get_user_logs(args.email)
        print(json.dumps(result, indent=4))

    def cli_detect_anomalies(self, args):
        """CLI wrapper for detecting security anomalies."""
        result = self.detect_security_anomalies(args.email)
        print(json.dumps(result, indent=4))


# ---------------------------- Flask API Endpoints ---------------------------- #

user_bp = Blueprint("user_service", __name__)
user_service = UserService()

@user_bp.route("/user/create", methods=["POST"])
def create_user():
    """Create a new user."""
    data = request.json
    return jsonify(user_service.create_user(data["name"], data["email"], data["password"], data.get("role", "user")))

@user_bp.route("/user/update", methods=["POST"])
def update_user():
    """Update user details."""
    data = request.json
    return jsonify(user_service.update_user(data["email"], data["updates"]))

@user_bp.route("/user/deactivate", methods=["POST"])
def deactivate_user():
    """Deactivate a user."""
    data = request.json
    return jsonify(user_service.deactivate_user(data["email"]))

@user_bp.route("/user/logs/<email>", methods=["GET"])
def get_user_logs(email):
    """Retrieve user logs."""
    return jsonify(user_service.get_user_logs(email))

@user_bp.route("/user/anomalies/<email>", methods=["GET"])
def detect_security_anomalies(email):
    """Detect security anomalies in user behavior."""
    return jsonify(user_service.detect_security_anomalies(email))


# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User Management CLI")
    subparsers = parser.add_subparsers(help="User management commands")

    # Create user
    parser_create = subparsers.add_parser("create", help="Create a new user")
    parser_create.add_argument("name", type=str, help="User's name")
    parser_create.add_argument("email", type=str, help="User's email")
    parser_create.add_argument("password", type=str, help="User's password")
    parser_create.add_argument("--role", type=str, default="user", help="User role (default: user)")
    parser_create.set_defaults(func=user_service.cli_create_user)

    # Update user
    parser_update = subparsers.add_parser("update", help="Update user details")
    parser_update.add_argument("email", type=str, help="User's email")
    parser_update.add_argument("--name", type=str, help="New name")
    parser_update.add_argument("--role", type=str, help="New role")
    parser_update.set_defaults(func=user_service.cli_update_user)

    # Deactivate user
    parser_deactivate = subparsers.add_parser("deactivate", help="Deactivate a user")
    parser_deactivate.add_argument("email", type=str, help="User's email")
    parser_deactivate.set_defaults(func=user_service.cli_deactivate_user)

    # Get user logs
    parser_logs = subparsers.add_parser("logs", help="Get user logs")
    parser_logs.add_argument("email", type=str, help="User's email")
    parser_logs.set_defaults(func=user_service.cli_get_user_logs)

    # Detect security anomalies
    parser_anomalies = subparsers.add_parser("anomalies", help="Detect security anomalies")
    parser_anomalies.add_argument("email", type=str, help="User's email")
    parser_anomalies.set_defaults(func=user_service.cli_detect_anomalies)

    args = parser.parse_args()
    args.func(args)

