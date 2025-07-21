import os
import json
import logging
import argparse
import secrets
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request

# Import User Model
from app.models.userModel import User

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Secret Key for JWT
JWT_SECRET = os.getenv("JWT_SECRET", "your_super_secret_key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 12  # JWT Expiration Time


# --------------------------------------------
# 🔐 **Password Hashing & Verification**
# --------------------------------------------
def hash_password(password: str) -> str:
    """
    Securely hash a password using bcrypt.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against its stored hash.
    """
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


# --------------------------------------------
# 🔑 **JWT Token Management**
# --------------------------------------------
def generate_jwt_token(user_id: str, role: str) -> str:
    """
    Generate a JWT token for CLI and UI authentication.
    """
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.error("JWT Token expired")
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        logger.error("Invalid JWT Token")
        return {"error": "Invalid token"}


# --------------------------------------------
# 🔥 **Role-Based Access Control (RBAC)**
# --------------------------------------------
def role_required(required_role: str):
    """
    Decorator to enforce role-based access control.
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            user = User.objects(id=current_user_id).first()

            if not user:
                return jsonify({"error": "User not found"}), 404

            if user.role != required_role:
                return jsonify({"error": f"{required_role} access required"}), 403

            return fn(*args, **kwargs)

        return wrapper
    return decorator


def admin_required(fn):
    """
    Restrict access to admin users only.
    """
    return role_required("admin")(fn)


# --------------------------------------------
# 🔥 **CLI-Based Authentication**
# --------------------------------------------
def cli_login(username: str, password: str) -> dict:
    """
    Authenticate a user via CLI and return a JWT token.
    """
    user = User.objects(username=username).first()
    if not user:
        return {"error": "Invalid username or password"}

    if not verify_password(password, user.password):
        return {"error": "Invalid username or password"}

    token = generate_jwt_token(user.user_id, user.role)
    return {"access_token": token, "role": user.role, "expires_in": f"{JWT_EXPIRATION_HOURS} hours"}


# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User Authentication CLI")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 CLI Login Command
    login_parser = subparsers.add_parser("login", help="Login and receive a JWT token")
    login_parser.add_argument("--username", required=True, help="Username")
    login_parser.add_argument("--password", required=True, help="Password")

    args = parser.parse_args()

    if args.command == "login":
        auth_response = cli_login(args.username, args.password)
        print(json.dumps(auth_response, indent=4))

