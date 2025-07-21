import os
import logging
import argparse
from datetime import timedelta
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from mongoengine import NotUniqueError, DoesNotExist
from app.models.userModel import User
from app.utils.logging import LoggingService

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

user_bp = Blueprint("user", __name__, url_prefix="/api/user")

# ---------------------------- API ENDPOINTS ---------------------------- #

@user_bp.route("/register", methods=["POST"])
def register_user():
    """Register a new user."""
    try:
        data = request.json
        username, email, password = data.get("username"), data.get("email"), data.get("password")

        # Ensure all fields are provided
        if not all([username, email, password]):
            return jsonify({"error": "Username, email, and password are required."}), 400

        # Check if email or username already exists
        if User.objects(email=email).first():
            return jsonify({"error": "Email is already taken."}), 409
        if User.objects(username=username).first():
            return jsonify({"error": "Username is already taken."}), 409

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        new_user.save()

        # Log the registration action
        LoggingService.log_action(new_user.id, "register", "User registered.")

        # Return response with user data
        return jsonify({
            "message": "User registered successfully",
            "user": {
                "id": str(new_user.id),
                "username": new_user.username,
                "email": new_user.email,
                "role": new_user.role
            }
        }), 201

    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed."}), 500

@user_bp.route("/login", methods=["POST"])
def login():
    """Authenticate user and return user info."""
    try:
        data = request.json
        username, password = data.get("username"), data.get("password")

        # Retrieve user by username
        user = User.objects.get(username=username)
        if not user.active:
            return jsonify({"error": "User account is deactivated."}), 403

        # Check if password matches
        if not check_password_hash(user.password, password):
            return jsonify({"error": "Invalid credentials."}), 401

        # Log the login action
        LoggingService.log_action(user.id, "login", "User logged in.")

        # Return response with user info
        return jsonify({
            "user": {
                "id": str(user.id),
                "username": user.username,
                "role": user.role,
                "email": user.email
            }
        }), 200

    except DoesNotExist:
        return jsonify({"error": "Invalid credentials."}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Login failed."}), 500

@user_bp.route("/list", methods=["GET"])
def list_users():
    """List all users."""
    try:
        users = User.objects.all()
        user_data = [{
            "id": str(u.id),
            "username": u.username,
            "role": u.role,
            "email": u.email,
            "active": u.active
        } for u in users]
        return jsonify({"users": user_data}), 200
    except Exception as e:
        logger.error(f"Error retrieving users: {e}")
        return jsonify({"error": "Failed to list users"}), 500

@user_bp.route("/update_role/<user_id>", methods=["POST"])
def update_user_role(user_id):
    """Update user's role."""
    try:
        data = request.json
        new_role = data.get("role")

        if new_role not in ["ADMIN", "SENIOR_ANALYST", "VIEWER"]:
            return jsonify({"error": "Invalid role specified."}), 400

        user = User.objects.get(id=user_id)
        user.role = new_role
        user.save()

        LoggingService.log_action(user.id, "update_role", f"Role updated to {new_role}")
        return jsonify({"message": "Role updated.", "new_role": new_role}), 200

    except DoesNotExist:
        return jsonify({"error": "User not found."}), 404
    except Exception as e:
        logger.error(f"Role update error: {e}")
        return jsonify({"error": "Failed to update role"}), 500

@user_bp.route("/deactivate/<user_id>", methods=["POST"])
def deactivate_user(user_id):
    """Deactivate user."""
    try:
        user = User.objects.get(id=user_id)
        user.active = False
        user.save()

        LoggingService.log_action(user.id, "deactivate", "User deactivated.")
        return jsonify({"message": "User deactivated."}), 200
    except DoesNotExist:
        return jsonify({"error": "User not found."}), 404
    except Exception as e:
        logger.error(f"Deactivation error: {e}")
        return jsonify({"error": "Failed to deactivate user"}), 500

# ---------------------------- CLI COMMANDS ---------------------------- #

def cli_register_user(username, email, password):
    try:
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        new_user.save()
        print(f"[✔] User '{username}' registered.")
    except NotUniqueError:
        print("[❌] Username or email already exists.")
    except Exception as e:
        print(f"[❌] Registration error: {e}")

def cli_list_users():
    try:
        users = User.objects.all()
        for u in users:
            print(f"ID: {u.id}, Username: {u.username}, Role: {u.role}, Active: {u.active}")
    except Exception as e:
        print(f"[❌] Failed to retrieve users: {e}")

def cli_update_user_role(user_id, new_role):
    try:
        if new_role not in ["ADMIN", "SENIOR_ANALYST", "VIEWER"]:
            print("[❌] Invalid role.")
            return
        user = User.objects.get(id=user_id)
        user.role = new_role
        user.save()
        print(f"[✔] Role updated to {new_role} for '{user.username}'")
    except DoesNotExist:
        print("[❌] User not found.")
    except Exception as e:
        print(f"[❌] Update error: {e}")

def cli_deactivate_user(user_id):
    try:
        user = User.objects.get(id=user_id)
        user.active = False
        user.save()
        print(f"[✔] User '{user.username}' deactivated.")
    except DoesNotExist:
        print("[❌] User not found.")
    except Exception as e:
        print(f"[❌] Deactivation error: {e}")

def cli_view_user_logs(user_id):
    try:
        logs = LoggingService.get_logs_by_user(user_id)
        if not logs:
            print("[ℹ] No logs for user.")
        else:
            for log in logs:
                print(f"[{log.timestamp}] {log.action} - {log.details}")
    except Exception as e:
        print(f"[❌] Log fetch error: {e}")

# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User Management CLI")
    parser.add_argument("--register", nargs=3, metavar=("USERNAME", "EMAIL", "PASSWORD"))
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--update-role", nargs=2, metavar=("USER_ID", "NEW_ROLE"))
    parser.add_argument("--deactivate", metavar="USER_ID")
    parser.add_argument("--logs", metavar="USER_ID")

    args = parser.parse_args()

    if args.register:
        cli_register_user(*args.register)
    elif args.list:
        cli_list_users()
    elif args.update_role:
        cli_update_user_role(*args.update_role)
    elif args.deactivate:
        cli_deactivate_user(args.deactivate)
    elif args.logs:
        cli_view_user_logs(args.logs)
    else:
        print("[❌] Invalid CLI arguments.")

