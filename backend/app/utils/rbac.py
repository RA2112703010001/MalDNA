from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app.models.userModel import User
from app.utils.custom_exceptions import InsufficientPermissionsError
from app.utils.logging import LoggingService, LogLevel, LoggingConfig

# ----------------------------------------------------------
# ✅ **User Role Definitions**
# ----------------------------------------------------------
class UserRole:
    """Predefined user roles with hierarchical permissions"""
    ADMIN = 'admin'
    SENIOR_ANALYST = 'senior_analyst'
    ANALYST = 'analyst'
    VIEWER = 'viewer'
    GUEST = 'guest'

# ----------------------------------------------------------
# ✅ **Permission Matrix - Define Access Levels**
# ----------------------------------------------------------
class PermissionMatrix:
    """Define permission matrix for different roles"""
    PERMISSIONS = {
        UserRole.ADMIN: [
            'generate_all_reports',
            'view_all_reports',
            'delete_reports',
            'manage_users',
            'perform_forensic_analysis',
            'access_user_data',
        ],
        UserRole.SENIOR_ANALYST: [
            'generate_malware_reports',
            'generate_forensic_reports',
            'generate_threat_intel_reports',
            'view_sensitive_reports'
        ],
        UserRole.ANALYST: [
            'generate_dna_reports',
            'generate_ransomware_reports',
            'generate_hybrid_reports',
            'view_basic_reports',
            'perform_forensic_analysis'
        ],
        UserRole.VIEWER: [
            'view_basic_reports'
        ],
        UserRole.GUEST: []
    }

# ----------------------------------------------------------
# ✅ **Role-Based Access Control Decorator**
# ----------------------------------------------------------
def require_role(allowed_roles):
    """
    Decorator to enforce role-based access control.
    
    Args:
        allowed_roles (list): Roles allowed to access the endpoint
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            user = User.objects.get(user_id=current_user_id)

            if user.role not in allowed_roles:
                # Logging the unauthorized access attempt
                LoggingService.log(
                    LogLevel.WARNING,
                    "Unauthorized access attempt",
                    {"user": user.username, "required_role": allowed_roles, "actual_role": user.role}
                )
                log_access_attempt(user, request.path, allowed=False)

                # Raise permission error if unauthorized
                raise InsufficientPermissionsError(
                    required_role=', '.join(allowed_roles),
                    current_role=user.role
                )

            # Logging the authorized access attempt
            log_access_attempt(user, request.path, allowed=True)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ----------------------------------------------------------
# ✅ **Permission Check Helper**
# ----------------------------------------------------------
def check_permission(user: User, permission: str) -> bool:
    """
    Check if a user has a specific permission.
    
    Args:
        user (User): User object
        permission (str): Permission name
    
    Returns:
        bool: True if permission granted, False otherwise
    """
    role_permissions = PermissionMatrix.PERMISSIONS.get(user.role, [])
    return permission in role_permissions

# ----------------------------------------------------------
# ✅ **Hierarchical Role Access**
# ----------------------------------------------------------
def get_role_hierarchy() -> dict:
    """
    Return a dictionary mapping each role to the roles it inherits from.
    Useful for hierarchical access and debugging.
    
    Returns:
        dict: Role -> List of inherited roles
    """
    roles = list(PermissionMatrix.PERMISSIONS.keys())
    role_hierarchy = {}
    for i, role in enumerate(roles):
        role_hierarchy[role] = roles[i:]
    return role_hierarchy

# ----------------------------------------------------------
# ✅ **Access Attempt Logging**
# ----------------------------------------------------------
def log_access_attempt(user: User, endpoint: str, allowed: bool):
    """
    Log access attempts for audit and compliance.
    
    Args:
        user (User): User object
        endpoint (str): API or CLI endpoint accessed
        allowed (bool): Access success or failure
    """
    # Log attempt to the audit log
    LoggingService.audit_log(
        user_id=user.user_id,
        username=user.username,
        action="ACCESS_ATTEMPT",
        resource_type="API" if request else "CLI",
        resource_id=endpoint,
        status="SUCCESS" if allowed else "FAILURE",
        details={"endpoint": endpoint}
    )

    # Log suspicious activity into the user security log
    user._log_security_event(
        event_type="suspicious_activity" if not allowed else "login_attempt",
        severity="critical" if not allowed else "low",
        details={"endpoint": endpoint, "method": request.method if request else "CLI"}
    )

