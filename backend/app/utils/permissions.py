import logging
from typing import Dict, Any, List

from app.models.userModel import User
from app.utils.rbac import UserRole
from app.utils.logging import LoggingService, LogLevel, LoggingConfig

# ----------------------------------------------------------
# ✅ Configure Logging
# ----------------------------------------------------------
logger = logging.getLogger(__name__)

# ----------------------------------------------------------
# ✅ Permission Management Service
# ----------------------------------------------------------
class PermissionService:
    """
    Advanced permission management service for role-based and action-based access control.
    """

    @staticmethod
    def get_user_permissions(user: User) -> Dict[str, Any]:
        """
        Generate comprehensive permission dictionary for a user.
        """
        permissions = {
            "role": user.role,
            "reports": {
                "malware": {"generate": False, "view": False, "delete": False},
                "forensic": {"generate": False, "view": False, "delete": False},
                "threat_intel": {"generate": False, "view": False, "delete": False},
                "dna": {"generate": False, "view": False, "delete": False},
            },
            "user_management": {
                "create_user": False,
                "update_user": False,
                "delete_user": False,
                "view_users": False,
            },
            "system": {"view_logs": False, "manage_settings": False},
        }

        role = user.role

        if role == UserRole.ADMIN:
            for group in permissions:
                if isinstance(permissions[group], dict):
                    for key in permissions[group]:
                        if isinstance(permissions[group][key], dict):
                            for sub_key in permissions[group][key]:
                                permissions[group][key][sub_key] = True
                        else:
                            permissions[group][key] = True

        elif role == UserRole.SENIOR_ANALYST:
            permissions["reports"]["malware"]["generate"] = True
            permissions["reports"]["malware"]["view"] = True
            permissions["reports"]["forensic"]["generate"] = True
            permissions["reports"]["forensic"]["view"] = True
            permissions["reports"]["threat_intel"]["view"] = True

        elif role == UserRole.ANALYST:
            permissions["reports"]["dna"]["generate"] = True
            permissions["reports"]["dna"]["view"] = True
            permissions["reports"]["malware"]["view"] = True

        elif role == UserRole.VIEWER:
            permissions["reports"]["dna"]["view"] = True
            permissions["reports"]["malware"]["view"] = True

        return permissions

    @staticmethod
    def check_specific_permission(user: User, resource_path: str, action: str) -> bool:
        """
        Check a specific permission for a user using a dot-notated path.

        Example:
            resource_path: 'reports.malware'
            action: 'generate'
        """
        permissions = PermissionService.get_user_permissions(user)
        keys = resource_path.split(".")
        current = permissions

        try:
            for key in keys:
                current = current[key]
            return current.get(action, False)
        except Exception:
            return False

    @staticmethod
    def filter_viewable_resources(user: User, resources: list, resource_path: str) -> list:
        """
        Filter a list of resources based on view permission.
        """
        if PermissionService.check_specific_permission(user, resource_path, "view"):
            return resources
        return []

    @staticmethod
    def modify_user_role(admin_user: User, target_user: User, new_role: str) -> bool:
        """
        Allow Admins to modify user roles. Includes audit logging.
        """
        if admin_user.role != UserRole.ADMIN:
            logger.warning(f"Unauthorized role change attempt by {admin_user.username}")
            LoggingService.log(LogLevel.WARNING, "Unauthorized role change attempt", {
                "by": admin_user.username,
                "target": target_user.username,
                "new_role": new_role
            })
            return False

        if new_role not in UserRole.__members__:
            logger.error(f"Invalid role assignment attempted: {new_role}")
            return False

        target_user.role = new_role
        target_user.save()

        LoggingService.audit_log(
            user_id=admin_user.user_id,
            username=admin_user.username,
            action="ROLE_MODIFICATION",
            resource_type="User",
            resource_id=target_user.user_id,
            details={"new_role": new_role}
        )

        logger.info(f"{admin_user.username} changed role of {target_user.username} to {new_role}")
        return True

    @staticmethod
    def get_permission_hierarchy() -> Dict[str, List[str]]:
        """
        Get permission hierarchy showing role-based inheritance.
        """
        return {
            UserRole.ADMIN: ["full_access"],
            UserRole.SENIOR_ANALYST: ["generate_sensitive_reports", "view_advanced_reports"],
            UserRole.ANALYST: ["generate_basic_reports", "view_basic_reports"],
            UserRole.VIEWER: ["view_basic_reports"]
        }

    @staticmethod
    def audit_permission_check(user: User, resource_path: str, action: str) -> bool:
        """
        Perform and audit a permission check attempt for sensitive access control.
        """
        permitted = PermissionService.check_specific_permission(user, resource_path, action)

        LoggingService.audit_log(
            user_id=user.user_id,
            username=user.username,
            action="PERMISSION_CHECK",
            resource_type=resource_path,
            resource_id="N/A",
            details={
                "action": action,
                "result": "ALLOWED" if permitted else "DENIED"
            }
        )

        return permitted

