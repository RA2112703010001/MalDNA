import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum, auto

import structlog
from pythonjsonlogger import jsonlogger
from mongoengine import Document, StringField, DateTimeField, DictField, BooleanField

# ----------------------------------------------------------
# ✅ Log Levels Enumeration
# ----------------------------------------------------------
class LogLevel(Enum):
    """Standardized log levels"""
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()

# ----------------------------------------------------------
# ✅ MongoDB-based Audit Logging
# ----------------------------------------------------------
class AuditLogEntry(Document):
    """MongoDB document for storing audit log entries"""
    user_id = StringField(required=True)
    username = StringField(required=True)
    action = StringField(required=True)
    resource_type = StringField(required=True)
    resource_id = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)
    ip_address = StringField()
    user_agent = StringField()
    details = DictField()
    status = StringField(choices=['SUCCESS', 'FAILURE'])
    is_blockchain_verified = BooleanField(default=False)

    meta = {"collection": "audit_logs"}

# ----------------------------------------------------------
# ✅ Logging Configuration
# ----------------------------------------------------------
class LoggingConfig:
    """Centralized logging configuration"""
    LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
    os.makedirs(LOG_DIR, exist_ok=True)

    @classmethod
    def configure_logging(cls):
        """Configure structured logging with JSON output"""
        os.makedirs(cls.LOG_DIR, exist_ok=True)

        file_handler = logging.FileHandler(
            os.path.join(cls.LOG_DIR, f'maldna_{datetime.utcnow().strftime("%Y%m%d")}.json'),
            mode='a'
        )
        file_handler.setFormatter(
            jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s %(exc_info)s')
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        logging.basicConfig(
            level=logging.INFO,
            handlers=[file_handler, console_handler]
        )

        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt='iso'),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

# ----------------------------------------------------------
# ✅ Centralized Logging & Audit Service
# ----------------------------------------------------------
class LoggingService:
    """Centralized logging and audit trail service"""

    @staticmethod
    def log(level: LogLevel, message: str, extra: Optional[Dict[str, Any]] = None):
        logger = structlog.get_logger()
        log_method = {
            LogLevel.DEBUG: logger.debug,
            LogLevel.INFO: logger.info,
            LogLevel.WARNING: logger.warning,
            LogLevel.ERROR: logger.error,
            LogLevel.CRITICAL: logger.critical
        }[level]
        log_method(message, **extra or {})

    @staticmethod
    def log_action(action: str, status: str, extra: Optional[Dict[str, Any]] = None):
        """
        Simplified log method for logging actions.
        """
        extra = extra or {}
        extra.update({"action": action, "status": status})
        LoggingService.log(LogLevel.INFO, f"Action: {action}, Status: {status}", extra)

    @staticmethod
    def audit_log(user_id: str, username: str, action: str, resource_type: str,
                  resource_id: Optional[str] = None, status: str = 'SUCCESS',
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None):
        """
        Create an audit log in MongoDB
        """
        try:
            audit_entry = AuditLogEntry(
                user_id=user_id,
                username=username,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details or {}
            )
            audit_entry.save()

        except Exception as e:
            structlog.get_logger().error("Failed to create audit log entry", error=str(e))

    @staticmethod
    def get_audit_logs(user_id: Optional[str] = None, action: Optional[str] = None,
                       resource_type: Optional[str] = None, start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query and return audit logs with optional filtering.
        """
        query = {}
        if user_id:
            query["user_id"] = user_id
        if action:
            query["action"] = action
        if resource_type:
            query["resource_type"] = resource_type
        if start_date:
            query["timestamp__gte"] = start_date
        if end_date:
            query["timestamp__lte"] = end_date

        return list(AuditLogEntry.objects(**query).order_by('-timestamp')[:limit])

# ✅ Initialize logging on module load
LoggingConfig.configure_logging()
logger = structlog.get_logger()

