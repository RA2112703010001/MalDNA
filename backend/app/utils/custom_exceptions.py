import logging
from enum import Enum, auto
from typing import Optional, Dict, Any

# Configure Logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🚨 **Error Categories**
# --------------------------------------------
class ErrorCategory(Enum):
    """Categorization of different error types."""
    VALIDATION_ERROR = auto()
    AUTHENTICATION_ERROR = auto()
    AUTHORIZATION_ERROR = auto()
    NOT_FOUND = auto()
    SYSTEM_ERROR = auto()
    NETWORK_ERROR = auto()
    RESOURCE_CONFLICT = auto()
    BLOCKCHAIN_ERROR = auto()
    FORENSIC_ERROR = auto()
    MALWARE_ANALYSIS_ERROR = auto()
    LINEAGE_TRACKING_ERROR = auto()


# --------------------------------------------
# ❌ **Base Custom Exception**
# --------------------------------------------
class CustomException(Exception):
    """Base custom exception for structured error handling."""
    def __init__(
        self, 
        message: str, 
        category: ErrorCategory = ErrorCategory.SYSTEM_ERROR,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.category = category
        self.error_code = error_code or str(category.name)
        self.details = details or {}

        # Log the error
        logger.error(f"[{self.error_code}] {self.message} | Details: {self.details}")

        super().__init__(self.message)


# --------------------------------------------
# 📊 **Report Generation Exception**
# --------------------------------------------
class ReportGenerationError(CustomException):
    """Exception raised when a report fails to generate."""
    def __init__(self, message: str, report_type: Optional[str] = None, entity_id: Optional[str] = None):
        super().__init__(
            message, 
            category=ErrorCategory.SYSTEM_ERROR,
            error_code="REPORT_GENERATION_FAILED",
            details={"report_type": report_type, "entity_id": entity_id}
        )


# --------------------------------------------
# 🔍 **Entity Not Found Exception**
# --------------------------------------------
class EntityNotFoundError(CustomException):
    """Exception raised when an entity is not found in the database."""
    def __init__(self, entity_type: str, entity_id: str):
        super().__init__(
            f"{entity_type} with ID {entity_id} not found",
            category=ErrorCategory.NOT_FOUND,
            error_code="ENTITY_NOT_FOUND",
            details={"entity_type": entity_type, "entity_id": entity_id}
        )


# --------------------------------------------
# 🔐 **Authorization & Authentication Errors**
# --------------------------------------------
class AuthenticationError(CustomException):
    """Exception raised for authentication failures."""
    def __init__(self, message: str = "Invalid authentication credentials"):
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION_ERROR,
            error_code="AUTHENTICATION_FAILED"
        )


class InsufficientPermissionsError(CustomException):
    """Exception raised when user lacks required permissions."""
    def __init__(self, required_role: str, current_role: Optional[str] = None):
        super().__init__(
            f"Insufficient permissions. Required role: {required_role}",
            category=ErrorCategory.AUTHORIZATION_ERROR,
            error_code="INSUFFICIENT_PERMISSIONS",
            details={"required_role": required_role, "current_role": current_role}
        )


# --------------------------------------------
# ⚡ **Malware Analysis Exception**
# --------------------------------------------
class MalwareAnalysisError(CustomException):
    """Exception raised for errors in malware analysis."""
    def __init__(self, message: str, sample_id: Optional[str] = None):
        super().__init__(
            message,
            category=ErrorCategory.MALWARE_ANALYSIS_ERROR,
            error_code="MALWARE_ANALYSIS_FAILED",
            details={"sample_id": sample_id}
        )


# --------------------------------------------
# 🔬 **Forensic Verification Exception**
# --------------------------------------------
class ForensicVerificationError(CustomException):
    """Exception raised when forensic verification fails."""
    def __init__(self, message: str, case_id: Optional[str] = None):
        super().__init__(
            message,
            category=ErrorCategory.FORENSIC_ERROR,
            error_code="FORENSIC_VERIFICATION_FAILED",
            details={"case_id": case_id}
        )


# --------------------------------------------
# 🔗 **Blockchain Verification Exception**
# --------------------------------------------
class BlockchainVerificationError(CustomException):
    """Exception raised when blockchain verification fails."""
    def __init__(self, message: str, transaction_id: Optional[str] = None):
        super().__init__(
            message,
            category=ErrorCategory.BLOCKCHAIN_ERROR,
            error_code="BLOCKCHAIN_VERIFICATION_FAILED",
            details={"transaction_id": transaction_id}
        )


# --------------------------------------------
# 🔬 **Lineage Tracking Exception**
# --------------------------------------------
class LineageTrackingError(CustomException):
    """Exception raised when AI-driven lineage tracking fails."""
    def __init__(self, message: str, sample_id: Optional[str] = None):
        super().__init__(
            message,
            category=ErrorCategory.LINEAGE_TRACKING_ERROR,
            error_code="LINEAGE_TRACKING_FAILED",
            details={"sample_id": sample_id}
        )


# --------------------------------------------
# ⚠ **Global Exception Handler**
# --------------------------------------------
def handle_exception(exc: Exception) -> Dict[str, Any]:
    """
    Convert exceptions to standardized error response.
    
    Args:
        exc (Exception): The exception to handle
    
    Returns:
        Dict containing error details.
    """
    if isinstance(exc, CustomException):
        return {
            "error": {
                "message": exc.message,
                "category": exc.category.name,
                "code": exc.error_code,
                "details": exc.details
            }
        }
    
    # Fallback for unhandled exceptions
    logger.error(f"Unhandled Exception: {str(exc)}")
    return {
        "error": {
            "message": str(exc),
            "category": "SYSTEM_ERROR",
            "code": "UNEXPECTED_ERROR",
            "details": {}
        }
    }

