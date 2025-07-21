import os
import secrets
import re
from typing import Dict, Any, List
from cryptography.fernet import Fernet
from flask import Flask
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from app.utils.loggingService import LoggingService, LogLevel

# ----------------------------------------------------------
# ✅ **Security Configuration Class**
# ----------------------------------------------------------
class SecurityConfiguration:
    """
    Comprehensive security configuration for the application
    """

    @staticmethod
    def generate_secret_key(length: int = 64) -> str:
        """
        Generate a cryptographically secure secret key
        
        Args:
            length (int): Length of the secret key
        
        Returns:
            str: Secure random secret key
        """
        return secrets.token_hex(length // 2)

    @staticmethod
    def generate_encryption_key() -> bytes:
        """
        Generate a Fernet encryption key
        
        Returns:
            bytes: Encryption key
        """
        return Fernet.generate_key()

    @staticmethod
    def configure_flask_security(app: Flask) -> None:
        """
        Apply comprehensive security configurations to Flask app
        
        Args:
            app (Flask): Flask application instance
        """
        # ✅ **Set secret keys**
        app.config['SECRET_KEY'] = SecurityConfiguration.generate_secret_key()
        app.config['JWT_SECRET_KEY'] = SecurityConfiguration.generate_secret_key()
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour
        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 604800  # 7 days

        # ✅ **CORS Configuration**
        app.config['CORS_SUPPORTS_CREDENTIALS'] = True
        app.config['CORS_ORIGINS'] = [
            'https://maldna.local',
            'https://localhost:3000',
            'https://127.0.0.1:3000'
        ]

        # ✅ **Rate Limiting**
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=[
                "100 per day",
                "30 per hour"
            ]
        )

        # ✅ **HTTP Security Headers**
        Talisman(
            app,
            content_security_policy={
                'default-src': "'self'",
                'script-src': [
                    "'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'
                ],
                'style-src': [
                    "'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'
                ],
                'img-src': "'self' data:",
                'font-src': [
                    "'self'", 'https://fonts.gstatic.com'
                ]
            },
            content_security_policy_nonce_in=['script-src'],
            force_https=True,
            strict_transport_security=True,
            x_frame_options='SAMEORIGIN',
            x_xss_protection=True,
            referrer_policy='strict-origin-when-cross-origin'
        )

        # ✅ **Proxy support for proper IP detection**
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

        LoggingService.log(LogLevel.INFO, "Security configurations applied successfully")

    # ----------------------------------------------------------
    # ✅ **Input Validation & Sanitization**
    # ----------------------------------------------------------
    @staticmethod
    def validate_input(input_value: str, pattern: str, max_length: int = 255) -> bool:
        """
        Validate input against a regex pattern
        
        Args:
            input_value (str): Input to validate
            pattern (str): Regex pattern
            max_length (int): Maximum allowed length
        
        Returns:
            bool: Whether input is valid
        """
        if not input_value or len(input_value) > max_length:
            return False

        return bool(re.match(pattern, input_value))

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent directory traversal
        
        Args:
            filename (str): Original filename
        
        Returns:
            str: Sanitized filename
        """
        return re.sub(r'[^\w\-_\.]', '', filename)

    # ----------------------------------------------------------
    # ✅ **Security Best Practices & Reports**
    # ----------------------------------------------------------
    @staticmethod
    def get_security_recommendations() -> Dict[str, List[str]]:
        """
        Generate security best practice recommendations
        
        Returns:
            Dict of security recommendations
        """
        return {
            'authentication': [
                'Enable multi-factor authentication',
                'Implement password rotation policy',
                'Use strong password complexity requirements'
            ],
            'network_security': [
                'Use HTTPS with strong TLS configuration',
                'Implement IP whitelisting',
                'Configure strict firewall rules'
            ],
            'data_protection': [
                'Encrypt sensitive data at rest and in transit',
                'Implement secure key management',
                'Use secure random number generators'
            ],
            'access_control': [
                'Implement least privilege principle',
                'Regularly audit user permissions',
                'Use role-based access control'
            ],
            'logging_and_monitoring': [
                'Enable comprehensive logging',
                'Set up real-time security alerts',
                'Regularly review and analyze logs'
            ]
        }

    @staticmethod
    def generate_security_report() -> Dict[str, Any]:
        """
        Generate a comprehensive security configuration report
        
        Returns:
            Dict containing security configuration details
        """
        return {
            'secret_key_length': 64,
            'jwt_token_expiry': {
                'access_token': '1 hour',
                'refresh_token': '7 days'
            },
            'rate_limiting': {
                'daily_limit': 100,
                'hourly_limit': 30
            },
            'security_headers': {
                'content_security_policy': 'Enabled',
                'strict_transport_security': 'Enabled',
                'x_frame_options': 'SAMEORIGIN',
                'x_xss_protection': 'Enabled'
            },
            'encryption': {
                'secret_key_method': 'Cryptographically secure random generation',
                'encryption_key_method': 'Fernet symmetric encryption'
            }
        }

