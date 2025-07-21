import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import timedelta

from dotenv import load_dotenv
import yaml
import hvac  # HashiCorp Vault client

# Load environment variables from .env file
load_dotenv()

# Define paths and API keys directly from environment variables
RADARE2_PATH = os.getenv("RADARE2_PATH", "/usr/bin/r2")
CUCKOO_PATH = os.getenv("CUCKOO_PATH", "/home/kali/cuckoo/venv")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
MALTIVERSE_API_KEY = os.getenv("MALTIVERSE_API_KEY")
IBMXFORCE_API_KEY = os.getenv("IBMXFORCE_API_KEY")


class ConfigError(Exception):
    """Custom exception for configuration errors"""
    pass


class SecretManager:
    """
    Advanced secret management with support for multiple backends
    """
    def __init__(self, 
                 backend: str = 'env', 
                 vault_url: Optional[str] = None, 
                 vault_token: Optional[str] = None):
        """
        Initialize secret manager
        """
        self.backend = backend
        self._vault_client = None
        
        if backend == 'vault' and vault_url and vault_token:
            try:
                self._vault_client = hvac.Client(
                    url=vault_url,
                    token=vault_token
                )
                if not self._vault_client.is_authenticated():
                    raise ConfigError("Vault authentication failed")
            except Exception as e:
                logging.error(f"Vault initialization error: {e}")
                raise ConfigError("Could not initialize Vault client")

    def get_secret(self, 
                   key: str, 
                   default: Optional[str] = None, 
                   namespace: str = 'default') -> str:
        """
        Retrieve secret from configured backend
        """
        try:
            if self.backend == 'env':
                return os.getenv(key, default)
            
            elif self.backend == 'vault' and self._vault_client:
                try:
                    secret = self._vault_client.secrets.kv.v2.read_secret_version(
                        path=f"{namespace}/{key}"
                    )
                    return secret['data']['data'].get(key, default)
                except Exception:
                    return default
            
            elif self.backend == 'file':
                config_path = os.getenv('SECRET_CONFIG_PATH', 'secrets.yaml')
                with open(config_path, 'r') as f:
                    secrets = yaml.safe_load(f)
                return secrets.get(namespace, {}).get(key, default)
            
            return default
        except Exception as e:
            logging.error(f"Secret retrieval error for {key}: {e}")
            return default


class Config:
    """
    Comprehensive configuration management with advanced features
    """
    _secret_manager = SecretManager(
        backend=os.getenv('SECRET_BACKEND', 'env'),
        vault_url=os.getenv('VAULT_URL'),
        vault_token=os.getenv('VAULT_TOKEN')
    )

    VERSION = '1.0.0'
    APPLICATION_NAME = 'MalDNA'
    SECRET_KEY = _secret_manager.get_secret('SECRET_KEY', 'development_secret')
    DEBUG = _secret_manager.get_secret('DEBUG', 'False').lower() == 'true'
    ENV = _secret_manager.get_secret('FLASK_ENV', 'development')

    # ✅ Malware Analysis Tools Paths (from .env)
    RADARE2_PATH = RADARE2_PATH
    CUCKOO_PATH = CUCKOO_PATH

    # ✅ External Threat Intelligence APIs (from .env)
    VIRUSTOTAL_API_KEY = VIRUSTOTAL_API_KEY
    HYBRID_ANALYSIS_API_KEY = HYBRID_ANALYSIS_API_KEY
    MALTIVERSE_API_KEY = MALTIVERSE_API_KEY
    IBMXFORCE_API_KEY = IBMXFORCE_API_KEY

    MONGODB_SETTINGS = {
        'host': _secret_manager.get_secret('MONGODB_URI', 'mongodb://maldna_user:maldna@cluster0-shard-00-00.nb5dt.mongodb.net:27017,cluster0-shard-00-01.nb5dt.mongodb.net:27017,cluster0>'),
        'db': _secret_manager.get_secret('MONGODB_DB', 'maldna'),
        'username': _secret_manager.get_secret('MONGODB_USERNAME'),
        'password': _secret_manager.get_secret('MONGODB_PASSWORD'),
        'authentication_source': _secret_manager.get_secret('MONGODB_AUTH_SOURCE', 'admin')
    }

    # Change log directory to a user-accessible location
    LOG_DIR = os.path.expanduser("~/MalDNA/logs")
    os.makedirs(LOG_DIR, exist_ok=True)  # Ensure the log directory exists

    LOGGING_CONFIG = {
        'level': _secret_manager.get_secret('LOG_LEVEL', 'INFO'),
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': os.path.join(LOG_DIR, 'backend.log')
    }

    @classmethod
    def get_config_dict(cls) -> Dict[str, Any]:
        return {
            key: value 
            for key, value in cls.__dict__.items() 
            if not key.startswith('_') and not callable(value)
        }


# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOGGING_CONFIG['level']),
    format=Config.LOGGING_CONFIG['format']
)

# Add file handler for logging
file_handler = logging.FileHandler(Config.LOGGING_CONFIG['file'])
logging.getLogger().addHandler(file_handler)


def load_config(app=None) -> Dict[str, Any]:
    """
    Load and return the application configuration as a dictionary.
    
    Args:
        app: Optional argument for passing the Flask app instance.
    """
    return Config.get_config_dict()

