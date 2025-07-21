import os
import hashlib
import logging
import shutil
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("file_processing.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Malware Storage Path
MALWARE_DIR = os.path.join(os.path.dirname(__file__), "..", "malware_samples")
os.makedirs(MALWARE_DIR, exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {".exe", ".dll", ".bin", ".apk", ".elf", ".mach-o", ".sh", ".py"}


# ----------------------------------------------------------
# ✅ **Malware File Processing**
# ----------------------------------------------------------
def preprocess_malware_file(file_path: str, model_type: Optional[str] = None) -> Dict:
    """
    Preprocess a malware file for analysis or classification.
    
    Args:
        file_path (str): Path to the malware file.
        model_type (Optional[str]): Type of model (e.g., 'hybrid', 'deep_learning').
    
    Returns:
        Dict: Preprocessed data containing features and metadata.
    """
    try:
        # Validate file path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file content
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        # Generate file hash
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Extract basic metadata
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(file_path)[1].lower()
        
        # Validate file type
        if file_extension not in ALLOWED_EXTENSIONS:
            raise ValueError(f"Unsupported file extension: {file_extension}")

        # Store metadata
        metadata = {
            "file_hash": file_hash,
            "file_size": file_size,
            "file_extension": file_extension,
            "model_type": model_type
        }

        logger.info(f"Preprocessed malware file: {file_path}")
        return metadata
    except Exception as e:
        logger.error(f"Malware file preprocessing failed: {e}")
        raise


# ----------------------------------------------------------
# ✅ **File Validation & Security Checks**
# ----------------------------------------------------------
def validate_file(file_path: str) -> bool:
    """
    Validate a file for processing.
    
    Args:
        file_path (str): Path to the file.
    
    Returns:
        bool: True if the file is valid, False otherwise.
    """
    try:
        if not os.path.exists(file_path):
            logger.warning(f"File validation failed: File not found ({file_path})")
            return False
        
        if not os.access(file_path, os.R_OK):
            logger.warning(f"File validation failed: File not readable ({file_path})")
            return False
        
        # Additional validation logic (e.g., file size, type)
        max_file_size = 16 * 1024 * 1024  # 16 MB
        if os.path.getsize(file_path) > max_file_size:
            logger.warning(f"File validation failed: File too large ({file_path})")
            return False
        
        # Verify file extension
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            logger.warning(f"File validation failed: Unsupported file extension ({file_extension})")
            return False

        logger.info(f"File validation succeeded: {file_path}")
        return True
    except Exception as e:
        logger.error(f"File validation error: {e}")
        return False


# ----------------------------------------------------------
# ✅ **CLI-Triggered Malware Sample Collection**
# ----------------------------------------------------------
def collect_malware_samples(database_samples: List[Dict]) -> List[Dict]:
    """
    Collect malware samples from a database and store them locally.
    
    Args:
        database_samples (List[Dict]): List of sample metadata from the database.
    
    Returns:
        List[Dict]: List of stored file metadata.
    """
    stored_samples = []

    for sample in database_samples:
        try:
            file_path = sample.get("file_path")
            if not file_path or not validate_file(file_path):
                logger.warning(f"Skipping invalid file: {file_path}")
                continue

            # Move file to malware directory
            stored_path = os.path.join(MALWARE_DIR, os.path.basename(file_path))
            shutil.copy(file_path, stored_path)

            # Extract metadata
            file_metadata = preprocess_malware_file(stored_path)
            stored_samples.append(file_metadata)
            logger.info(f"Stored malware sample: {stored_path}")

        except Exception as e:
            logger.error(f"Error processing malware sample: {e}")

    return stored_samples


# ----------------------------------------------------------
# ✅ **Bulk Malware Sample Retrieval via CLI**
# ----------------------------------------------------------
def retrieve_bulk_samples(sample_hashes: List[str]) -> List[str]:
    """
    Retrieve malware samples from local storage based on their hashes.
    
    Args:
        sample_hashes (List[str]): List of malware sample hashes.
    
    Returns:
        List[str]: Paths to retrieved samples.
    """
    retrieved_files = []

    for file_name in os.listdir(MALWARE_DIR):
        file_path = os.path.join(MALWARE_DIR, file_name)

        try:
            if not validate_file(file_path):
                continue

            # Compute file hash
            with open(file_path, "rb") as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()

            if file_hash in sample_hashes:
                retrieved_files.append(file_path)
                logger.info(f"Retrieved sample: {file_path}")

        except Exception as e:
            logger.error(f"Error retrieving sample {file_path}: {e}")

    return retrieved_files


# ----------------------------------------------------------
# ✅ **File Cleanup for Expired Malware Samples**
# ----------------------------------------------------------
def cleanup_expired_samples(days_threshold: int = 30) -> int:
    """
    Remove malware samples older than the specified threshold.
    
    Args:
        days_threshold (int): Number of days before a file is considered expired.
    
    Returns:
        int: Number of deleted files.
    """
    deleted_count = 0
    current_time = datetime.now().timestamp()

    for file_name in os.listdir(MALWARE_DIR):
        file_path = os.path.join(MALWARE_DIR, file_name)

        try:
            if not validate_file(file_path):
                continue

            # Check file age
            file_age_days = (current_time - os.path.getctime(file_path)) / 86400
            if file_age_days > days_threshold:
                os.remove(file_path)
                deleted_count += 1
                logger.info(f"Deleted expired sample: {file_path}")

        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")

    return deleted_count

