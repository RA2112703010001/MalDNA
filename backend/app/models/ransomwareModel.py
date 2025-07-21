import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List

# MongoDB Integration
from mongoengine import (
    Document, StringField, DictField, DateTimeField, FloatField, BooleanField, ListField, EmbeddedDocument, EmbeddedDocumentField
)

# Blockchain Integration
from app.services.blockchainService import blockchain_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------
# 📂 **Embedded Document for Ransomware Encryption Details**
# --------------------------------------------------------
class EncryptionPattern(EmbeddedDocument):
    """
    Stores encryption details observed in ransomware attacks.
    """
    pattern_id = StringField(primary_key=True, default=lambda: hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest())
    algorithm = StringField(required=True, choices=["AES", "RSA", "ChaCha20", "Blowfish", "Unknown"])
    key_length = StringField(default="Unknown")
    file_extensions = ListField(StringField())  # Tracks encrypted file extensions
    encryption_behavior = DictField(default={})  # Observed behaviors (e.g., full-disk encryption, targeted files)

# --------------------------------------------------------
# 📂 **Embedded Document for File Modifications**
# --------------------------------------------------------
class FileModification(EmbeddedDocument):
    """
    Stores details about files modified by ransomware.
    """
    modification_id = StringField(primary_key=True, default=lambda: hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest())
    affected_file = StringField(required=True)
    original_extension = StringField()
    new_extension = StringField()
    modification_timestamp = DateTimeField(default=datetime.utcnow)

# --------------------------------------------------------
# 📂 **Ransomware Analysis Model**
# --------------------------------------------------------
class RansomwareModel(Document):
    """
    Tracks ransomware behaviors, encryption patterns, and ransom notes.
    """

    # 🔗 **Unique Identifiers**
    ransomware_id = StringField(primary_key=True, default=lambda: hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest(), unique=True)
    sample_id = StringField(required=True, unique=True)  # Links to malware sample

    # 📌 **Attack Details**
    ransomware_family = StringField()
    attack_vector = StringField(choices=["phishing", "drive_by_download", "exploit", "RDP", "USB", "unknown"], default="unknown")
    affected_systems = ListField(StringField())  # IPs, hostnames, etc.

    # 🔐 **Encryption Patterns & File Modifications**
    encryption_details = ListField(EmbeddedDocumentField(EncryptionPattern), default=list)
    modified_files = ListField(EmbeddedDocumentField(FileModification), default=list)

    # 📝 **Ransom Notes & Demands**
    ransom_note = StringField()
    ransom_amount = FloatField(default=0.0)
    cryptocurrency_address = StringField()

    # 📊 **Threat Intelligence & Risk Assessment**
    threat_intelligence = DictField(default={"sources": [], "confidence_score": 0.0})
    risk_score = FloatField(min_value=0.0, max_value=100.0, default=0.0)

    # 🔗 **Blockchain Verification**
    blockchain_verification = DictField(default={"tx_id": None, "verified": False, "timestamp": None})

    # 📌 **Metadata**
    collected_at = DateTimeField(default=datetime.utcnow)
    last_updated = DateTimeField(default=datetime.utcnow)

    # 📌 **Indexing & Optimization**
    meta = {
        "indexes": ["ransomware_id", "sample_id", "ransomware_family", "attack_vector", "risk_score"],
        "ordering": ["-collected_at"],
        "strict": True
    }

    # --------------------------------------------------------
    # 🛠️ **Risk Score Calculation**
    # --------------------------------------------------------
    def calculate_risk_score(self):
        """
        Computes a risk score based on encryption patterns, attack vectors, and ransom demands.
        """
        base_risk = {"phishing": 30, "drive_by_download": 40, "exploit": 60, "RDP": 70, "USB": 50, "unknown": 20}.get(self.attack_vector, 20)
        encryption_factor = min(len(self.encryption_details) * 10, 50)
        ransom_factor = 20 if self.ransom_amount > 0 else 0
        self.risk_score = min(base_risk + encryption_factor + ransom_factor, 100)

    # --------------------------------------------------------
    # 🔗 **Blockchain Evidence Storage**
    # --------------------------------------------------------
    def store_on_blockchain(self):
        """
        Stores ransomware attack evidence on the blockchain.
        """
        try:
            blockchain_tx = blockchain_service.store_data_on_blockchain(json.dumps(self.to_dict()))
            self.blockchain_verification = {"tx_id": blockchain_tx, "verified": True, "timestamp": datetime.utcnow()}
            self.save()
            logger.info(f"Ransomware data stored on blockchain (TX: {blockchain_tx})")
        except Exception as e:
            logger.error(f"Blockchain storage failed: {e}")

    # --------------------------------------------------------
    # 📊 **Data Conversion & Queries**
    # --------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert ransomware model data to a dictionary.
        """
        return {
            "ransomware_id": self.ransomware_id,
            "sample_id": self.sample_id,
            "ransomware_family": self.ransomware_family,
            "attack_vector": self.attack_vector,
            "affected_systems": self.affected_systems,
            "encryption_details": [enc.to_mongo() for enc in self.encryption_details],
            "modified_files": [mod.to_mongo() for mod in self.modified_files],
            "ransom_note": self.ransom_note,
            "ransom_amount": self.ransom_amount,
            "cryptocurrency_address": self.cryptocurrency_address,
            "threat_intelligence": self.threat_intelligence,
            "risk_score": self.risk_score,
            "blockchain_verification": self.blockchain_verification,
            "collected_at": self.collected_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }

    @classmethod
    def retrieve_by_family(cls, ransomware_family: str) -> List[Dict[str, Any]]:
        """
        Retrieve ransomware cases by family.
        """
        try:
            cases = cls.objects(ransomware_family=ransomware_family)
            return [case.to_dict() for case in cases]
        except Exception as e:
            logger.error(f"Failed to retrieve ransomware cases: {e}")
            return []

    @classmethod
    def retrieve_recent_cases(cls, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Retrieve recent ransomware cases within the specified time window.
        """
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            cases = cls.objects(collected_at__gte=cutoff)
            return [case.to_dict() for case in cases]
        except Exception as e:
            logger.error(f"Failed to retrieve recent ransomware cases: {e}")
            return []

    @classmethod
    def retrieve_high_risk_cases(cls) -> List[Dict[str, Any]]:
        """
        Retrieve ransomware cases with high risk scores (>75).
        """
        try:
            cases = cls.objects(risk_score__gte=75)
            return [case.to_dict() for case in cases]
        except Exception as e:
            logger.error(f"Failed to retrieve high-risk ransomware cases: {e}")
            return []

