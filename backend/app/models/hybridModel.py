import hashlib
import json
import logging
import uuid
from datetime import datetime
from app.services.blockchainService import BlockchainService
from mongoengine import (
    Document, StringField, DictField, DateTimeField,
    FloatField, ListField, BooleanField, ValidationError
)

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Blockchain instance
blockchain_service = BlockchainService()

class HybridAnalysisReport(Document):
    file_path = StringField(required=True)
    sample_id = StringField(required=True, unique=True)
    sample_hash = StringField(required=True, unique=True)
    file_name = StringField(required=False)

    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)  # Added the updated_at field
    timestamp = DateTimeField(default=datetime.utcnow)
    analysis_time = DateTimeField(default=datetime.utcnow)

    prediction = StringField(choices=["benign", "malicious", "suspicious"])
    classification_result = StringField()
    malware_type = StringField()

    risk_score = FloatField(min_value=0.0, max_value=100.0, default=0.0)
    reputation_score = FloatField(default=0.0)

    static_features = DictField()
    dynamic_features = DictField()
    hybrid_features = DictField()

    static_analysis = DictField()
    dynamic_analysis = DictField()
    hybrid_analysis = DictField()

    malware_dna = StringField()
    related_samples = ListField(StringField())
    lineage_info = DictField()

    classification = StringField(required=False)
    result_timestamp = DateTimeField(default=datetime.utcnow)

    blockchain_verification = DictField(default={})
    blockchain_verified = BooleanField(default=False)

    meta = {
        "collection": "hybrid_analysis_reports",
        "indexes": ["file_path", "sample_id", "sample_hash", "malware_type", "classification_result", "created_at"],
        "ordering": ["-created_at"],
        "strict": True
    }

    def save_report(self):
        try:
            if not self.sample_id:
                self.sample_id = str(uuid.uuid4())
                logger.warning(f"⚠️ Auto-generated sample_id: {self.sample_id}")

            if not self.sample_hash:
                logger.error("❌ sample_hash is required and is missing!")
                raise ValueError("sample_hash is required")

            existing = HybridAnalysisReport.objects(sample_hash=self.sample_hash).first()
            if existing and str(existing.id) != str(self.id):
                raise ValueError(f"Duplicate sample_hash: {self.sample_hash}")

            if self.classification and not isinstance(self.classification, str):
                logger.warning(f"⚠️ Invalid classification value: {self.classification}. Converting to string.")
                self.classification = str(self.classification)

            if self.prediction not in ["benign", "malicious", "suspicious"]:
                logger.warning(f"⚠️ Invalid prediction '{self.prediction}', setting to 'suspicious'")
                self.prediction = "suspicious"

            for field_name in ['static_features', 'dynamic_features', 'hybrid_features', 'lineage_info']:
                val = getattr(self, field_name, None)
                if not isinstance(val, dict):
                    logger.warning(f"⚠️ {field_name} not a dict, defaulting to empty dict")
                    setattr(self, field_name, {})

            if isinstance(self.classification_result, dict):
                self.classification_result = str(self.classification_result)
            if isinstance(self.malware_type, dict):
                self.malware_type = str(self.malware_type)

            logger.info(f"📥 Saving report for sample_id: {self.sample_id}")
            self.updated_at = datetime.utcnow()  # Set the updated_at field when saving
            self.save()

            hash_data = hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True, default=str).encode()).hexdigest()
            tx_id = blockchain_service.store_data_on_blockchain(hash_data)

            self.blockchain_verification = {
                "tx_id": tx_id,
                "verified": True,
                "timestamp": datetime.utcnow()
            }
            self.blockchain_verified = True
            self.save()

            logger.info(f"✅ Blockchain TX saved: {tx_id}")

        except ValidationError as ve:
            logger.error(f"❌ MongoEngine validation error: {ve}")
            raise
        except ValueError as ve:
            logger.error(f"❌ Value error: {ve}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}")
            raise

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "sample_id": self.sample_id,
            "sample_hash": self.sample_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,  # Include updated_at in to_dict
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "analysis_time": self.analysis_time.isoformat() if self.analysis_time else None,
            "prediction": self.prediction,
            "classification_result": self.classification_result,
            "malware_type": self.malware_type,
            "risk_score": self.risk_score,
            "reputation_score": self.reputation_score,
            "static_features": self.static_features or {},
            "dynamic_features": self.dynamic_features or {},
            "hybrid_features": self.hybrid_features or {},
            "static_analysis": self.static_analysis or {},
            "dynamic_analysis": self.dynamic_analysis or {},
            "hybrid_analysis": self.hybrid_analysis or {},
            "malware_dna": self.malware_dna,
            "related_samples": self.related_samples or [],
            "lineage_info": self.lineage_info or {},
            "blockchain_verified": self.blockchain_verified,
            "blockchain_verification": self.blockchain_verification or {},
            "classification": self.classification,
            "result_timestamp": self.result_timestamp.isoformat() if self.result_timestamp else None
        }

    @classmethod
    def load_from_database(cls, sample_id: str):
        try:
            return cls.objects.get(sample_id=sample_id)
        except cls.DoesNotExist:
            try:
                return cls.objects.get(sample_hash=sample_id)
            except Exception as e:
                logger.error(f"❌ Could not find report by sample_id or sample_hash '{sample_id}': {e}")
                return None

    def is_blockchain_verified(self) -> bool:
        return self.blockchain_verification.get("verified", False)

