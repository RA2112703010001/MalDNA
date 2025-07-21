# threatmodel.py

import uuid
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

from mongoengine import (
    Document, StringField, DateTimeField, ListField, DictField,
    BooleanField, FloatField, EmbeddedDocument, EmbeddedDocumentField, ValidationError
)

# --------------------------------------------------------
# 🔧 Logging Configuration
# --------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------
# 📚 Threat Metadata Model
# --------------------------------------------------------
class ThreatMetadata(EmbeddedDocument):
    metadata_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    category = StringField(required=True)
    description = StringField()
    confidence_score = FloatField(default=0.5, min_value=0.0, max_value=1.0)
    created_at = DateTimeField(default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata_id": self.metadata_id,
            "category": self.category,
            "description": self.description,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at.isoformat()
        }

# --------------------------------------------------------
# 🧬 Indicator of Compromise (IoC)
# --------------------------------------------------------
class IndicatorOfCompromise(EmbeddedDocument):
    ioc_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    type = StringField(
        required=True,
        choices=["ip", "domain", "hash", "url", "email", "file_path", "registry_key"]
    )
    value = StringField(required=True, unique=True)
    confidence = FloatField(default=0.5, min_value=0.0, max_value=1.0)
    first_seen = DateTimeField(default=datetime.utcnow)
    last_seen = DateTimeField(default=datetime.utcnow)
    description = StringField()

    def clean(self):
        if self.confidence < 0 or self.confidence > 1:
            raise ValidationError("Confidence must be between 0 and 1.")
        if self.last_seen < self.first_seen:
            raise ValidationError("Last seen cannot be earlier than first seen.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description
        }

# --------------------------------------------------------
# 🧠 Threat Intelligence Model
# --------------------------------------------------------
class ThreatIntel(Document):
    intel_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    malware_family = StringField()
    threat_actor = StringField()
    attack_vector = StringField()
    
    indicators_of_compromise = ListField(EmbeddedDocumentField(IndicatorOfCompromise))
    ai_prediction = StringField(choices=["benign", "malicious", "suspicious"], default="suspicious")
    ai_confidence = FloatField(min_value=0.0, max_value=1.0, default=0.0)

    metadata = EmbeddedDocumentField(ThreatMetadata, default=None)

    first_seen = DateTimeField()
    last_seen = DateTimeField(default=datetime.utcnow)
    tags = ListField(StringField())
    
    blockchain_verification = DictField(default={"tx_id": None, "verified": False, "timestamp": None})

    meta = {
        "indexes": [
            "intel_id",
            "malware_family",
            "threat_actor",
            "attack_vector",
            "tags"
        ],
        "ordering": ["-last_seen"],
        "strict": True
    }

    def clean(self):
        if self.first_seen and self.first_seen > self.last_seen:
            raise ValidationError("First seen timestamp cannot be later than last seen.")

    def compute_threat_score(self) -> float:
        """Compute threat severity based on AI confidence, IoCs, and metadata."""
        ioc_weight = sum([ioc.confidence for ioc in self.indicators_of_compromise])
        meta_weight = self.metadata.confidence_score if self.metadata else 0.5
        score = (self.ai_confidence * 0.5) + (ioc_weight * 0.3) + (meta_weight * 0.2)
        return round(min(score, 1.0), 4)

    def correlate_tags(self) -> List[str]:
        """Return meaningful tags based on AI and metadata."""
        tags = set(self.tags or [])
        if self.ai_prediction == "malicious":
            tags.update(["high-risk", "critical"])
        elif self.ai_prediction == "suspicious":
            tags.update(["needs-review"])
        if self.metadata:
            tags.add(self.metadata.category.lower())
        return list(tags)

    @classmethod
    def bulk_retrieve(cls, limit: int = 50) -> List['ThreatIntel']:
        return cls.objects.limit(limit)

    @classmethod
    def correlate_iocs(cls, ioc_value: str) -> List['ThreatIntel']:
        return cls.objects(indicators_of_compromise__value=ioc_value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intel_id": self.intel_id,
            "malware_family": self.malware_family,
            "threat_actor": self.threat_actor,
            "attack_vector": self.attack_vector,
            "ai_prediction": self.ai_prediction,
            "ai_confidence": self.ai_confidence,
            "indicators_of_compromise": [ioc.to_dict() for ioc in self.indicators_of_compromise],
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat(),
            "tags": self.correlate_tags(),
            "computed_threat_score": self.compute_threat_score(),
            "blockchain_verification": self.blockchain_verification
        }

# --------------------------------------------------------
# ⚠️ Threat Event Model
# --------------------------------------------------------
class ThreatEvent(Document):
    event_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    event_type = StringField(
        required=True,
        choices=[
            "file_modification", "network_intrusion",
            "privilege_escalation", "data_breach",
            "malware_execution", "ransomware_activity"
        ]
    )
    severity = StringField(required=True, choices=["low", "medium", "high", "critical"], default="low")
    impact_level = FloatField(min_value=0.0, max_value=1.0, default=0.0)

    timestamp = DateTimeField(default=datetime.utcnow)
    detected_at = DateTimeField(default=datetime.utcnow)

    source_info = DictField(default={"ip": None, "geolocation": None, "reputation_score": 0.0})
    target_system = DictField(default={"hostname": None, "platform": None, "vulnerabilities": []})
    
    iocs = ListField(EmbeddedDocumentField(IndicatorOfCompromise))
    
    risk_score = FloatField(min_value=0.0, max_value=100.0, default=0.0)
    
    blockchain_verification = DictField(default={"tx_id": None, "verified": False, "timestamp": None})
    tags = ListField(StringField())

    meta = {
        "indexes": [
            "event_id",
            "severity",
            "timestamp",
            "event_type",
            ("source_info.ip", "source_info.geolocation"),
            "tags"
        ],
        "ordering": ["-timestamp"],
        "strict": True
    }

    def clean(self):
        if self.risk_score == 0.0:
            self._calculate_risk_score()
        if self.detected_at < self.timestamp:
            raise ValidationError("Detected timestamp cannot be before event timestamp.")

    def _calculate_risk_score(self):
        base_score = {"low": 10, "medium": 50, "high": 75, "critical": 100}.get(self.severity, 0)
        impact_multiplier = self.impact_level * 1.5
        ioc_multiplier = min(len(self.iocs) * 5, 25)
        self.risk_score = min(base_score * impact_multiplier + ioc_multiplier, 100.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "impact_level": self.impact_level,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp.isoformat(),
            "detected_at": self.detected_at.isoformat(),
            "source_info": self.source_info,
            "target_system": self.target_system,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "blockchain_verification": self.blockchain_verification,
            "tags": self.tags
        }

