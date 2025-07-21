import os
import uuid
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional

from mongoengine import (
    Document, StringField, DateTimeField, BooleanField,
    DictField, FloatField, ListField, EmbeddedDocument,
    EmbeddedDocumentField
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# -----------------------------
# 🔍 AI-Based Anomaly Detection
# -----------------------------
class AnomalyDetection(EmbeddedDocument):
    anomaly_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = DateTimeField(default=datetime.utcnow)
    description = StringField()
    anomaly_type = StringField(choices=["behavioral", "network", "execution_flow", "file_system"])
    confidence_score = FloatField(min_value=0.0, max_value=1.0, default=0.0)
    indicators = DictField()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "anomaly_type": self.anomaly_type,
            "confidence_score": self.confidence_score,
            "indicators": self.indicators
        }

# -----------------------------
# 🚨 Live Alert Notification
# -----------------------------
class LiveAlert(EmbeddedDocument):
    alert_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = DateTimeField(default=datetime.utcnow)
    severity = StringField(choices=["low", "medium", "high", "critical"], default="low")
    threat_type = StringField()
    triggered_by = StringField()
    remediation_steps = ListField(StringField(), default=[])
    additional_info = DictField()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "threat_type": self.threat_type,
            "triggered_by": self.triggered_by,
            "remediation_steps": self.remediation_steps,
            "additional_info": self.additional_info
        }

# -----------------------------
# 📡 Real-Time Malware Model
# -----------------------------
class RealtimeAnalysisRecord(Document):
    timestamp = DateTimeField(default=datetime.utcnow)
    file_path = StringField(required=True)
    file_hash = StringField(unique=True, required=True)

    # Detection Results
    malware_detected = BooleanField(default=False)
    risk_score = FloatField(min_value=0.0, max_value=100.0, default=0.0)
    ai_confidence = FloatField(min_value=0.0, max_value=1.0, default=0.0)

    # Threat Indicators
    suspicious_behavior_detected = BooleanField(default=False)
    ransomware_activity_detected = BooleanField(default=False)
    zero_day_attack_detected = BooleanField(default=False)

    # AI Analysis
    anomalies_detected = ListField(EmbeddedDocumentField(AnomalyDetection), default=[])
    alerts_generated = ListField(EmbeddedDocumentField(LiveAlert), default=[])

    # Logs & Threats
    event_driven_alerts = ListField(DictField(), default=[])
    detected_threats = ListField(StringField(), default=[])
    analysis_details = DictField(default={})
    monitoring_logs = ListField(DictField(), default=[])

    # Blockchain
    blockchain_tx_id = StringField()
    blockchain_verified = BooleanField(default=False)

    meta = {
        "indexes": [
            "timestamp", "file_path", "file_hash",
            "malware_detected", "risk_score"
        ],
        "ordering": ["-timestamp"]
    }

    # -----------------------------
    # 🛠️ Utility Methods
    # -----------------------------
    def compute_file_hash(self):
        """Auto-compute SHA256 hash from file path if not provided"""
        try:
            with open(self.file_path, "rb") as f:
                file_data = f.read()
                self.file_hash = hashlib.sha256(file_data).hexdigest()
        except Exception as e:
            logger.error(f"Hash computation failed: {e}")

    def add_anomaly(self, description: str, anomaly_type: str, confidence_score: float, indicators: Dict[str, Any]):
        try:
            anomaly = AnomalyDetection(
                description=description,
                anomaly_type=anomaly_type,
                confidence_score=confidence_score,
                indicators=indicators
            )
            self.anomalies_detected.append(anomaly)
            self.save()
        except Exception as e:
            logger.error(f"Failed to add anomaly: {e}")

    def generate_alert(self, severity: str, threat_type: str, triggered_by: str, remediation_steps: List[str], additional_info: Optional[Dict[str, Any]] = None):
        try:
            alert = LiveAlert(
                severity=severity,
                threat_type=threat_type,
                triggered_by=triggered_by,
                remediation_steps=remediation_steps,
                additional_info=additional_info or {}
            )
            self.alerts_generated.append(alert)
            self.save()
        except Exception as e:
            logger.error(f"Failed to generate alert: {e}")

    def store_monitoring_log(self, log_entry: Dict[str, Any]):
        try:
            self.monitoring_logs.append(log_entry)
            self.save()
        except Exception as e:
            logger.error(f"Monitoring log storage failed: {e}")

    def verify_blockchain_entry(self, blockchain_tx_id: str):
        try:
            self.blockchain_tx_id = blockchain_tx_id
            self.blockchain_verified = True
            self.save()
        except Exception as e:
            logger.error(f"Blockchain verification failed: {e}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "malware_detected": self.malware_detected,
            "risk_score": self.risk_score,
            "ai_confidence": self.ai_confidence,
            "suspicious_behavior_detected": self.suspicious_behavior_detected,
            "ransomware_activity_detected": self.ransomware_activity_detected,
            "zero_day_attack_detected": self.zero_day_attack_detected,
            "anomalies_detected": [anomaly.to_dict() for anomaly in self.anomalies_detected],
            "alerts_generated": [alert.to_dict() for alert in self.alerts_generated],
            "blockchain_tx_id": self.blockchain_tx_id,
            "blockchain_verified": self.blockchain_verified,
            "event_driven_alerts": self.event_driven_alerts,
            "detected_threats": self.detected_threats,
            "analysis_details": self.analysis_details,
            "monitoring_logs": self.monitoring_logs
        }

