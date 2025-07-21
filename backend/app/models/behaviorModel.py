import os
import uuid
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
import networkx as nx
import numpy as np

from mongoengine import (
    Document, StringField, DateTimeField, ListField, DictField,
    BooleanField, FloatField, IntField, EmbeddedDocument, EmbeddedDocumentField, ValidationError
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --------------------------------------------------------
# 🛠️ **API Call Logging Model**
# --------------------------------------------------------
class APICallLog(EmbeddedDocument):
    """Detailed API call tracking."""
    
    log_id = StringField(default=lambda: str(uuid.uuid4()))  # No primary_key
    timestamp = DateTimeField(default=datetime.utcnow)
    api_name = StringField(required=True)
    module = StringField()
    parameters = DictField()
    return_value = StringField()
    is_suspicious = BooleanField(default=False)

    def clean(self):
        if not self.api_name:
            raise ValidationError("API name is required")


# --------------------------------------------------------
# 🌐 **Network Activity Logging Model**
# --------------------------------------------------------
class NetworkActivityLog(EmbeddedDocument):
    """Comprehensive network activity tracking."""
    
    log_id = StringField(default=lambda: str(uuid.uuid4()))  # No primary_key
    timestamp = DateTimeField(default=datetime.utcnow)
    remote_ip = StringField()
    remote_port = IntField()
    protocol = StringField()
    direction = StringField(choices=["inbound", "outbound"])
    bytes_transferred = IntField(default=0)
    connection_type = StringField()
    is_malicious = BooleanField(default=False)


# --------------------------------------------------------
# ⚙️ **System Modification Logging Model**
# --------------------------------------------------------
class SystemModificationLog(EmbeddedDocument):
    """Detailed system modification tracking."""
    
    log_id = StringField(default=lambda: str(uuid.uuid4()))  # No primary_key
    timestamp = DateTimeField(default=datetime.utcnow)
    modification_type = StringField(choices=[
        "file_creation", "file_deletion", "file_modification",
        "registry_key_creation", "registry_key_modification",
        "process_injection", "service_modification"
    ])
    target_path = StringField()
    details = DictField()
    is_critical = BooleanField(default=False)


# --------------------------------------------------------
# 🧠 **Behavior Model for Malware Tracking**
# --------------------------------------------------------
class BehaviorModel(Document):
    """Advanced Malware Behavior Tracking Model."""
    
    _id = StringField(default=lambda: str(uuid.uuid4()))  # ✅ Use `_id` as primary key
    sample_id = StringField(required=True)
    platform = StringField(choices=["windows", "linux", "android", "macos", "ios", "embedded"])
    collected_at = DateTimeField(default=datetime.utcnow)

    # 🛡️ **Behavior Tracking**
    api_calls = ListField(EmbeddedDocumentField(APICallLog), default=list)
    network_activities = ListField(EmbeddedDocumentField(NetworkActivityLog), default=list)
    system_modifications = ListField(EmbeddedDocumentField(SystemModificationLog), default=list)

    # 📊 **Threat Intelligence & Analysis**
    behavior_categories = ListField(StringField())
    threat_level = StringField(choices=["low", "medium", "high", "critical"], default="low")
    anomaly_score = FloatField(default=0.0)
    is_suspicious = BooleanField(default=False)
    is_anomalous = BooleanField(default=False)

    # 🔄 **Correlation & Intelligence**
    correlated_malware_families = ListField(StringField())
    threat_intelligence = DictField(default={"sources": [], "confidence_score": 0.0, "global_tags": []})

    # 🔗 **Blockchain Verification**
    blockchain_verification = DictField(default={"tx_id": None, "verified": False, "timestamp": None})

    # 📈 **Advanced Behavior Analysis**
    behavior_graph = DictField(default={"nodes": [], "edges": []})
    last_updated = DateTimeField(default=datetime.utcnow)

    # 📑 **Report Fields**
    file_path = StringField(required=True)  # Keep required
    report = DictField(required=True)  # Required to store analysis data

    # 📌 **Indexing & Optimization**
    meta = {
        "indexes": [
            {"fields": ["sample_id"]},  
            {"fields": ["sample_id", "platform"]},  
            {"fields": ["platform"]},  
            {"fields": ["threat_level"]},  
            {"fields": ["is_suspicious", "anomaly_score"]}  
        ],
        "ordering": ["-collected_at"],
        "strict": False  
    }

    def clean(self):
        """Perform validation before saving the object."""
        self.last_updated = datetime.utcnow()
        self._calculate_anomaly_score()

        if not self.sample_id:
            raise ValidationError("sample_id is required and cannot be empty.")

        for api_call in self.api_calls:
            api_call.clean()
        for network_activity in self.network_activities:
            self._validate_network_activity(network_activity)

    # --------------------------------------------------------
    # 🔍 **Behavior Anomaly Detection**
    # --------------------------------------------------------
    def _calculate_anomaly_score(self):
        """Calculate an anomaly score based on API calls, network activity, and system modifications."""
        try:
            suspicious_api_calls = sum(1 for call in self.api_calls if call.is_suspicious)
            malicious_network_activities = sum(1 for act in self.network_activities if act.is_malicious)
            critical_modifications = sum(1 for mod in self.system_modifications if mod.is_critical)

            self.anomaly_score = min(
                (suspicious_api_calls * 0.4) + 
                (malicious_network_activities * 0.3) + 
                (critical_modifications * 0.3), 
                1.0
            )
            self.is_suspicious = self.anomaly_score > 0.5
            self.is_anomalous = self.anomaly_score > 0.7
        except Exception as e:
            logger.error(f"Anomaly score calculation failed: {e}")

    def _validate_network_activity(self, network_activity: NetworkActivityLog):
        """Validate network activity data."""
        if network_activity.remote_ip and not self._validate_ip(network_activity.remote_ip):
            raise ValidationError("Invalid IP address")
        if network_activity.remote_port and (network_activity.remote_port < 0 or network_activity.remote_port > 65535):
            raise ValidationError("Invalid port number")

    def _validate_ip(self, ip: str) -> bool:
        """Validate an IP address."""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    # --------------------------------------------------------
    # 📊 **Behavior Graph Generation**
    # --------------------------------------------------------
    def generate_behavior_graph(self):
        """Generate a behavior graph from API calls and network activities."""
        try:
            G = nx.DiGraph()
            for api_call in self.api_calls:
                G.add_node(api_call.api_name, type='api_call', suspicious=api_call.is_suspicious)
            for network_activity in self.network_activities:
                G.add_node(network_activity.remote_ip, type='network', malicious=network_activity.is_malicious)

            self.behavior_graph = {
                "nodes": [dict(node) for node in G.nodes(data=True)],  # Ensure JSON compatibility
                "edges": list(G.edges())
            }
            self.save()
        except Exception as e:
            logger.error(f"Behavior graph generation failed: {e}")

    def to_dict(self):
        """Convert behavior model data to a dictionary."""
        return {
            "_id": self._id,  # ✅ Fixed key name
            "sample_id": self.sample_id,
            "platform": self.platform,
            "threat_level": self.threat_level,
            "anomaly_score": self.anomaly_score,
            "is_suspicious": self.is_suspicious,
            "is_anomalous": self.is_anomalous,
            "file_path": self.file_path,
            "report": self.report
        }

