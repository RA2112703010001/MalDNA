import os
import uuid
import json
import logging
import networkx as nx
import plotly.graph_objs as go
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from mongoengine import (
    Document, EmbeddedDocument, EmbeddedDocumentField, StringField,
    DateTimeField, DictField, FloatField, ListField, BooleanField, ValidationError
)

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# -------------------------------------
# 🧩 Subdocuments (Reusable Structures)
# -------------------------------------

class IngestionMetadata(EmbeddedDocument):
    """Metadata for automated ingestion."""
    job_id = StringField(default=lambda: str(uuid.uuid4()), primary_key=True)
    source_path = StringField(required=True)
    ingestion_time = DateTimeField(default=datetime.utcnow)
    processed = BooleanField(default=False)
    notes = StringField()
    error_message = StringField()

class AIClassification(EmbeddedDocument):
    """AI-driven malware classification result."""
    model_version = StringField(required=True)
    predicted_label = StringField()
    confidence_score = FloatField(min_value=0.0, max_value=1.0)
    feature_vector = DictField()

class ProcessEvent(EmbeddedDocument):
    """A single event in process behavior."""
    pid = StringField()
    process_name = StringField()
    command_line = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)
    is_suspicious = BooleanField(default=False)

class MemoryArtifact(EmbeddedDocument):
    """Artifacts found in memory during analysis."""
    artifact_type = StringField()
    value = StringField()
    risk_score = FloatField(min_value=0.0, max_value=10.0)
    timestamp = DateTimeField(default=datetime.utcnow)

class IncidentTimeline(EmbeddedDocument):
    """Chronology of forensic events."""
    event_description = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)
    severity = StringField(choices=["low", "medium", "high"], default="low")

class ForensicMetadata:
    """
    Lightweight metadata structure for exporting forensic context to other modules.
    Useful in dataset service, sample labeling, blockchain storage, etc.
    """
    def __init__(self, sample_id, evidence, source, collected_by, timestamp=None):
        self.sample_id = sample_id
        self.evidence = evidence
        self.source = source
        self.collected_by = collected_by
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self):
        return {
            "sample_id": ObjectId(self.sample_id) if not isinstance(self.sample_id, ObjectId) else self.sample_id,
            "evidence": self.evidence,
            "source": self.source,
            "collected_by": self.collected_by,
            "timestamp": self.timestamp
        }
# -------------------------------------
# 🧬 ForensicModel Document
# -------------------------------------

class ForensicModel(Document):
    """Memory and disk forensic analysis result model."""
    forensic_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    sample_id = StringField(required=True)
    platform = StringField(choices=["windows", "linux", "macos", "android", "ios", "embedded"])
    collected_at = DateTimeField(default=datetime.utcnow)

    # 🧩 Ingestion
    ingestion_metadata = EmbeddedDocumentField(IngestionMetadata)

    # 🧠 AI Classification
    ai_classification = EmbeddedDocumentField(AIClassification)

    # 🧱 Memory Dump
    memory_dump = DictField(default={"path": None, "size": 0, "hash": None, "compression_method": None})

    # 🔍 Artifacts & Events
    process_events = ListField(EmbeddedDocumentField(ProcessEvent), default=list)
    memory_artifacts = ListField(EmbeddedDocumentField(MemoryArtifact), default=list)
    incident_timeline = ListField(EmbeddedDocumentField(IncidentTimeline), default=list)

    # 🚨 Threat Indicators
    persistence_mechanisms = ListField(DictField(), default=list)
    stealth_techniques = ListField(StringField(), default=list)
    detection_flags = DictField(default={
        "shellcode": False, "rootkit": False, "backdoor": False,
        "code_injection": False, "hidden_processes": False
    })

    # 🌐 Threat Intel
    threat_intelligence = DictField(default={"sources": [], "confidence_score": 0.0, "global_tags": []})

    # 🔗 Blockchain Proof
    blockchain_verification = DictField(default={"tx_id": None, "verified": False, "timestamp": None})

    # 🧠 Graphs
    attack_graph = DictField(default={"nodes": [], "edges": []})

    # 📊 Risk Score
    risk_score = FloatField(min_value=0.0, max_value=100.0, default=0.0)

    # 📄 Report Export
    exported_report = DictField(default={"format": None, "exported_at": None, "path": None})

    # 🔄 Updated
    last_updated = DateTimeField(default=datetime.utcnow)

    meta = {
        "indexes": ["forensic_id", "sample_id", "platform"],
        "ordering": ["-collected_at"],
        "strict": True
    }

    # ----------------------------
    # 🔢 Risk Score Logic
    # ----------------------------
    def clean(self):
        self.last_updated = datetime.utcnow()
        self._calculate_risk_score()
        self._validate_memory_dump()

    def _calculate_risk_score(self):
        try:
            risk_multipliers = {
                "shellcode": 25, "rootkit": 30,
                "backdoor": 35, "code_injection": 20, "hidden_processes": 15
            }
            base_risk = sum(
                risk_multipliers.get(flag, 0) for flag, detected in self.detection_flags.items() if detected
            )
            artifact_risk = sum(artifact.risk_score * 10 for artifact in self.memory_artifacts)

            ai_risk = 0
            if self.ai_classification and self.ai_classification.confidence_score:
                ai_risk = self.ai_classification.confidence_score * 25

            self.risk_score = min(base_risk + artifact_risk + ai_risk, 100.0)
        except Exception as e:
            logger.error(f"Risk score error: {e}")

    def _validate_memory_dump(self):
        try:
            if self.memory_dump.get('path') and not os.path.exists(self.memory_dump['path']):
                raise ValidationError("Memory dump file does not exist")
        except Exception as e:
            logger.error(f"Memory dump validation error: {e}")

    # ----------------------------
    # 🕸️ Attack Graph Builder
    # ----------------------------
    def generate_attack_graph(self):
        try:
            G = nx.DiGraph()
            for event in self.process_events:
                G.add_node(event.process_name, type="process", suspicious=event.is_suspicious)

            for artifact in self.memory_artifacts:
                G.add_node(artifact.artifact_type, type="artifact", risk_score=artifact.risk_score)

            events = sorted(self.process_events + self.memory_artifacts, key=lambda x: x.timestamp)
            for i in range(len(events) - 1):
                src = getattr(events[i], 'process_name', getattr(events[i], 'artifact_type', 'Unknown'))
                dst = getattr(events[i+1], 'process_name', getattr(events[i+1], 'artifact_type', 'Unknown'))
                G.add_edge(src, dst)

            self.attack_graph = {
                "nodes": list(G.nodes(data=True)),
                "edges": list(G.edges())
            }
            self.save()
            return self.attack_graph
        except Exception as e:
            logger.error(f"Attack graph generation error: {e}")
            return {}

    # ----------------------------
    # 📄 Report Export (PDF/JSON)
    # ----------------------------
    def export_report(self, format: str = "pdf") -> str:
        try:
            export_dir = os.path.join("reports", self.platform)
            os.makedirs(export_dir, exist_ok=True)
            export_path = os.path.join(export_dir, f"forensic_{self.forensic_id}.{format.lower()}")

            if format.lower() == "json":
                with open(export_path, "w") as json_file:
                    json.dump(self.to_mongo(), json_file, indent=4, default=str)
            elif format.lower() == "pdf":
                c = canvas.Canvas(export_path, pagesize=letter)
                c.setFont("Helvetica", 10)
                c.drawString(100, 750, f"Forensic Report: {self.forensic_id}")
                c.drawString(100, 735, f"Platform: {self.platform}")
                c.drawString(100, 720, f"Sample ID: {self.sample_id}")
                c.drawString(100, 705, f"Collected At: {self.collected_at}")
                c.drawString(100, 690, f"Risk Score: {self.risk_score}")
                c.drawString(100, 675, f"AI Label: {self.ai_classification.predicted_label if self.ai_classification else 'N/A'}")
                c.drawString(100, 660, f"Ingested: {self.ingestion_metadata.source_path if self.ingestion_metadata else 'Manual'}")
                c.drawString(100, 645, "...")
                c.save()
            else:
                raise ValueError("Unsupported format")

            self.exported_report = {
                "format": format,
                "exported_at": datetime.utcnow(),
                "path": export_path
            }
            self.save()
            logger.info(f"Exported report to: {export_path}")
            return export_path
        except Exception as e:
            logger.error(f"Report export error: {e}")
            return ""

