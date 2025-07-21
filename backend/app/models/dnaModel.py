import os
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any
import mongoengine
from mongoengine import (
    Document, StringField, DateTimeField, ListField, DictField, FloatField, BooleanField, EmbeddedDocument, EmbeddedDocumentField, ValidationError
)

# MongoDB Configuration
MONGODB_URI = "mongodb://127.0.0.1:27017/maldna_db"
DB_NAME = "maldna_db"
mongoengine.connect(DB_NAME, host=MONGODB_URI)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --------------------------- DNA Metadata ---------------------------
class DNAMetadata(EmbeddedDocument):
    """Stores DNA sequence metadata for malware samples."""
    metadataid = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    sample_id = StringField(required=True)
    source_sample_id = StringField(required=True)
    dna_sequence = StringField(required=True)
    metadata = DictField(default={})
    created_at = DateTimeField(default=datetime.utcnow)

# --------------------------- Mutation Tracking ---------------------------
class DNAMutation(EmbeddedDocument):
    """Tracks detailed DNA mutations."""
    mutation_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = DateTimeField(default=datetime.utcnow)
    description = StringField(required=True)
    mutation_type = StringField(choices=["opcode_change", "function_call_modification", "behavior_shift", "encoding_variation"])
    impact_score = FloatField(min_value=0.0, max_value=1.0, default=0.0)
    before = DictField()
    after = DictField()

    def clean(self):
        if not (0.0 <= self.impact_score <= 1.0):
            raise ValidationError("Impact score must be between 0 and 1")

# -------------------- DNA Signature Analysis Tracking --------------------
class DNASignatureAnalysis(EmbeddedDocument):
    """Tracks DNA signature analysis results."""
    analysis_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = DateTimeField(default=datetime.utcnow)
    analysis_type = StringField(choices=["static", "dynamic", "behavioral", "machine_learning", "correlation"])
    confidence_score = FloatField(min_value=0.0, max_value=1.0, default=0.5)
    results = DictField()
    anomaly_indicators = ListField(StringField())

# ---------------------------- Main DNA Model ----------------------------
class DNAModel(Document):
    malware_id = StringField(required=True, default=lambda: str(uuid.uuid4()))  # Auto-generate if not provided
    # Unique Identifiers
    dna_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    sample_id = StringField(required=True)
    source_sample_id = StringField(required=True)

    # Platform Information
    platform = StringField(choices=["windows", "linux", "android", "macos", "ios", "embedded"])
    collected_at = DateTimeField(default=datetime.utcnow)

    # Static & Dynamic DNA
    static_dna = DictField(default={"opcode_entropy": 0.0, "library_dependencies": [], "code_patterns": []})
    dynamic_dna = DictField(default={"behavior_profile": {}, "system_interaction": {}, "resource_usage": {}})

    # Opcode & Function Call Information
    opcode_sequence = ListField(StringField())
    function_calls = ListField(StringField())
    n_grams = ListField(StringField())

    # Mutation & Evolution Tracking
    mutations = ListField(EmbeddedDocumentField(DNAMutation), default=list)

    # Similarity & Clustering
    similarity_matrix = DictField(default={"levenshtein_scores": {}, "cosine_similarity": {}, "feature_vector_distance": {}})
    similarity_analysis_history = ListField(DictField(), default=list)

    # Phylogenetic Data
    phylogenetic_data = DictField(default={"evolutionary_path": [], "parent_signatures": [], "child_signatures": []})

    # Classification & Threat Intelligence
    family_name = StringField()
    group_assignment = StringField()
    threat_intelligence = DictField(default={"sources": [], "confidence_score": 0.0, "global_tags": []})

    # Blockchain Verification
    blockchain_verification = DictField(default={"tx_id": None, "verified": False, "timestamp": None})

    # Signature Analysis & Detection
    signature_analyses = ListField(EmbeddedDocumentField(DNASignatureAnalysis), default=list)

    # Anomaly Detection
    cluster_id = StringField()
    is_anomalous = BooleanField(default=False)
    anomaly_score = FloatField(default=0.0)

    # Metadata
    last_updated = DateTimeField(default=datetime.utcnow)

    # New fields to address the error
    filename = StringField(required=True)  # Store the file name
    dna_fingerprint = StringField(required=True)  # Store the DNA fingerprint

    meta = {
        "indexes": [
            "dna_id", "sample_id", "source_sample_id", "family_name", "platform",
            ("is_anomalous", "anomaly_score"), "group_assignment"
        ],
        "ordering": ["-collected_at"],
        "strict": True,
        "auto_create_index": False
    }

    # Method to calculate anomaly score, etc.
    def clean(self):
        """Validate and update metadata."""
        self.last_updated = datetime.utcnow()
        self._calculate_anomaly_score()
        for mutation in self.mutations:
            mutation.clean()

    def _calculate_anomaly_score(self):
        """Computes anomaly score based on mutations and opcode entropy."""
        try:
            opcode_entropy = self._calculate_entropy(self.opcode_sequence)
            mutation_impact = sum(m.impact_score for m in self.mutations) / max(1, len(self.mutations))
            self.anomaly_score = min(opcode_entropy * 0.5 + mutation_impact * 0.3 + (1 if self.is_anomalous else 0) * 0.2, 1.0)
            self.is_anomalous = self.anomaly_score > 0.7
        except Exception as e:
            logger.error(f"Error calculating anomaly score: {e}")

    def _calculate_entropy(self, sequence: List[str]) -> float:
        """Calculates Shannon entropy for opcode sequences."""
        try:
            if not sequence:
                return 0.0
            unique, counts = np.unique(sequence, return_counts=True)
            probabilities = counts / len(sequence)
            return -np.sum(probabilities * np.log2(probabilities))
        except Exception as e:
            logger.error(f"Entropy calculation failed: {e}")
            return 0.0

    def add_mutation(self, description: str, mutation_type: str, before: Dict[str, Any], after: Dict[str, Any], impact_score: float = 0.0):
        """Adds a new mutation entry."""
        try:
            mutation = DNAMutation(description=description, mutation_type=mutation_type, before=before, after=after, impact_score=impact_score)
            self.mutations.append(mutation)
            self.save()
        except Exception as e:
            logger.error(f"Error adding mutation: {e}")

    def add_signature_analysis(self, analysis_type: str, results: Dict[str, Any], confidence_score: float = 0.5):
        """Adds a signature analysis result."""
        try:
            analysis = DNASignatureAnalysis(analysis_type=analysis_type, results=results, confidence_score=confidence_score)
            self.signature_analyses.append(analysis)
            self.save()
        except Exception as e:
            logger.error(f"Error adding signature analysis: {e}")

    def calculate_similarity(self, other_dna: 'DNAModel') -> Dict[str, float]:
        """Computes similarity between two DNA signatures."""
        try:
            joined_self = ' '.join(self.opcode_sequence)
            joined_other = ' '.join(other_dna.opcode_sequence)
            max_len = max(len(joined_self), len(joined_other))
            levenshtein_score = 1 - (distance(joined_self, joined_other) / max_len if max_len > 0 else 0)

            static_self = list(self.static_dna.values())
            static_other = list(other_dna.static_dna.values())
            if len(static_self) == len(static_other):
                cosine_similarity = 1 - cosine(static_self, static_other)
            else:
                cosine_similarity = 0.0

            similarity_result = {
                "levenshtein_similarity": levenshtein_score,
                "cosine_similarity": cosine_similarity
            }
            self.similarity_analysis_history.append(similarity_result)
            self.save()
            return similarity_result
        except Exception as e:
            logger.error(f"Error computing similarity: {e}")
            return {"error": str(e)}

    def generate_unique_dna_id(self):
        """Generates a unique DNA ID if not provided."""
        if not self.dna_id:
            self.dna_id = str(uuid.uuid4())
        return self.dna_id

# ----------------------- DNA Generation Method -------------------------
def generate_dna_signature(sample_id: str, source_sample_id: str, opcode_sequence: List[str], filename: str, malware_id: str = None):
    """Generates a DNA signature for a given sample."""
    try:
        # Ensure that source_sample_id is passed
        if not source_sample_id:
            raise ValueError("source_sample_id is required")

        # If malware_id is not provided, generate it
        if not malware_id:
            malware_id = str(uuid.uuid4())

        dna_model = DNAModel(
            sample_id=sample_id,
            source_sample_id=source_sample_id,  # Ensure this is passed
            opcode_sequence=opcode_sequence,
            filename=filename,
            malware_id=malware_id,  # Pass malware_id here
            dna_fingerprint=generate_dna_fingerprint(opcode_sequence)  # Assuming you have a method to generate the fingerprint
        )
        dna_model.save()
        logger.info(f"DNA model for sample {sample_id} saved successfully.")
    except ValidationError as e:
        logger.error(f"Error saving DNA model: {e}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise e

# ----------------------- Helper Methods ------------------------------
def generate_dna_fingerprint(opcode_sequence: List[str]) -> str:
    """Generate a simple DNA fingerprint based on opcode sequence."""
    return '-'.join(opcode_sequence)

