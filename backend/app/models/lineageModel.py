import uuid
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Any

from mongoengine import (
    Document, StringField, DateTimeField, ListField, DictField,
    FloatField, EmbeddedDocument, EmbeddedDocumentField, ValidationError, connect
)

# Connect to MongoDB
connect(
    db="maldna_db",
    host="mongodb://127.0.0.1:27017/maldna_db",
    alias="default"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MutationRecord class for tracking mutation information
class MutationRecord(EmbeddedDocument):
    mutation_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = DateTimeField(default=datetime.utcnow)
    description = StringField(required=True)
    dna_diff = DictField()
    impact_score = FloatField(min_value=0.0, max_value=1.0, default=0.0)

    def clean(self):
        if not (0.0 <= self.impact_score <= 1.0):
            raise ValidationError("Impact score must be between 0 and 1")

# LineageModel class for representing malware lineage data
class LineageModel(Document):
    sample_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    source_sample_id = StringField(required=True)
    dna_fingerprint = StringField(required=True) 
    dna_referenceid = StringField(required=True)
    timestamp = DateTimeField(default=datetime.utcnow)
    mutation_date = DateTimeField(default=datetime.utcnow)
    verified = StringField(choices=["yes", "no", "unknown"], default="unknown")
    family_name = StringField(required=True, max_length=100)
    dna_sequence = StringField(required=True, unique=True)
    mutations = ListField(StringField())  # Add mutations list
    mutation_history = ListField(StringField()) 
    
    filename = StringField()
    lineage_data = DictField()

    behavior_profile = DictField(default={
        "static_analysis": {},
        "dynamic_analysis": {},
        "network_behavior": {},
        "system_impact": {}
    })

    mutations = ListField(EmbeddedDocumentField(MutationRecord), default=list)
    mutation_rate = FloatField(default=0.0)

    lineage_graph = DictField(default={
        "parent": None,
        "children": [],
        "siblings": [],
        "mutation_path": []
    })

    ai_lineage_predictions = DictField(default={})
    cross_chain_metadata = DictField(default={})

    version = StringField(default="1.0")
    version_history = ListField(DictField(), default=list)

    blockchain_verification = DictField(default={
        "tx_id": None,
        "verified": False,
        "timestamp": None,
        "gas_used": None,
        "contract_address": None
    })

    genetic_analysis = DictField(default={
        "similarity_matrix": {},
        "signature_hash": None,
        "anomaly_score": 0.0
    })

    threat_intelligence = DictField(default={
        "sources": [],
        "confidence_score": 0.0,
        "global_tags": [],
        "ioc_match": []
    })

    platform_behaviors = DictField(default={
        "windows": {},
        "linux": {},
        "macos": {},
        "android": {},
        "ios": {}
    })

    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        "db_alias": "default",
        "collection": "lineage_models",
        "indexes": [
            "sample_id",
            "source_sample_id",
            "family_name",
            "dna_sequence",
            ("threat_intelligence.global_tags", "created_at")
        ],
        "ordering": ["-created_at"],
        "strict": True,
        "auto_create_index": False
    }

    def clean(self):
        self.updated_at = datetime.utcnow()
        self._generate_dna_signature()

        # Ensure dna_referenceid is set if not provided
        if not self.dna_referenceid:
            self.dna_referenceid = str(uuid.uuid4())  # You can customize this generation

        for mutation in self.mutations:
            mutation.clean()

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        # Check if indexes are valid before saving to avoid crashes
        self.fix_invalid_indexes()
        return super().save(*args, **kwargs)

    def _generate_dna_signature(self):
        try:
            if self.dna_sequence:
                self.genetic_analysis["signature_hash"] = hashlib.sha256(self.dna_sequence.encode()).hexdigest()
        except Exception as e:
            logger.warning(f"⚠️ Failed to generate signature: {e}")

    def add_mutation(self, description: str, dna_diff: Dict[str, Any], impact_score: float = 0.0) -> None:
        mutation = MutationRecord(description=description, dna_diff=dna_diff, impact_score=impact_score)
        self.mutations.append(mutation)
        self.mutation_rate = len(self.mutations) / (len(self.mutations) + 1)
        self.save()

    def retrieve_mutation_history(self) -> List[Dict[str, Any]]:
        return [
            {
                "mutation_id": mut.mutation_id,
                "timestamp": mut.timestamp,
                "description": mut.description,
                "impact_score": mut.impact_score
            } for mut in self.mutations
        ]

    def compare_mutation_rates(self, dna_samples: List[str]) -> Dict[str, float]:
        results = {}
        for dna in dna_samples:
            sample = LineageModel.objects(dna_sequence=dna).first()
            if sample:
                results[sample.sample_id] = sample.mutation_rate
        return results

    def predict_future_mutations(self, dna_list: List[str]) -> Dict[str, Any]:
        predictions = {}
        for dna in dna_list:
            sample = LineageModel.objects(dna_sequence=dna).first()
            if sample:
                predictions[sample.sample_id] = {
                    "prediction": f"Mutation trend with {len(sample.mutations)} past changes",
                    "estimated_risk": sample.genetic_analysis.get("anomaly_score", 0.0)
                }
        return predictions

    def reconstruct_malware_lineage(self) -> Dict[str, Any]:
        logger.info(f"Reconstructing lineage for sample_id: {self.sample_id}")
        return {
            "sample_id": self.sample_id,
            "family_name": self.family_name,
            "mutation_path": self.lineage_graph.get("mutation_path", []),
            "mutations": self.retrieve_mutation_history(),
            "graph": self.lineage_graph,
            "similarity": self.genetic_analysis.get("similarity_matrix", {})
        }

    def blockchain_verify_lineage(self, blockchain_service) -> Dict[str, Any]:
        try:
            data_to_store = self.to_dict()

            # Ensure dna_referenceid is included in the blockchain data
            if not self.dna_referenceid:
                self.dna_referenceid = str(uuid.uuid4())  # Or handle as necessary

            tx_id = blockchain_service.store_on_blockchain(data_to_store)
            verified = blockchain_service.verify_on_blockchain(tx_id)

            self.blockchain_verification = {
                "tx_id": tx_id,
                "verified": verified,
                "timestamp": datetime.utcnow(),
                "gas_used": blockchain_service.get_gas_usage(tx_id),
                "contract_address": blockchain_service.get_contract_address()
            }
            self.save()
            return self.blockchain_verification
        except Exception as e:
            logger.error(f"❌ Blockchain verification failed: {e}")
            return {"error": str(e)}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "source_sample_id": self.source_sample_id,
            "family_name": self.family_name,
            "dna_sequence": self.dna_sequence,
            "filename": self.filename,
            "lineage_data": self.lineage_data,
            "behavior_profile": self.behavior_profile,
            "mutations": [m.to_mongo().to_dict() for m in self.mutations],
            "mutation_rate": self.mutation_rate,
            "lineage_graph": self.lineage_graph,
            "ai_lineage_predictions": self.ai_lineage_predictions,
            "cross_chain_metadata": self.cross_chain_metadata,
            "version": self.version,
            "version_history": self.version_history,
            "blockchain_verification": self.blockchain_verification,
            "genetic_analysis": self.genetic_analysis,
            "threat_intelligence": self.threat_intelligence,
            "platform_behaviors": self.platform_behaviors,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def fix_invalid_indexes(self):
        try:
            db = self._get_collection().database
            collection = db[self._get_collection_name()]
            indexes = collection.index_information()
            for name, spec in indexes.items():
                if "_id" in dict(spec.get("key", [])) and name != "_id_":
                    if any(k in spec for k in ["background", "unique", "sparse"]):
                        logger.warning(f"⚠️ Dropping invalid _id index: {name}")
                        collection.drop_index(name)
        except Exception as e:
            logger.error(f"❌ Error fixing invalid indexes: {str(e)}")

# Example usage: fetching mutation history
def fetch_mutation_history(sample_id: str):
    try:
        lineage_model = LineageModel.objects(sample_id=sample_id).first()
        if lineage_model:
            mutation_history = lineage_model.retrieve_mutation_history()
            logger.info(f"Fetched mutation history for sample_id {sample_id}: {mutation_history}")
        else:
            logger.error(f"❌ LineageModel not found for sample_id {sample_id}.")
    except Exception as e:
        logger.error(f"❌ Fetching mutation history failed: {e}")

# Example fetch mutation history for sample_id "2"
fetch_mutation_history("2")

