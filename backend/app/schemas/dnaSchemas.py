import os
import json
import hashlib
import logging
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field, validator

# MongoDB Integration
from mongoengine import (
    Document, StringField, DateTimeField, DictField, ListField, FloatField, ValidationError
)

# Blockchain Service (Mocked for Now)
from app.services.blockchainService import blockchain_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **DNA Metadata Schema**
# --------------------------------------------
class DNAMetadataSchema(BaseModel):
    """Pydantic schema for malware DNA sequences"""
    sequence_hash: str = Field(..., description="SHA256 hash of the DNA sequence")
    sample_id: str = Field(..., description="Associated malware sample ID")
    dna_sequence: str = Field(..., min_length=10, description="Encoded DNA sequence of the malware")
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    source: Optional[str] = Field(None, description="Source of the DNA sequence")

    @validator("sequence_hash")
    def validate_hash(cls, v):
        """Ensure hash is a valid SHA256 hash"""
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError("Invalid SHA256 hash")
        return v

    @validator("dna_sequence")
    def validate_dna_sequence(cls, v):
        """Ensure DNA sequence contains valid characters"""
        allowed_chars = set("ACGT0123456789")
        if not set(v).issubset(allowed_chars):
            raise ValueError("DNA sequence contains invalid characters")
        return v

# --------------------------------------------
# 📌 **MongoDB DNA Storage**
# --------------------------------------------
class DNAModel(Document):
    """
    MongoDB model for storing malware DNA sequences.
    """
    dna_id = StringField(primary_key=True, required=True)
    sequence_hash = StringField(required=True, unique=True)
    sample_id = StringField(required=True)
    dna_sequence = StringField(required=True)
    collected_at = DateTimeField(default=datetime.utcnow)
    source = StringField()
    similarity_scores = DictField(default={})
    blockchain_verification = DictField(default={})

    meta = {
        "collection": "malware_dna",
        "indexes": ["sequence_hash", "sample_id", "-collected_at"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert DNA record to a dictionary.
        """
        return {
            "dna_id": self.dna_id,
            "sequence_hash": self.sequence_hash,
            "sample_id": self.sample_id,
            "dna_sequence": self.dna_sequence,
            "collected_at": self.collected_at.isoformat(),
            "source": self.source,
            "similarity_scores": self.similarity_scores,
            "blockchain_verification": self.blockchain_verification
        }

# --------------------------------------------
# 📌 **DNA Similarity Validation**
# --------------------------------------------
class DNASimilaritySchema(BaseModel):
    """Pydantic schema for validating DNA similarity scoring"""
    reference_sequence_hash: str = Field(..., description="SHA256 hash of the reference DNA sequence")
    comparison_sequence_hash: str = Field(..., description="SHA256 hash of the compared DNA sequence")
    similarity_score: float = Field(..., ge=0, le=1, description="Similarity score (0-1)")
    confidence_level: float = Field(..., ge=0, le=1, description="Confidence in similarity measurement")

# --------------------------------------------
# 📌 **Blockchain Validation Schema**
# --------------------------------------------
class BlockchainValidationSchema(BaseModel):
    """Pydantic schema for blockchain verification of DNA sequences"""
    dna_id: str = Field(..., description="Unique DNA identifier")
    blockchain_tx_id: str = Field(..., description="Blockchain transaction ID")
    verification_status: str = Field(..., description="Status of blockchain verification")

    @validator("verification_status")
    def validate_status(cls, v):
        """Ensure verification status is valid"""
        allowed_statuses = ["pending", "verified", "failed"]
        if v not in allowed_statuses:
            raise ValueError(f"Invalid verification status. Allowed: {allowed_statuses}")
        return v

# --------------------------------------------
# 🔥 **CLI Utility for DNA Management**
# --------------------------------------------
def submit_dna_sequence(sample_id: str, dna_sequence: str, source: Optional[str] = None) -> Dict[str, Any]:
    """
    Submit a new malware DNA sequence.
    """
    logger.info(f"🚀 Submitting DNA sequence for sample {sample_id}...")

    # Compute SHA256 Hash of DNA Sequence
    sequence_hash = hashlib.sha256(dna_sequence.encode()).hexdigest()

    # Validate Using Pydantic Schema
    metadata = DNAMetadataSchema(
        sequence_hash=sequence_hash,
        sample_id=sample_id,
        dna_sequence=dna_sequence,
        source=source
    )

    # Store in MongoDB
    dna_id = f"dna_{sequence_hash[:8]}"
    dna_record = DNAModel(
        dna_id=dna_id,
        sequence_hash=sequence_hash,
        sample_id=sample_id,
        dna_sequence=dna_sequence,
        source=source
    )
    dna_record.save()

    # Log to Blockchain
    blockchain_tx_id = blockchain_service.store_data_on_blockchain(json.dumps(dna_record.to_dict()))
    dna_record.blockchain_verification = {"tx_id": blockchain_tx_id, "verified": True}
    dna_record.save()

    logger.info(f"✅ DNA sequence stored successfully with blockchain TX: {blockchain_tx_id}")
    return dna_record.to_dict()

# --------------------------------------------
# 📌 **Retrieve DNA Sequences**
# --------------------------------------------
def retrieve_dna_sequences(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve stored malware DNA sequences.
    """
    logger.info(f"📄 Retrieving last {limit} DNA sequences...")

    dna_records = DNAModel.objects().order_by("-collected_at")[:limit]
    return [record.to_dict() for record in dna_records]

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware DNA Sequence Management")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Submit DNA Sequence
    submit_parser = subparsers.add_parser("submit", help="Submit a new malware DNA sequence")
    submit_parser.add_argument("--sample_id", required=True, help="Malware sample ID")
    submit_parser.add_argument("--dna_sequence", required=True, help="DNA sequence to store")
    submit_parser.add_argument("--source", help="Source of DNA sequence")

    # 📌 Retrieve DNA Sequences
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve stored malware DNA sequences")
    retrieve_parser.add_argument("--limit", type=int, default=10, help="Number of records to retrieve")

    args = parser.parse_args()

    # Execute Command
    if args.command == "submit":
        dna_record = submit_dna_sequence(args.sample_id, args.dna_sequence, args.source)
        print(json.dumps(dna_record, indent=4))

    elif args.command == "retrieve":
        records = retrieve_dna_sequences(args.limit)
        print(json.dumps(records, indent=4))
