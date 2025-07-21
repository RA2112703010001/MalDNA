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
# 🎯 **Forensic Evidence Schema**
# --------------------------------------------
class ForensicEvidenceSchema(BaseModel):
    """Pydantic schema for forensic evidence validation"""
    evidence_id: str = Field(..., description="Unique identifier for forensic evidence")
    case_id: str = Field(..., description="Associated forensic case ID")
    description: str = Field(..., description="Description of the forensic evidence")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    handler: Optional[str] = Field(None, description="Name of forensic handler")
    preservation_method: Optional[str] = Field(None, description="Preservation technique used")
    forensic_significance: Optional[float] = Field(None, ge=0, le=10, description="Significance score (0-10)")

    @validator("evidence_id")
    def validate_evidence_id(cls, v):
        """Ensure evidence ID is a valid UUID"""
        if len(v) < 8:
            raise ValueError("Invalid evidence ID")
        return v

# --------------------------------------------
# 📌 **MongoDB Forensic Evidence Storage**
# --------------------------------------------
class ForensicEvidence(Document):
    """
    MongoDB model for storing forensic evidence.
    """
    evidence_id = StringField(primary_key=True, required=True)
    case_id = StringField(required=True)
    description = StringField(required=True)
    collection_timestamp = DateTimeField(default=datetime.utcnow)
    handler = StringField()
    preservation_method = StringField()
    forensic_significance = FloatField(default=0.0)

    blockchain_verification = DictField(default={})

    meta = {
        "collection": "forensic_evidence",
        "indexes": ["case_id", "-collection_timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert forensic evidence record to dictionary.
        """
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "description": self.description,
            "collection_timestamp": self.collection_timestamp.isoformat(),
            "handler": self.handler,
            "preservation_method": self.preservation_method,
            "forensic_significance": self.forensic_significance,
            "blockchain_verification": self.blockchain_verification
        }

# --------------------------------------------
# 📌 **Blockchain Verification Schema**
# --------------------------------------------
class BlockchainForensicSchema(BaseModel):
    """Pydantic schema for blockchain verification of forensic evidence"""
    evidence_id: str = Field(..., description="Unique evidence identifier")
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
# 🔥 **CLI Utility for Forensic Evidence Management**
# --------------------------------------------
def store_forensic_evidence(case_id: str, description: str, handler: Optional[str] = None, preservation_method: Optional[str] = None, forensic_significance: float = 0.0) -> Dict[str, Any]:
    """
    Store forensic evidence in the database.
    """
    logger.info(f"🚀 Storing forensic evidence for case {case_id}...")

    # Generate a Unique Evidence ID
    evidence_id = f"evidence_{hashlib.md5(case_id.encode()).hexdigest()[:8]}"

    # Validate Using Pydantic Schema
    evidence_data = ForensicEvidenceSchema(
        evidence_id=evidence_id,
        case_id=case_id,
        description=description,
        handler=handler,
        preservation_method=preservation_method,
        forensic_significance=forensic_significance
    )

    # Store in MongoDB
    evidence_record = ForensicEvidence(
        evidence_id=evidence_id,
        case_id=case_id,
        description=description,
        handler=handler,
        preservation_method=preservation_method,
        forensic_significance=forensic_significance
    )
    evidence_record.save()

    # Log to Blockchain
    blockchain_tx_id = blockchain_service.store_data_on_blockchain(json.dumps(evidence_record.to_dict()))
    evidence_record.blockchain_verification = {"tx_id": blockchain_tx_id, "verified": True}
    evidence_record.save()

    logger.info(f"✅ Forensic evidence stored successfully with blockchain TX: {blockchain_tx_id}")
    return evidence_record.to_dict()

# --------------------------------------------
# 📌 **Retrieve Forensic Evidence**
# --------------------------------------------
def retrieve_forensic_evidence(evidence_id: str) -> Dict[str, Any]:
    """
    Retrieve forensic evidence data.
    """
    logger.info(f"📄 Retrieving forensic evidence {evidence_id}...")

    evidence_record = ForensicEvidence.objects(evidence_id=evidence_id).first()
    if not evidence_record:
        return {"error": "Forensic evidence not found"}

    return evidence_record.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forensic Evidence Management")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Store Forensic Evidence
    store_parser = subparsers.add_parser("store", help="Store forensic evidence")
    store_parser.add_argument("--case_id", required=True, help="Forensic case ID")
    store_parser.add_argument("--description", required=True, help="Description of evidence")
    store_parser.add_argument("--handler", help="Name of forensic handler")
    store_parser.add_argument("--preservation_method", help="Preservation method used")
    store_parser.add_argument("--forensic_significance", type=float, default=0.0, help="Significance score (0-10)")

    # 📌 Retrieve Forensic Evidence
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve stored forensic evidence")
    retrieve_parser.add_argument("--evidence_id", required=True, help="Forensic evidence ID")

    args = parser.parse_args()

    # Execute Command
    if args.command == "store":
        evidence_record = store_forensic_evidence(
            args.case_id, args.description, args.handler, args.preservation_method, args.forensic_significance
        )
        print(json.dumps(evidence_record, indent=4))

    elif args.command == "retrieve":
        evidence_data = retrieve_forensic_evidence(args.evidence_id)
        print(json.dumps(evidence_data, indent=4))
