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
# 🎯 **Lineage Tracking Schema**
# --------------------------------------------
class LineageTrackingSchema(BaseModel):
    """Pydantic schema for lineage tracking requests"""
    lineage_id: str = Field(..., description="Unique identifier for the lineage tracking request")
    sample_id: str = Field(..., description="Malware sample ID being analyzed")
    parent_sample_id: Optional[str] = Field(None, description="Parent malware sample ID (if applicable)")
    mutation_details: Optional[Dict[str, Any]] = Field({}, description="Details of mutations observed")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @validator("lineage_id")
    def validate_lineage_id(cls, v):
        """Ensure lineage ID is a valid UUID"""
        if len(v) < 8:
            raise ValueError("Invalid lineage ID")
        return v

# --------------------------------------------
# 📌 **MongoDB Lineage Storage**
# --------------------------------------------
class LineageModel(Document):
    """
    MongoDB model for tracking malware lineage.
    """
    lineage_id = StringField(primary_key=True, required=True)
    sample_id = StringField(required=True, unique=True)
    parent_sample_id = StringField()
    mutation_details = DictField(default={})
    timestamp = DateTimeField(default=datetime.utcnow)
    blockchain_verification = DictField(default={})

    meta = {
        "collection": "malware_lineage",
        "indexes": ["sample_id", "parent_sample_id", "-timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert lineage record to a dictionary.
        """
        return {
            "lineage_id": self.lineage_id,
            "sample_id": self.sample_id,
            "parent_sample_id": self.parent_sample_id,
            "mutation_details": self.mutation_details,
            "timestamp": self.timestamp.isoformat(),
            "blockchain_verification": self.blockchain_verification
        }

# --------------------------------------------
# 📌 **Blockchain Verification Schema**
# --------------------------------------------
class BlockchainLineageSchema(BaseModel):
    """Pydantic schema for blockchain verification of lineage tracking"""
    lineage_id: str = Field(..., description="Unique lineage identifier")
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
# 🔥 **CLI Utility for Lineage Tracking**
# --------------------------------------------
def track_lineage(sample_id: str, parent_sample_id: Optional[str] = None, mutation_details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Track a new malware lineage.
    """
    logger.info(f"🚀 Tracking lineage for sample {sample_id}...")

    # Generate a Unique Lineage ID
    lineage_id = f"lineage_{hashlib.md5(sample_id.encode()).hexdigest()[:8]}"

    # Validate Using Pydantic Schema
    lineage_data = LineageTrackingSchema(
        lineage_id=lineage_id,
        sample_id=sample_id,
        parent_sample_id=parent_sample_id,
        mutation_details=mutation_details or {}
    )

    # Store in MongoDB
    lineage_record = LineageModel(
        lineage_id=lineage_id,
        sample_id=sample_id,
        parent_sample_id=parent_sample_id,
        mutation_details=mutation_details or {}
    )
    lineage_record.save()

    # Log to Blockchain
    blockchain_tx_id = blockchain_service.store_data_on_blockchain(json.dumps(lineage_record.to_dict()))
    lineage_record.blockchain_verification = {"tx_id": blockchain_tx_id, "verified": True}
    lineage_record.save()

    logger.info(f"✅ Lineage stored successfully with blockchain TX: {blockchain_tx_id}")
    return lineage_record.to_dict()

# --------------------------------------------
# 📌 **Retrieve Malware Lineage**
# --------------------------------------------
def retrieve_lineage(sample_id: str) -> Dict[str, Any]:
    """
    Retrieve stored malware lineage data.
    """
    logger.info(f"📄 Retrieving lineage data for sample {sample_id}...")

    lineage_record = LineageModel.objects(sample_id=sample_id).first()
    if not lineage_record:
        return {"error": "Lineage data not found"}

    return lineage_record.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Lineage Tracking")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Track Malware Lineage
    track_parser = subparsers.add_parser("track", help="Track a new malware lineage")
    track_parser.add_argument("--sample_id", required=True, help="Malware sample ID")
    track_parser.add_argument("--parent_sample_id", help="Parent malware sample ID (if applicable)")
    track_parser.add_argument("--mutation_details", type=json.loads, help="Mutation details in JSON format")

    # 📌 Retrieve Malware Lineage
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve stored malware lineage data")
    retrieve_parser.add_argument("--sample_id", required=True, help="Malware sample ID")

    args = parser.parse_args()

    # Execute Command
    if args.command == "track":
        lineage_record = track_lineage(args.sample_id, args.parent_sample_id, args.mutation_details)
        print(json.dumps(lineage_record, indent=4))

    elif args.command == "retrieve":
        lineage_data = retrieve_lineage(args.sample_id)
        print(json.dumps(lineage_data, indent=4))
