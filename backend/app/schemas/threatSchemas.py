import os
import json
import logging
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field, validator

# MongoDB Integration
from mongoengine import (
    Document, StringField, DateTimeField, DictField, ListField, FloatField, BooleanField, ValidationError
)

# Blockchain Verification Service (Mocked for Now)
from app.services.blockchainVerification import blockchain_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Indicator of Compromise (IOC) Schema**
# --------------------------------------------
class IOCSchema(BaseModel):
    """Pydantic schema for Indicators of Compromise (IoCs)"""
    ioc_id: str = Field(..., description="Unique identifier for the IoC")
    ioc_type: str = Field(..., description="Type of IoC (IP, Hash, URL, etc.)")
    value: str = Field(..., description="The actual IoC value")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score (0-1)")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    description: Optional[str] = None

    @validator("ioc_type")
    def validate_ioc_type(cls, v):
        """Ensure IoC type is valid"""
        valid_types = ["ip", "domain", "hash", "url", "email", "file_path", "registry_key"]
        if v.lower() not in valid_types:
            raise ValueError(f"Invalid IoC type: {v}")
        return v

# --------------------------------------------
# 📌 **MongoDB Model for Threat Intelligence**
# --------------------------------------------
class ThreatIntel(Document):
    """
    MongoDB model for storing threat intelligence.
    """
    threat_id = StringField(primary_key=True, required=True)
    threat_name = StringField(required=True)
    threat_type = StringField()
    first_seen = DateTimeField()
    last_seen = DateTimeField(default=datetime.utcnow)
    associated_threat_actor = StringField()
    attack_vectors = ListField(DictField(), default=list)
    targeted_industries = ListField(DictField(), default=list)
    indicators_of_compromise = ListField(DictField(), default=list)
    risk_score = FloatField(default=0.0)
    blockchain_reference = DictField(default={})

    meta = {
        "collection": "threat_intelligence",
        "indexes": ["threat_id", "threat_name", "-last_seen", "risk_score"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert threat intelligence record to dictionary.
        """
        return {
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "threat_type": self.threat_type,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat(),
            "associated_threat_actor": self.associated_threat_actor,
            "attack_vectors": self.attack_vectors,
            "targeted_industries": self.targeted_industries,
            "indicators_of_compromise": self.indicators_of_compromise,
            "risk_score": self.risk_score,
            "blockchain_reference": self.blockchain_reference
        }

# --------------------------------------------
# 📌 **Threat Intelligence Report Request Schema**
# --------------------------------------------
class ThreatIntelReportSchema(BaseModel):
    """Pydantic schema for Threat Intelligence Report Requests"""
    threat_id: str = Field(..., description="Unique identifier for the threat intelligence report")
    output_format: str = Field(default="html", description="Requested output format")

# --------------------------------------------
# 📌 **Blockchain Verification for Threat Intelligence**
# --------------------------------------------
class BlockchainVerificationSchema(BaseModel):
    """Pydantic schema for validating blockchain references in threat intelligence"""
    blockchain_tx_id: str = Field(..., description="Blockchain transaction ID")
    verified: bool = Field(..., description="Indicates if the blockchain record is verified")
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow)

# --------------------------------------------
# 🔥 **CLI Utility for Threat Intelligence**
# --------------------------------------------
def store_threat_intelligence(threat_id: str, threat_name: str, threat_type: str, risk_score: float, associated_threat_actor: Optional[str] = None) -> Dict[str, Any]:
    """
    Store threat intelligence in the database.
    """
    logger.info(f"🚀 Storing threat intelligence record {threat_id}...")

    # Validate Using Pydantic Schema
    threat_data = ThreatIntel(
        threat_id=threat_id,
        threat_name=threat_name,
        threat_type=threat_type,
        risk_score=risk_score,
        associated_threat_actor=associated_threat_actor
    )

    # Store in MongoDB
    threat_data.save()

    logger.info(f"✅ Threat intelligence record stored successfully")
    return threat_data.to_dict()

# --------------------------------------------
# 📌 **Retrieve Threat Intelligence**
# --------------------------------------------
def retrieve_threat_intelligence(threat_id: str) -> Dict[str, Any]:
    """
    Retrieve threat intelligence data.
    """
    logger.info(f"📄 Retrieving threat intelligence record {threat_id}...")

    threat_record = ThreatIntel.objects(threat_id=threat_id).first()
    if not threat_record:
        return {"error": "Threat intelligence record not found"}

    return threat_record.to_dict()

# --------------------------------------------
# 📌 **Blockchain Verification for Threat Intelligence**
# --------------------------------------------
def verify_threat_intelligence_on_blockchain(threat_id: str) -> Dict[str, Any]:
    """
    Verify threat intelligence record on blockchain.
    """
    logger.info(f"🔍 Verifying threat intelligence {threat_id} on blockchain...")

    threat_record = ThreatIntel.objects(threat_id=threat_id).first()
    if not threat_record:
        return {"error": "Threat intelligence record not found"}

    # Blockchain Verification (Mocked for Now)
    blockchain_result = blockchain_service.verify_transaction(threat_record.to_dict())

    # Validate Blockchain Verification Schema
    BlockchainVerificationSchema(
        blockchain_tx_id=blockchain_result["blockchain_tx_id"],
        verified=blockchain_result["verified"],
        verification_timestamp=blockchain_result["verification_timestamp"]
    )

    # Store Blockchain Reference
    threat_record.blockchain_reference = blockchain_result
    threat_record.save()

    logger.info(f"✅ Blockchain verification stored for threat intelligence {threat_id}")
    return threat_record.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence Management")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Store Threat Intelligence
    store_parser = subparsers.add_parser("store", help="Store threat intelligence record")
    store_parser.add_argument("--threat_id", required=True, help="Threat ID")
    store_parser.add_argument("--threat_name", required=True, help="Threat Name")
    store_parser.add_argument("--threat_type", required=True, help="Threat Type")
    store_parser.add_argument("--risk_score", type=float, required=True, help="Risk Score (0-100)")
    store_parser.add_argument("--associated_threat_actor", help="Threat Actor")

    # 📌 Retrieve Threat Intelligence
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve threat intelligence record")
    retrieve_parser.add_argument("--threat_id", required=True, help="Threat ID")

    # 📌 Blockchain Verification
    blockchain_parser = subparsers.add_parser("verify", help="Verify threat intelligence on blockchain")
    blockchain_parser.add_argument("--threat_id", required=True, help="Threat ID")

    args = parser.parse_args()

    # Execute Command
    if args.command == "store":
        threat_data = store_threat_intelligence(
            args.threat_id, args.threat_name, args.threat_type, args.risk_score, args.associated_threat_actor
        )
        print(json.dumps(threat_data, indent=4))

    elif args.command == "retrieve":
        threat_data = retrieve_threat_intelligence(args.threat_id)
        print(json.dumps(threat_data, indent=4))

    elif args.command == "verify":
        verification_data = verify_threat_intelligence_on_blockchain(args.threat_id)
        print(json.dumps(verification_data, indent=4))
