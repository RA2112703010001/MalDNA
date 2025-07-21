import json
import logging
import argparse
from datetime import datetime
from typing import List, Dict, Optional, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field

# MongoDB Integration
from mongoengine import Document, StringField, DateTimeField, BooleanField, FloatField, DictField

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Blockchain Transaction Schema**
# --------------------------------------------
class BlockchainTransactionSchema(BaseModel):
    """Schema for blockchain transaction validation"""
    transaction_id: str = Field(..., description="Unique transaction identifier")
    blockchain_network: str = Field(..., description="Blockchain network name (e.g., Ethereum, Hyperledger)")
    sender_address: str = Field(..., description="Blockchain sender address")
    recipient_address: str = Field(..., description="Blockchain recipient address")
    transaction_fee: float = Field(..., ge=0.0, description="Transaction fee in blockchain currency")
    confirmation_status: bool = Field(default=False, description="Whether the transaction is confirmed")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Transaction timestamp")

# --------------------------------------------
# 📌 **MongoDB Model for Blockchain Transactions**
# --------------------------------------------
class BlockchainTransaction(Document):
    """
    MongoDB model for tracking blockchain transactions.
    """
    transaction_id = StringField(primary_key=True, required=True, unique=True)
    blockchain_network = StringField(required=True)
    sender_address = StringField(required=True)
    recipient_address = StringField(required=True)
    transaction_fee = FloatField(default=0.0)
    confirmation_status = BooleanField(default=False)
    timestamp = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "blockchain_transactions",
        "indexes": ["transaction_id", "blockchain_network", "-timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert blockchain transaction data to dictionary.
        """
        return {
            "transaction_id": self.transaction_id,
            "blockchain_network": self.blockchain_network,
            "sender_address": self.sender_address,
            "recipient_address": self.recipient_address,
            "transaction_fee": self.transaction_fee,
            "confirmation_status": self.confirmation_status,
            "timestamp": self.timestamp.isoformat()
        }

# --------------------------------------------
# 🎯 **Blockchain Verification Schema**
# --------------------------------------------
class BlockchainVerificationSchema(BaseModel):
    """Schema for validating blockchain evidence verification"""
    verification_id: str = Field(..., description="Unique verification identifier")
    transaction_id: str = Field(..., description="Blockchain transaction ID")
    forensic_record_id: str = Field(..., description="Forensic record associated with verification")
    verification_status: bool = Field(default=False, description="Whether the verification was successful")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Verification timestamp")

# --------------------------------------------
# 📌 **MongoDB Model for Blockchain Verification**
# --------------------------------------------
class BlockchainVerification(Document):
    """
    MongoDB model for tracking blockchain-based forensic record verification.
    """
    verification_id = StringField(primary_key=True, required=True, unique=True)
    transaction_id = StringField(required=True)
    forensic_record_id = StringField(required=True)
    verification_status = BooleanField(default=False)
    timestamp = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "blockchain_verifications",
        "indexes": ["verification_id", "transaction_id", "-timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert blockchain verification data to dictionary.
        """
        return {
            "verification_id": self.verification_id,
            "transaction_id": self.transaction_id,
            "forensic_record_id": self.forensic_record_id,
            "verification_status": self.verification_status,
            "timestamp": self.timestamp.isoformat()
        }

# --------------------------------------------
# 🔥 **CLI Utility for Blockchain Transactions**
# --------------------------------------------
def log_blockchain_transaction(transaction_id: str, blockchain_network: str, sender_address: str, recipient_address: str, transaction_fee: float) -> Dict[str, Any]:
    """
    Log a blockchain transaction in the database.
    """
    logger.info(f"🚀 Logging blockchain transaction {transaction_id}...")

    transaction_data = BlockchainTransaction(
        transaction_id=transaction_id,
        blockchain_network=blockchain_network,
        sender_address=sender_address,
        recipient_address=recipient_address,
        transaction_fee=transaction_fee
    )
    transaction_data.save()

    logger.info(f"✅ Blockchain transaction {transaction_id} logged successfully")
    return transaction_data.to_dict()

def verify_blockchain_record(transaction_id: str, forensic_record_id: str) -> Dict[str, Any]:
    """
    Verify forensic record against blockchain transaction.
    """
    logger.info(f"🔍 Verifying blockchain record for forensic record {forensic_record_id}...")

    transaction_record = BlockchainTransaction.objects(transaction_id=transaction_id).first()
    if not transaction_record:
        return {"error": "Transaction not found"}

    verification_data = BlockchainVerification(
        verification_id=str(datetime.utcnow().timestamp()),
        transaction_id=transaction_id,
        forensic_record_id=forensic_record_id,
        verification_status=True
    )
    verification_data.save()

    logger.info(f"✅ Blockchain verification completed for forensic record {forensic_record_id}")
    return verification_data.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blockchain Transaction & Verification CLI")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Log Blockchain Transaction
    transaction_parser = subparsers.add_parser("log_transaction", help="Log a new blockchain transaction")
    transaction_parser.add_argument("--transaction_id", required=True, help="Blockchain Transaction ID")
    transaction_parser.add_argument("--blockchain_network", required=True, help="Blockchain Network (e.g., Ethereum, Hyperledger)")
    transaction_parser.add_argument("--sender_address", required=True, help="Sender Wallet Address")
    transaction_parser.add_argument("--recipient_address", required=True, help="Recipient Wallet Address")
    transaction_parser.add_argument("--transaction_fee", required=True, type=float, help="Transaction Fee")

    # 📌 Verify Blockchain Record
    verification_parser = subparsers.add_parser("verify_record", help="Verify forensic record on blockchain")
    verification_parser.add_argument("--transaction_id", required=True, help="Blockchain Transaction ID")
    verification_parser.add_argument("--forensic_record_id", required=True, help="Forensic Record ID")

    args = parser.parse_args()

    # Execute Command
    if args.command == "log_transaction":
        transaction_data = log_blockchain_transaction(
            args.transaction_id, args.blockchain_network, args.sender_address, args.recipient_address, args.transaction_fee
        )
        print(json.dumps(transaction_data, indent=4))

    elif args.command == "verify_record":
        verification_data = verify_blockchain_record(args.transaction_id, args.forensic_record_id)
        print(json.dumps(verification_data, indent=4))
