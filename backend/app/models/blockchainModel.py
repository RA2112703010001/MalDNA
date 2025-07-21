# ----------------------------
# blockchain_models.py
# ----------------------------
import uuid
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from mongoengine import (
    Document, StringField, DateTimeField, FloatField, BooleanField,
    IntField, DictField, ListField, QuerySet
)

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --------------------------------------------------------
# 🔗 Blockchain Entry Model (Forensic Evidence Model)
# --------------------------------------------------------
class BlockchainEntry(Document):
    transaction_id = StringField(primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    sample_id = StringField(required=True)
    evidence_data = DictField(required=True)
    source_ip = StringField()
    threat_score = FloatField()
    signature_hash = StringField()
    analysis_type = StringField(choices=["static", "dynamic", "hybrid"])
    timestamp = DateTimeField(default=datetime.utcnow)
    ai_classification = StringField(choices=["benign", "malicious", "suspicious", "unknown"])
    oracle_id = StringField()
    verified_on_chain = BooleanField(default=False)
    synced_to_blockchain = BooleanField(default=False)
    synced_at = DateTimeField()
    blockchain_network = StringField(choices=[
        'ethereum', 'polygon', 'binance_smart_chain', 'solana', 'avalanche', 'hyperledger'
    ])
    chain_context = DictField()
    gas_used = IntField()
    gas_price = FloatField()
    execution_cost_eth = FloatField()
    integrity_signature = StringField()
    is_verified = BooleanField(default=False)
    verification_timestamp = DateTimeField()

    meta = {"collection": "blockchain_entries"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "sample_id": self.sample_id,
            "evidence_data": self.evidence_data,
            "source_ip": self.source_ip,
            "threat_score": self.threat_score,
            "signature_hash": self.signature_hash,
            "analysis_type": self.analysis_type,
            "timestamp": self.timestamp.isoformat(),
            "ai_classification": self.ai_classification,
            "oracle_id": self.oracle_id,
            "verified_on_chain": self.verified_on_chain,
            "synced_to_blockchain": self.synced_to_blockchain,
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "blockchain_network": self.blockchain_network,
            "chain_context": self.chain_context,
            "gas_used": self.gas_used,
            "gas_price": self.gas_price,
            "execution_cost_eth": self.execution_cost_eth,
            "integrity_signature": self.integrity_signature,
            "is_verified": self.is_verified,
            "verification_timestamp": self.verification_timestamp.isoformat() if self.verification_timestamp else None
        }

    def generate_integrity_signature(self):
        data_string = f"{self.sample_id}{self.analysis_type}{self.timestamp.isoformat()}"
        self.signature_hash = hashlib.sha256(data_string.encode()).hexdigest()
        self.integrity_signature = self.signature_hash
        self.save()
        logger.info(f"🔐 Integrity signature generated for entry {self.transaction_id}")

    def verify_entry(self):
        if self.signature_hash:
            self.is_verified = True
            self.verification_timestamp = datetime.utcnow()
            self.save()
            logger.info(f"✅ Entry {self.transaction_id} verified.")
            return True
        logger.warning(f"❌ Verification failed for {self.transaction_id}")
        return False

# --------------------------------------------------------
# 📜 Blockchain Transaction Model
# --------------------------------------------------------
class BlockchainTransaction(Document):
    transaction_hash = StringField(required=True, unique=True)
    transaction_type = StringField(required=True, choices=[
        'dna_fingerprint', 'malware_signature', 'threat_intelligence',
        'forensic_evidence', 'blockchain_verification', 'classification_vote'
    ])
    blockchain_network = StringField(required=True, choices=[
        'ethereum', 'hyperledger', 'polygon', 'binance_smart_chain', 'solana', 'avalanche'
    ])
    sender_address = StringField(required=True)
    recipient_address = StringField(required=True)
    payload_hash = StringField(required=True)
    payload_type = StringField(required=True)
    stake_amount = FloatField(default=0.0)
    researcher_address = StringField()
    malware_dna_hash = StringField()
    ai_classification = StringField(choices=["benign", "malicious", "suspicious", "unknown"])
    oracle_id = StringField()
    reputation_score = FloatField(default=0.0)
    classification = StringField(choices=["benign", "malicious", "suspicious", "unknown"])
    classification_confidence = FloatField(default=0.0)
    votes = ListField(DictField())
    is_verified = BooleanField(default=False)
    verification_timestamp = DateTimeField()
    integrity_signature = StringField()
    event_name = StringField()
    event_args = DictField()
    synced_at = DateTimeField()
    linked_chains = ListField(StringField())
    cross_chain_status = DictField()
    chain_context = DictField()
    gas_used = IntField()
    gas_price = FloatField()
    execution_cost_eth = FloatField()
    created_at = DateTimeField(default=datetime.utcnow)
    transaction_fee = FloatField(default=0.0)
    block_number = StringField()
    confirmations = IntField(default=0)
    verified = BooleanField(default=False)
    meta = {
        'collection': 'blockchain_transactions',
        'indexes': [
            'transaction_hash',
            'sender_address',
            'recipient_address',
            ('blockchain_network', 'transaction_type'),
            ('transaction_type', 'is_verified')
        ]
    }

    def __str__(self):
        return f"Blockchain Transaction: {self.transaction_hash}"

    def generate_integrity_signature(self):
        data_string = f"{self.transaction_hash}{self.payload_hash}{self.block_number or ''}"
        self.integrity_signature = hashlib.sha256(data_string.encode()).hexdigest()
        self.save()

    def verify_transaction(self) -> bool:
        if self.integrity_signature:
            self.is_verified = True
            self.verification_timestamp = datetime.utcnow()
            self.save()
            logger.info(f"✅ Verified transaction {self.transaction_hash}")
            return True
        logger.warning(f"❌ Failed verification for {self.transaction_hash}")
        return False

    def add_vote(self, voter_address: str, vote: str):
        self.votes.append({
            "voter": voter_address,
            "vote": vote,
            "timestamp": datetime.utcnow().isoformat()
        })
        self.save()
        logger.info(f"🗳️ Vote added to transaction {self.transaction_hash} by {voter_address}")

    def update_classification(self, classification: str, confidence: float):
        self.classification = classification
        self.classification_confidence = confidence
        self.save()
        logger.info(f"🔍 Classification updated to '{classification}' ({confidence*100:.1f}%)")

    def update_reputation(self, score: float):
        self.reputation_score = score
        self.save()
        logger.info(f"⭐ Researcher reputation updated to {score:.2f}")

    def set_ai_classification(self, label: str, oracle_id: str):
        self.ai_classification = label
        self.oracle_id = oracle_id
        self.save()
        logger.info(f"🤖 AI classification set by oracle {oracle_id}: {label}")

    def sync_event(self, event_name: str, event_args: Dict):
        self.event_name = event_name
        self.event_args = event_args
        self.synced_at = datetime.utcnow()
        self.save()
        logger.info(f"🔁 Synced event {event_name} for tx {self.transaction_hash}")

    def update_cross_chain_status(self, chain: str, status: str):
        if not self.cross_chain_status:
            self.cross_chain_status = {}
        self.cross_chain_status[chain] = status
        self.save()
        logger.info(f"🌐 Updated cross-chain status: {chain} -> {status}")

    def set_gas_metadata(self, gas_used: int, gas_price: float):
        self.gas_used = gas_used
        self.gas_price = gas_price
        self.execution_cost_eth = (gas_used * gas_price) / 1e18
        self.save()
        logger.info(f"⛽ Gas metadata set for {self.transaction_hash}")

    @classmethod
    def create_transaction(cls, **kwargs) -> 'BlockchainTransaction':
        tx = cls(**kwargs)
        tx.generate_integrity_signature()
        tx.save()
        logger.info(f"📦 Created blockchain transaction {tx.transaction_hash}")
        return tx

    @classmethod
    def get_transaction(cls, transaction_hash: str) -> Optional['BlockchainTransaction']:
        tx = cls.objects(transaction_hash=transaction_hash).first()
        if tx:
            logger.info(f"📥 Retrieved transaction {transaction_hash}")
        else:
            logger.warning(f"❌ Transaction {transaction_hash} not found")
        return tx

    @classmethod
    def update_confirmation_count(cls, transaction_hash: str, confirmations: int) -> Optional['BlockchainTransaction']:
        tx = cls.get_transaction(transaction_hash)
        if tx:
            tx.confirmations = confirmations
            tx.save()
            logger.info(f"🔄 Updated confirmations for {transaction_hash} to {confirmations}")
            return tx
        return None

    @classmethod
    def retrieve_recent_transactions(cls, limit: int = 10) -> QuerySet:
        return cls.objects.order_by('-created_at').limit(limit)

    @classmethod
    def retrieve_transactions_by_type(cls, transaction_type: str, limit: int = 10) -> QuerySet:
        return cls.objects(transaction_type=transaction_type).order_by('-created_at').limit(limit)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": self.transaction_hash,
            "transaction_type": self.transaction_type,
            "blockchain_network": self.blockchain_network,
            "sender_address": self.sender_address,
            "recipient_address": self.recipient_address,
            "payload_hash": self.payload_hash,
            "payload_type": self.payload_type,
            "stake_amount": self.stake_amount,
            "researcher_address": self.researcher_address,
            "malware_dna_hash": self.malware_dna_hash,
            "ai_classification": self.ai_classification,
            "oracle_id": self.oracle_id,
            "reputation_score": self.reputation_score,
            "classification": self.classification,
            "classification_confidence": self.classification_confidence,
            "votes": self.votes,
            "is_verified": self.is_verified,
            "verification_timestamp": self.verification_timestamp.isoformat() if self.verification_timestamp else None,
            "event_name": self.event_name,
            "event_args": self.event_args,
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "linked_chains": self.linked_chains,
            "cross_chain_status": self.cross_chain_status,
            "chain_context": self.chain_context,
            "gas_used": self.gas_used,
            "gas_price": self.gas_price,
            "execution_cost_eth": self.execution_cost_eth,
            "created_at": self.created_at.isoformat(),
            "transaction_fee": self.transaction_fee,
            "block_number": self.block_number,
            "confirmations": self.confirmations,
            "integrity_signature": self.integrity_signature
        }

