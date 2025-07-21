import os
import json
import logging
import argparse
import hashlib
from datetime import datetime
from flask import jsonify, Blueprint, request
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from app.services.blockchainService import BlockchainService
# Import models
from app.models.blockchainModel import BlockchainTransaction, BlockchainEntry
from app.models.malwareModel import MalwareModel  # Assuming this is where the malware model is stored

# Define the blockchain blueprint
blockchain_bp = Blueprint("blockchain", __name__, url_prefix="/api/blockchain")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class Config:
    BLOCKCHAIN_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://localhost:8545")
    CONTRACT_ADDRESS = os.getenv("SMART_CONTRACT_ADDRESS")
    PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
    CONTRACT_ABI_PATH = os.getenv("CONTRACT_ABI_PATH")

class BlockchainService:
    def __init__(self):
        try:
            if not all([Config.BLOCKCHAIN_URL, Config.CONTRACT_ADDRESS, Config.PRIVATE_KEY, Config.CONTRACT_ABI_PATH]):
                raise ValueError("Blockchain configuration is missing required parameters")

            self.web3 = Web3(Web3.HTTPProvider(Config.BLOCKCHAIN_URL))
            if not self.web3.is_connected():
                raise ConnectionError("Failed to connect to the blockchain network")

            with open(Config.CONTRACT_ABI_PATH, "r") as f:
                abi_data = json.load(f)
                if isinstance(abi_data, list):  # raw ABI
                    abi = abi_data
                elif isinstance(abi_data, dict) and "abi" in abi_data:
                    abi = abi_data["abi"]
                else:
                    raise ValueError("Invalid ABI format")

            self.contract = self.web3.eth.contract(address=Config.CONTRACT_ADDRESS, abi=abi)

            self.account = Account.from_key(Config.PRIVATE_KEY)

            logger.info("✅ Blockchain service initialized successfully")
        except Exception as e:
            logger.error(f"❌ Blockchain service initialization failed: {e}")
            raise

    def store_dna_fingerprint(self, malware_dna):
        try:
            timestamp = datetime.now().isoformat()
            signature = self.sign_data({"malware_dna": malware_dna, "timestamp": timestamp})
            tx_hash = self._submit_transaction("storeMalwareDNA", malware_dna, timestamp, signature)

            # Save transaction locally
            BlockchainTransaction(
                sample_id=malware_dna,
                tx_hash=tx_hash,
                verified=True,
                timestamp=datetime.utcnow()
            ).save()

            return {"tx_hash": tx_hash, "malware_dna": malware_dna, "timestamp": timestamp, "signature": signature}
        except Exception as e:
            logger.error(f"❌ Malware DNA storage failed: {e}")
            return {"error": "Failed to store malware DNA"}, 500

    def verify_dna_fingerprint(self, sample_id):
        try:
            evidence = self.contract.functions.getMalwareDNA(sample_id).call()
            if not evidence:
                return {"error": "DNA fingerprint not found on blockchain"}, 404

            malware_dna, timestamp, signature = evidence
            is_valid = self.verify_signature({"malware_dna": malware_dna, "timestamp": timestamp}, signature)
            return {"malware_dna": malware_dna, "timestamp": timestamp, "is_valid": is_valid}
        except Exception as e:
            logger.error(f"❌ DNA verification failed: {e}")
            return {"error": "Failed to verify DNA fingerprint"}, 500

    def store_forensic_evidence_entry(self, sample_id, evidence_data, analysis_type="hybrid", threat_score=0.0, source_ip=None):
        try:
            signature_hash = hashlib.sha256(json.dumps(evidence_data, sort_keys=True).encode()).hexdigest()
            entry = BlockchainEntry(
                sample_id=sample_id,
                evidence_data=evidence_data,
                analysis_type=analysis_type,
                threat_score=threat_score,
                source_ip=source_ip,
                signature_hash=signature_hash
            )
            entry.save()
            logger.info(f"✅ Forensic entry saved locally for sample {sample_id}")
            return entry
        except Exception as e:
            logger.error(f"❌ Failed to store forensic entry: {e}")
            raise

    def store_forensic_evidence(self, evidence_id, forensic_data):
        try:
            entry = self.store_forensic_evidence_entry(
                sample_id=evidence_id,
                evidence_data=forensic_data,
                analysis_type=forensic_data.get("analysis_type", "hybrid"),
                threat_score=forensic_data.get("threat_score", 0.0),
                source_ip=forensic_data.get("source_ip")
            )
            timestamp = datetime.now().isoformat()
            signature = self.sign_data({"evidence_id": evidence_id, "timestamp": timestamp})
            tx_hash = self._submit_transaction(
                "storeForensicEvidence",
                evidence_id,
                json.dumps(forensic_data),
                timestamp,
                signature
            )

            # Save transaction
            BlockchainTransaction(
                sample_id=evidence_id,
                tx_hash=tx_hash,
                verified=True,
                timestamp=datetime.utcnow()
            ).save()

            return {
                "tx_hash": tx_hash,
                "evidence_id": evidence_id,
                "timestamp": timestamp,
                "signature": signature,
                "signature_hash": entry.signature_hash
            }
        except Exception as e:
            logger.error(f"❌ Forensic evidence storage failed: {e}")
            return {"error": "Failed to store forensic evidence"}, 500

    def retrieve_evidence_history(self, evidence_id):
        try:
            history = self.contract.functions.getForensicHistory(evidence_id).call()
            if not history:
                return {"error": "No forensic history found"}, 404
            return {"evidence_id": evidence_id, "history": history}
        except Exception as e:
            logger.error(f"❌ Failed to retrieve forensic history: {e}")
            return {"error": "Failed to retrieve evidence history"}, 500

    def sign_data(self, data):
        try:
            message = json.dumps(data, sort_keys=True).encode("utf-8")
            encoded_message = encode_defunct(text=message.decode("utf-8"))
            signed_message = self.web3.eth.account.sign_message(encoded_message, private_key=self.account.key)
            return signed_message.signature.hex()
        except Exception as e:
            logger.error(f"❌ Data signing failed: {e}")
            raise

    def verify_signature(self, data, signature):
        try:
            message = json.dumps(data, sort_keys=True).encode("utf-8")
            encoded_message = encode_defunct(text=message.decode("utf-8"))
            recovered_address = self.web3.eth.account.recover_message(encoded_message, signature=signature)
            return recovered_address.lower() == self.account.address.lower()
        except Exception as e:
            logger.error(f"❌ Signature verification failed: {e}")
            return False

    def _submit_transaction(self, method, *args):
        try:
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            txn = getattr(self.contract.functions, method)(*args).build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "gas": 3000000,
                "gasPrice": self.web3.to_wei("10", "gwei")
            })
            signed_txn = self.web3.eth.account.sign_transaction(txn, private_key=self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn['rawTransaction'])  # Fixed line
            logger.info(f"✅ Transaction submitted: {tx_hash.hex()}")
            return tx_hash.hex()
        except Exception as e:
            logger.error(f"❌ Failed to submit transaction: {e}")
            raise

    def get_blockchain_verified_count(self):
        try:
            return BlockchainTransaction.objects(verified=True).count()
        except Exception as e:
            logger.error(f"❌ Error fetching blockchain verified count: {e}")
            return 0

    def get_blockchain_tx_entries_count(self):
        try:
            return BlockchainTransaction.objects.count()
        except Exception as e:
            logger.error(f"❌ Error fetching blockchain transaction entries: {e}")
            return 0

# Instantiate service
blockchain_service = BlockchainService()


# ------------------- FLASK ROUTES -------------------

@blockchain_bp.route("/verify_dna/<string:sample_id>", methods=["GET"])
def verify_dna_route(sample_id):
    result = blockchain_service.verify_dna_fingerprint(sample_id)
    return jsonify(result[0]) if isinstance(result, tuple) else jsonify(result), result[1] if isinstance(result, tuple) else 200

@blockchain_bp.route("/forensic_history/<string:evidence_id>", methods=["GET"])
def forensic_history_route(evidence_id):
    result = blockchain_service.retrieve_evidence_history(evidence_id)
    return jsonify(result[0]) if isinstance(result, tuple) else jsonify(result), result[1] if isinstance(result, tuple) else 200

@blockchain_bp.route("/store", methods=["POST"])
def unified_store_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request payload"}), 400

        if "malware_dna" in data:
            result = blockchain_service.store_dna_fingerprint(data["malware_dna"])
            return jsonify(result)
        elif "forensic_data" in data:
            result = blockchain_service.store_forensic_evidence(data["sample_id"], data["forensic_data"])
            return jsonify(result)
        else:
            return jsonify({"error": "Invalid payload"}), 400
    except Exception as e:
        logger.error(f"❌ Error in unified store route: {e}")
        return jsonify({"error": str(e)}), 500

@blockchain_bp.route('/stats', methods=['GET'])
def get_blockchain_stats():
    try:
        verified_count = BlockchainEntry.objects(type="malware_dna").count()
        total_transactions = BlockchainTransaction.objects.count()

        return jsonify({
            'verified_count': verified_count,
            'total_transactions': total_transactions
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ------------------- CLI ENTRY -------------------

def cli_store_dna_fingerprint(malware_dna):
    print(json.dumps(blockchain_service.store_dna_fingerprint(malware_dna), indent=4))

def cli_verify_dna_fingerprint(sample_id):
    print(json.dumps(blockchain_service.verify_dna_fingerprint(sample_id), indent=4))

def cli_store_forensic_evidence(evidence_id, forensic_data):
    print(json.dumps(blockchain_service.store_forensic_evidence(evidence_id, forensic_data), indent=4))

def cli_forensic_history(evidence_id):
    print(json.dumps(blockchain_service.retrieve_evidence_history(evidence_id), indent=4))

# Command-line argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blockchain services CLI")
    parser.add_argument("action", choices=["store_dna", "verify_dna", "store_forensic", "forensic_history"], help="Action to perform")
    parser.add_argument("--malware_dna", help="Malware DNA fingerprint to store")
    parser.add_argument("--sample_id", help="Sample ID for verification")
    parser.add_argument("--evidence_id", help="Evidence ID for forensic history retrieval")
    parser.add_argument("--forensic_data", help="Forensic data for storage")

    args = parser.parse_args()

    if args.action == "store_dna" and args.malware_dna:
        cli_store_dna_fingerprint(args.malware_dna)
    elif args.action == "verify_dna" and args.sample_id:
        cli_verify_dna_fingerprint(args.sample_id)
    elif args.action == "store_forensic" and args.evidence_id and args.forensic_data:
        cli_store_forensic_evidence(args.evidence_id, args.forensic_data)
    elif args.action == "forensic_history" and args.evidence_id:
        cli_forensic_history(args.evidence_id)
    else:
        print("Invalid arguments")

