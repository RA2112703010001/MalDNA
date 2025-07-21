import os
import json
import logging
import traceback
from typing import Dict, Any, Optional
from flask import Blueprint, request, jsonify
from dotenv import load_dotenv
from web3 import Web3

# Internal utility functions
from app.utils.blockchainUtils import (
    store_on_blockchain,
    verify_on_blockchain,
    classify_malware,
    get_reputation
)

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

blockchain_bp = Blueprint("blockchain", __name__, url_prefix="/api/blockchain")


class BlockchainService:
    def __init__(self):
        try:
            self.rpc_url = os.getenv("BLOCKCHAIN_RPC_URL", "http://localhost:8545")
            self.contract_address = os.getenv("SMART_CONTRACT_ADDRESS")
            self.private_key = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
            self.abi_path = os.getenv("CONTRACT_ABI_PATH")

            if not all([self.rpc_url, self.contract_address, self.private_key, self.abi_path]):
                raise EnvironmentError("❌ Missing blockchain environment configuration.")

            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if not self.web3.is_connected():
                raise ConnectionError("❌ Blockchain connection failed.")

            with open(self.abi_path, "r") as abi_file:
                abi_data = json.load(abi_file)

            abi = abi_data["abi"] if isinstance(abi_data, dict) else abi_data
            self.contract = self.web3.eth.contract(address=Web3.to_checksum_address(self.contract_address), abi=abi)
            self.account = self.web3.eth.account.from_key(self.private_key)
            self.address = self.account.address
            logger.info("✅ Blockchain service initialized.")

        except EnvironmentError as env_err:
            logger.error(f"⚠️ {str(env_err)}")
            raise

        except ConnectionError as conn_err:
            logger.error(f"⚠️ {str(conn_err)}")
            raise

        except Exception as e:
            logger.error(f"❌ An unexpected error occurred during initialization: {e}")
            raise

    def store_on_blockchain(self, data: Dict[str, Any]) -> str:
        try:
            # Validate input types
            if not isinstance(data.get('sample_id'), str) or not isinstance(data.get('dna_referenceid'), str):
                raise ValueError("❌ sample_id and dna_referenceid must be strings")

            logger.info(f"📦 Storing on blockchain: {data}")

            # Convert sample_id string to bytes32 using Keccak hash
            sample_id_bytes32 = Web3.keccak(text=data['sample_id'])

            # Build transaction
            tx = self.contract.functions.storeData(
                sample_id_bytes32,
                data['dna_referenceid']
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
                'gasPrice': self.web3.eth.gas_price  # Dynamic gas price
            })

            # Estimate gas
            tx['gas'] = self.web3.eth.estimateGas(tx)

            # Sign transaction
            signed_txn = self.web3.eth.account.sign_transaction(tx, private_key=self.private_key)

            # Send transaction
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)

            logger.info(f"✅ DNA data stored successfully. Tx hash: {tx_hash.hex()}")
            return tx_hash.hex()

        except (ConnectionError, TimeoutError) as e:
            logger.error(f"❌ Blockchain connection issue: {e}")
            return {"error": "Blockchain connection issue. Please try again later."}

        except Exception as e:
            logger.error(f"❌ Failed to store DNA on blockchain: {e}")
            traceback.print_exc()
            return {"error": str(e)}

    def update_blockchain_status(self, malware_metadata, status: str) -> Dict[str, str]:
        try:
            # Extract necessary metadata for storing
            sample_id = malware_metadata.sample_id
            filename = malware_metadata.filename
            file_hash = malware_metadata.file_hash
            dna_referenceid = getattr(malware_metadata, 'dna_referenceid', None) 
            timestamp = malware_metadata.timestamp
            if not dna_referenceid:
                logger.warning(f"⚠️ dna_referenceid missing for {sample_id}. Defaulting to 'unknown'.")
                dna_referenceid = "unknown"
  
            # Prepare data to store on the blockchain
            data_to_store = {
                'sample_id': sample_id,
                'filename': filename,
                'file_hash': file_hash,
                'dna_referenceid': dna_referenceid,
                'timestamp': timestamp.isoformat()
            }

            # Store the data on the blockchain
            tx_result = self.store_on_blockchain(data_to_store)
      
            return {"message": "Blockchain status updated successfully", "transaction_result": tx_result}
        except Exception as e:
            logger.error(f"❌ Failed to update blockchain status: {e}")
            return {"error": str(e)}


# Initialize service instance
try:
    blockchain_service: Optional[BlockchainService] = BlockchainService()
except Exception as e:
    logger.error(f"⚠️ Failed to initialize blockchain service: {e}")
    blockchain_service = None


# ---------------------------- FORENSIC WRAPPER FUNCTIONS ---------------------------- #

def store_forensic_evidence_on_blockchain(data: Dict[str, Any]) -> Dict[str, str]:
    if not blockchain_service:
        raise RuntimeError("Blockchain service is unavailable.")
    try:
        # Now passing the dictionary of data to store
        tx_result = blockchain_service.store_on_blockchain(data)
        logger.info("✅ Forensic evidence stored on blockchain.")
        return tx_result
    except Exception as e:
        logger.error(f"❌ Failed to store forensic evidence: {e}")
        raise
def store_threat_intel_on_blockchain(data: Dict[str, Any]) -> Dict[str, str]:
    if not blockchain_service:
        raise RuntimeError("Blockchain service is unavailable.")
    try:
        # Now passing the dictionary of data to store
        tx_result = blockchain_service.store_on_blockchain(data)
        logger.info("✅ Threat intel stored on blockchain.")
        return tx_result
    except Exception as e:
        logger.error(f"❌ Failed to store threat intel: {e}")
        raise


def verify_threat_intel_on_blockchain(data: Dict[str, Any], tx_id: str) -> bool:
    if not blockchain_service:
        raise RuntimeError("Blockchain service is unavailable.")
    try:
        return blockchain_service.verify_malware(data, tx_id)
    except Exception as e:
        logger.error(f"❌ Threat intel verification failed: {e}")
        raise

def verify_forensic_evidence_on_blockchain(data: Dict[str, Any], tx_id: str) -> bool:
    if not blockchain_service:
        raise RuntimeError("Blockchain service is unavailable.")
    try:
        return blockchain_service.verify_malware(data, tx_id)
    except Exception as e:
        logger.error(f"❌ Forensic evidence verification failed: {e}")
        raise

