import os
import json
import logging
import argparse
import requests
from typing import Dict, Any, List
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Internal dependencies
from app.utils.securityUtils import sanitize_input
from app.services.blockchainService import (
    store_threat_intel_on_blockchain,
    verify_threat_intel_on_blockchain
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# API Keys for threat intelligence services
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
MALTIVERSE_API_KEY = os.getenv("MALTIVERSE_API_KEY")
IBMXFORCE_API_KEY = os.getenv("IBMXFORCE_API_KEY")

def validate_api_key(func):
    """Decorator to validate API keys before making API calls."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not any([VIRUSTOTAL_API_KEY, HYBRID_ANALYSIS_API_KEY, MALTIVERSE_API_KEY, IBMXFORCE_API_KEY]):
            logger.error("Missing one or more required API keys.")
            raise ValueError("One or more required API keys are missing.")
        return func(*args, **kwargs)
    return wrapper

class ThreatIntelligenceService:
    @staticmethod
    def extract_iocs(sandbox_report: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract IOCs (IPs, Domains, Hashes, URLs) from a malware sandbox report."""
        iocs = []

        if "network" in sandbox_report:
            net = sandbox_report["network"]
            for ip in net.get("ips", []):
                iocs.append({"type": "ip", "value": ip})
            for domain in net.get("domains", []):
                iocs.append({"type": "domain", "value": domain})
            for url in net.get("urls", []):
                iocs.append({"type": "url", "value": url})

        if "static" in sandbox_report:
            static = sandbox_report["static"]
            for hash_type in ("md5", "sha1", "sha256"):
                if static.get(hash_type):
                    iocs.append({"type": "hash", "subtype": hash_type, "value": static[hash_type]})

        logger.info(f"[✅] Extracted {len(iocs)} IOCs from sandbox report")
        return iocs

    @classmethod
    @validate_api_key
    def analyze_malware_dna(cls, file_hash: str) -> Dict[str, Any]:
        """Analyze malware file hash against multiple threat intelligence databases."""
        sanitized_hash = sanitize_input(file_hash)
        results = {
            "VirusTotal": check_virustotal(sanitized_hash),
            "HybridAnalysis": check_hybrid_analysis(sanitized_hash),
            "Maltiverse": check_maltiverse(sanitized_hash),
            "IBM X-Force": check_ibmxforce(sanitized_hash),
        }
        logger.info(f"[🔬] Threat intel lookup complete for hash: {sanitized_hash}")
        return results

    @classmethod
    def store_threat_on_blockchain(cls, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store threat intelligence on the blockchain."""
        tx_id = store_threat_intel_on_blockchain(threat_data)
        logger.info(f"[🛡️] Stored threat intel on blockchain - TX ID: {tx_id}")
        return {"blockchain_tx_id": tx_id}

    @classmethod
    def verify_threat_on_blockchain(cls, threat_data: Dict[str, Any], tx_id: str) -> bool:
        """Verify threat intelligence integrity on the blockchain."""
        is_verified = verify_threat_intel_on_blockchain(threat_data, tx_id)
        if is_verified:
            logger.info(f"[✅] Threat data verified successfully for TX ID: {tx_id}")
        else:
            logger.warning(f"[❌] Verification failed for TX ID: {tx_id}")
        return is_verified

# ---------------------------- API HELPER FUNCTIONS ---------------------------- #

def check_virustotal(file_hash: str) -> Dict[str, Any]:
    """Check file hash against VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers, timeout=10)
    return response.json() if response.status_code == 200 else {"error": "VirusTotal lookup failed"}

def check_hybrid_analysis(file_hash: str) -> Dict[str, Any]:
    """Check file hash against Hybrid Analysis."""
    url = f"https://www.hybrid-analysis.com/api/v2/report/{file_hash}"
    headers = {"api-key": HYBRID_ANALYSIS_API_KEY}
    response = requests.get(url, headers=headers, timeout=10)
    return response.json() if response.status_code == 200 else {"error": "Hybrid Analysis lookup failed"}

def check_maltiverse(file_hash: str) -> Dict[str, Any]:
    """Check file hash against Maltiverse."""
    url = f"https://api.maltiverse.com/sample/{file_hash}"
    headers = {"Authorization": f"Bearer {MALTIVERSE_API_KEY}"}
    response = requests.get(url, headers=headers, timeout=10)
    return response.json() if response.status_code == 200 else {"error": "Maltiverse lookup failed"}

def check_ibmxforce(file_hash: str) -> Dict[str, Any]:
    """Check file hash against IBM X-Force."""
    url = f"https://api.xforce.ibmcloud.com/malware/{file_hash}"
    headers = {"Authorization": f"Bearer {IBMXFORCE_API_KEY}"}
    response = requests.get(url, headers=headers, timeout=10)
    return response.json() if response.status_code == 200 else {"error": "IBM X-Force lookup failed"}

# ---------------------------- CLI FUNCTIONALITY ---------------------------- #

def cli_analyze_malware_dna(file_hash):
    result = ThreatIntelligenceService.analyze_malware_dna(file_hash)
    print(json.dumps(result, indent=4))

def cli_store_threat_on_blockchain(threat_json):
    with open(threat_json, "r") as file:
        threat_data = json.load(file)
    result = ThreatIntelligenceService.store_threat_on_blockchain(threat_data)
    print(json.dumps(result, indent=4))

def cli_verify_threat_on_blockchain(threat_json, tx_id):
    with open(threat_json, "r") as file:
        threat_data = json.load(file)
    result = ThreatIntelligenceService.verify_threat_on_blockchain(threat_data, tx_id)
    print(json.dumps({"verified": result}, indent=4))

# ---------------------------- CLI ENTRY POINT ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence CLI")
    parser.add_argument("--analyze-hash", metavar="HASH", help="Analyze malware file hash against threat intelligence databases.")
    parser.add_argument("--store-threat", metavar="JSON", help="Store threat intelligence on blockchain.")
    parser.add_argument("--verify-threat", nargs=2, metavar=("JSON", "TX_ID"), help="Verify threat intelligence integrity on blockchain.")

    args = parser.parse_args()

    if args.analyze_hash:
        cli_analyze_malware_dna(args.analyze_hash)
    elif args.store_threat:
        cli_store_threat_on_blockchain(args.store_threat)
    elif args.verify_threat:
        cli_verify_threat_on_blockchain(args.verify_threat[0], args.verify_threat[1])
    else:
        print("[❌] Invalid CLI command.")

