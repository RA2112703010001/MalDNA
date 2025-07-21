import os
import json
import logging
import argparse
import subprocess
import hashlib
from datetime import datetime
from typing import List, Dict, Any

# Third-party
import yara
from bson import ObjectId
from dotenv import load_dotenv

# Internal dependencies
from app.models.forensicModel import ForensicModel, IncidentTimeline
from app.services.blockchainService import BlockchainService
from app.utils.securityUtils import sanitize_file_path

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment
load_dotenv()
VOLATILITY_PATH = os.getenv("VOLATILITY_PATH", "/usr/local/bin/volatility")
SCALPEL_CONFIG = os.getenv("SCALPEL_CONFIG", "/etc/scalpel.conf")
YARA_RULES_PATH = os.getenv("YARA_RULES_PATH", "/etc/yara/rules")

class ForensicService:
    """Service layer for forensic collection, analysis, and blockchain tracking."""

    @staticmethod
    def collect_forensic_evidence(file_path: str) -> Dict[str, Any]:
        """Extract DNA + timeline and enrich data."""
        dna = ForensicService.extract_malware_dna(file_path)
        timeline = ForensicService.reconstruct_incident_timeline(dna)
        return {
            "dna": dna,
            "timeline_events": timeline,
            "collected_at": datetime.utcnow().isoformat()
        }

    @staticmethod
    def manage_chain_of_custody(file_path: str) -> Dict[str, str]:
        """Log chain of custody info."""
        return {
            "file_path": file_path,
            "hash": hashlib.sha256(open(file_path, "rb").read()).hexdigest(),
            "collected_by": "MalDNA Automated",
            "timestamp": datetime.utcnow().isoformat()
        }

    @staticmethod
    def analyze_memory_dump(memory_dump_path: str) -> Dict[str, Any]:
        """Analyze memory with volatility."""
        command = [VOLATILITY_PATH, "-f", memory_dump_path, "imageinfo"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return {"path": memory_dump_path, "volatility_output": result.stdout}

    @staticmethod
    def analyze_disk_image(disk_image_path: str) -> Dict[str, Any]:
        """Analyze disk using fls (TSK)."""
        command = ["fls", "-r", disk_image_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return {"path": disk_image_path, "tsk_output": result.stdout}

    @staticmethod
    def yara_scan(file_path: str) -> List[str]:
        """Run YARA rules on the file."""
        rules = yara.compile(filepath=YARA_RULES_PATH)
        matches = rules.match(file_path)
        return [match.rule for match in matches]

    @staticmethod
    def extract_malware_dna(file_path: str) -> Dict[str, Any]:
        """Generate file hash + yara matches."""
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        yara_matches = ForensicService.yara_scan(file_path)
        return {
            "file": file_path,
            "sha256": file_hash,
            "yara_matches": yara_matches
        }

    @staticmethod
    def reconstruct_incident_timeline(forensic_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Simulate a basic timeline."""
        return [
            {"event": "Malware DNA extracted", "timestamp": datetime.utcnow().isoformat()},
            {"event": "File uploaded", "timestamp": datetime.utcnow().isoformat()}
        ]

    @staticmethod
    def analyze_memory_by_id(evidence_id: str) -> Dict[str, Any]:
        """Get memory path from DB and analyze."""
        evidence = ForensicModel.objects(id=ObjectId(evidence_id)).first()
        return ForensicService.analyze_memory_dump(evidence.file_path)

    @staticmethod
    def detect_rootkits_by_id(evidence_id: str) -> Dict[str, Any]:
        """Mock rootkit detection."""
        # TODO: Replace with rkhunter/volatility plugin logic
        return {"rootkits": ["No suspicious modules found"], "status": "clean"}

    @staticmethod
    def analyze_disk_image_by_id(evidence_id: str) -> Dict[str, Any]:
        """Get disk path from DB and analyze."""
        evidence = ForensicModel.objects(id=ObjectId(evidence_id)).first()
        return ForensicService.analyze_disk_image(evidence.file_path)

    @staticmethod
    def store_evidence_on_blockchain(forensic_data: Dict[str, Any]) -> str:
        """Commit forensic DNA to blockchain."""
        return BlockchainService.store_on_chain(data=forensic_data)

    @staticmethod
    def verify_evidence_integrity(evidence_id: str) -> Dict[str, Any]:
        """Cross-verify DNA hash with blockchain."""
        evidence = ForensicModel.objects(id=ObjectId(evidence_id)).first()
        local_hash = evidence.custody_info.get("hash")
        return BlockchainService.verify_on_chain(data={"sha256": local_hash})

    @staticmethod
    def generate_forensic_report(forensic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a structured forensic report."""
        blockchain_status = ForensicService.store_evidence_on_blockchain(forensic_data)
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "forensic_summary": forensic_data,
            "blockchain_verification": blockchain_status
        }

    @staticmethod
    def export_forensic_report(evidence_id: str, export_format: str = "pdf") -> str:
        """Export report to file (mock)."""
        report = ForensicService.generate_forensic_report(
            ForensicModel.objects(id=ObjectId(evidence_id)).first().forensic_data
        )
        export_path = f"/tmp/forensic_report_{evidence_id}.{export_format}"
        with open(export_path, "w") as f:
            json.dump(report, f, indent=4)
        return export_path

    @staticmethod
    def analyze_stored_evidence(evidence_id: str) -> Dict[str, Any]:
        """Run full analysis on stored sample."""
        evidence = ForensicModel.objects(id=ObjectId(evidence_id)).first()
        memory = ForensicService.analyze_memory_dump(evidence.file_path)
        disk = ForensicService.analyze_disk_image(evidence.file_path)
        dna = ForensicService.extract_malware_dna(evidence.file_path)
        return {"memory": memory, "disk": disk, "dna": dna}

# ---------------------------- CLI WRAPPERS ---------------------------- #

def cli_analyze_memory(memory_dump_path):
    result = ForensicService.analyze_memory_dump(memory_dump_path)
    print(json.dumps(result, indent=4))

def cli_analyze_disk(disk_image_path):
    result = ForensicService.analyze_disk_image(disk_image_path)
    print(json.dumps(result, indent=4))

def cli_extract_malware_dna(file_path):
    result = ForensicService.extract_malware_dna(file_path)
    print(json.dumps(result, indent=4))

def cli_generate_report(file_path):
    forensic_data = ForensicService.extract_malware_dna(file_path)
    report = ForensicService.generate_forensic_report(forensic_data)
    print(json.dumps(report, indent=4))

# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Forensic Analysis CLI")
    parser.add_argument("--memory", help="Analyze memory dump.")
    parser.add_argument("--disk", help="Analyze disk image.")
    parser.add_argument("--dna", help="Extract malware DNA.")
    parser.add_argument("--report", help="Generate forensic report.")

    args = parser.parse_args()
    if args.memory:
        cli_analyze_memory(args.memory)
    elif args.disk:
        cli_analyze_disk(args.disk)
    elif args.dna:
        cli_extract_malware_dna(args.dna)
    elif args.report:
        cli_generate_report(args.report)
    else:
        print("[❌] Invalid CLI command.")

