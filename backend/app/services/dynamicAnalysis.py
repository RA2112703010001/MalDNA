import os
import json
import logging
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Any
import random
import shutil
from dotenv import load_dotenv
import uuid
# Internal dependencies
from app.models.behaviorModel import BehaviorModel
from app.services.dnaService import DNAAnalysisService
from app.utils.featureExtraction import FeatureExtractor
from app.services.threatIntelligence import ThreatIntelligenceService

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration Constants
GHIDRA_HEADLESS = os.getenv("GHIDRA_HEADLESS", "/opt/ghidra_10.4_PUBLIC/support/analyzeHeadless")
GHIDRA_PROJECT_DIR = os.getenv("GHIDRA_PROJECT_DIR", "/home/kali/MalDNA/ghidra_projects")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/home/kali/MalDNA/output/")

# Ensure necessary directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(GHIDRA_PROJECT_DIR, exist_ok=True)
os.makedirs("/home/kali/MalDNA/dataset/", exist_ok=True)


class DynamicAnalysisService:
    @staticmethod
    def validate_file_path(file_path: str):
        if not isinstance(file_path, str) or not file_path.strip():
            logger.error(f"Invalid file path: {file_path}")
            raise ValueError("Invalid file path. Expected a valid string.")
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logger.error(f"File does not exist or is not a valid file: {file_path}")
            raise FileNotFoundError(f"File does not exist: {file_path}")

    @classmethod
    def execute_with_ghidra(cls, file_path: str) -> Dict[str, Any]:
        try:
            cls.validate_file_path(file_path)
            project_name = f"malware_{random.randint(1000, 9999)}"
            ghidra_command = [
                GHIDRA_HEADLESS,
                GHIDRA_PROJECT_DIR,
                project_name,
                "-import",
                file_path,
                "-postScript",
                "GhidraAnalysisScript.java"
            ]

            logger.info(f"🛠 Running Ghidra Analysis: {' '.join(ghidra_command)}")

            # Increase timeout to 600 seconds (10 minutes)
            process = subprocess.Popen(ghidra_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=600)

            if process.returncode != 0:
                logger.error(f"❌ Ghidra Analysis Failed: {stderr}")
                return {"error": f"Ghidra analysis failed: {stderr}"}

            logger.info(f"✅ Ghidra Analysis Completed for {file_path}")
            return {"ghidra_output": stdout.strip()}

        except subprocess.TimeoutExpired:
            logger.error(f"❌ Ghidra analysis timed out after 600 seconds for {file_path}")
            return {"error": "Ghidra analysis timed out after 600 seconds."}
        except Exception as e:
            logger.error(f"❌ Error executing Ghidra analysis: {e}")
            return {"error": f"Error executing Ghidra analysis: {e}"}

    @classmethod
    def generate_dynamic_analysis_report(cls, file_path: str) -> Dict[str, Any]:
        try:
            logger.info(f"🔍 Received file for dynamic analysis: {file_path}")
            cls.validate_file_path(file_path)

            sample_id = str(random.randint(1000, 9999))
            ghidra_result = cls.execute_with_ghidra(file_path)
            if "error" in ghidra_result:
                return ghidra_result

            features = FeatureExtractor.extract_dynamic_features_from_ghidra(ghidra_result.get("ghidra_output", ""))
            iocs = cls._extract_iocs(ghidra_result)
            classification = cls._ai_behavioral_classification(ghidra_result)
            dna_signature = DNAAnalysisService.generate_dna_sequence(file_path)
            blockchain_status = cls.verify_blockchain(dna_signature)

            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "sample_id": sample_id,
                "file_path": file_path,
                "ghidra_result": ghidra_result,
                "features": features,
                "behavioral_classification": classification,
                "dna_signature": dna_signature,
                "blockchain_verification": blockchain_status,
                "threat_intelligence": iocs
            }

            logger.info(f"📝 Report Preview: {json.dumps(report, indent=2)[:500]}...")

            output_file = os.path.join(OUTPUT_DIR, f"report_{sample_id}.json")
            with open(output_file, "w") as f:
                json.dump(report, f, indent=4)

            logger.info(f"✅ Analysis report saved: {output_file}")

            behavior_log = BehaviorModel(sample_id=sample_id, file_path=file_path, report=report)
            if not behavior_log.sample_id:
                logger.error("❌ sample_id is missing before saving to MongoDB!")
                raise ValueError("sample_id cannot be empty.")

            behavior_log.save()
            return report

        except Exception as e:
            logger.error(f"❌ Dynamic analysis failed: {e}")
            raise

    @staticmethod
    def _extract_iocs(ghidra_result: Dict[str, Any]) -> Dict[str, List[str]]:
        return ThreatIntelligenceService.extract_iocs(ghidra_result)

    @staticmethod
    def _ai_behavioral_classification(ghidra_result: Dict[str, Any]) -> str:
        if "malicious" in ghidra_result.get("ghidra_output", "").lower():
            return "High Risk"
        return "Low Risk"

    @staticmethod
    def verify_blockchain(dna_signature: str) -> str:
        return "Blockchain Verification: Success" if dna_signature else "Blockchain Verification: Failed"

    # ---------------------------- CLI HANDLER ---------------------------- #

def cli_run_ghidra(args):
    file_path = DynamicAnalysisService.upload_sample(args.file)
    result = DynamicAnalysisService.execute_with_ghidra(file_path)
    print(json.dumps(result, indent=4))

def cli_generate_report(args):
    file_path = DynamicAnalysisService.upload_sample(args.file)
    report = DynamicAnalysisService.generate_dynamic_analysis_report(file_path)
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghidra-Based Malware Analysis CLI")
    subparsers = parser.add_subparsers(help="Commands")

    parser_ghidra = subparsers.add_parser("run_ghidra", help="Analyze malware using Ghidra")
    parser_ghidra.add_argument("--file", required=True, help="Path to malware sample")
    parser_ghidra.set_defaults(func=cli_run_ghidra)

    parser_report = subparsers.add_parser("generate_report", help="Generate malware analysis report")
    parser_report.add_argument("--file", required=True, help="Path to malware sample")
    parser_report.set_defaults(func=cli_generate_report)

    args = parser.parse_args()
    args.func(args)

