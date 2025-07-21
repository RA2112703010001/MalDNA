import os
import json
import logging
import argparse
import subprocess
import numpy as np
from typing import Dict, List, Any, Optional

# Internal dependencies
from flask import Blueprint, jsonify, request
from app.models.behaviorModel import BehaviorLog
from app.services.blockchainService import store_ransomware_logs_on_blockchain, verify_ransomware_logs_on_blockchain
from app.utils.securityUtils import sanitize_file_path, validate_file
from app.utils.featureExtraction import extract_features_for_ml

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Flask Blueprint for Ransomware Detection
ransomware_bp = Blueprint("ransomware_detection", __name__)

# Configuration
CUCKOO_PATH = os.getenv("CUCKOO_PATH", "/usr/local/bin/cuckoo")
RAPID_MODIFICATION_THRESHOLD = int(os.getenv("RAPID_MODIFICATION_THRESHOLD", "10"))
RANSOMWARE_ANOMALY_THRESHOLD = float(os.getenv("RANSOMWARE_ANOMALY_THRESHOLD", "0.7"))


class RansomwareDetectionService:
    @classmethod
    def analyze_ransomware_behavior(cls, file_path: str) -> Dict[str, Any]:
        """Analyze ransomware behavior from a malware sample."""
        try:
            validated_path = sanitize_file_path(file_path)
            validate_file(validated_path)

            sandbox_report = cls._analyze_in_sandbox(validated_path)
            report = {
                "file_path": validated_path,
                "ransomware_indicators": cls._detect_ransomware_indicators(sandbox_report),
                "api_patterns": cls._recognize_api_patterns(sandbox_report),
                "ai_prediction": cls._ai_anomaly_detection(sandbox_report),
            }

            # Store in database
            behavior_log = BehaviorLog(file_path=validated_path, report=report)
            behavior_log.save()

            # Store on blockchain
            report["blockchain_verification"] = store_ransomware_logs_on_blockchain(report)

            logger.info(f"Ransomware analysis completed for {file_path}")
            return report
        except Exception as e:
            logger.error(f"Ransomware detection failed: {e}")
            raise

    @classmethod
    def _analyze_in_sandbox(cls, file_path: str) -> Dict[str, Any]:
        """Analyze file in Cuckoo Sandbox."""
        try:
            submit_command = [CUCKOO_PATH, "submit", "--timeout=300", file_path]
            task_id = cls._extract_task_id(cls._run_command(submit_command))

            report_command = [CUCKOO_PATH, "api", f"tasks/report/{task_id}"]
            return json.loads(cls._run_command(report_command))
        except Exception as e:
            logger.error(f"Sandbox analysis failed: {e}")
            raise

    @staticmethod
    def _run_command(command: List[str]) -> str:
        """Safely run subprocess commands."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=600)
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            raise

    @staticmethod
    def _extract_task_id(stdout: str) -> str:
        """Extract task ID from sandbox output."""
        try:
            return stdout.split("ID: ")[1].split("\n")[0].strip()
        except IndexError:
            logger.error(f"Could not extract task ID: {stdout}")
            raise ValueError("Failed to extract task ID from sandbox output.")

    @classmethod
    def _detect_ransomware_indicators(cls, sandbox_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect ransomware indicators based on file behavior."""
        try:
            ransomware_indicators = []
            file_activities = sandbox_report.get("behavior", {}).get("generic", [])

            # Detect rapid file modifications
            file_modifications = {}
            for event in file_activities:
                file_path = event.get("path", "")
                file_modifications[file_path] = file_modifications.get(file_path, 0) + 1

            rapid_modifications = {k: v for k, v in file_modifications.items() if v > RAPID_MODIFICATION_THRESHOLD}
            if rapid_modifications:
                ransomware_indicators.append({"type": "rapid_file_modifications", "details": rapid_modifications})

            return ransomware_indicators
        except Exception as e:
            logger.error(f"Ransomware behavior detection failed: {e}")
            raise

    @classmethod
    def _recognize_api_patterns(cls, sandbox_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify suspicious API patterns related to ransomware activity."""
        try:
            suspicious_patterns = {
                "encryption": ["CryptEncrypt", "BCryptEncrypt"],
                "file_operations": ["CreateFile", "WriteFile", "DeleteFile"],
                "registry": ["RegSetValue", "RegDeleteValue"]
            }

            detected_patterns = []
            api_calls = sandbox_report.get("behavior", {}).get("apistats", {})

            for process, calls in api_calls.items():
                for category, patterns in suspicious_patterns.items():
                    matching_calls = [call for call in calls if call in patterns]
                    if matching_calls:
                        detected_patterns.append({"process": process, "category": category, "calls": matching_calls})

            return detected_patterns
        except Exception as e:
            logger.error(f"API pattern recognition failed: {e}")
            raise

    @classmethod
    def _ai_anomaly_detection(cls, sandbox_report: Dict[str, Any]) -> str:
        """AI-powered anomaly detection for ransomware activity."""
        try:
            features = extract_features_for_ml(sandbox_report)
            anomaly_score = np.mean(features)
            return "malicious" if anomaly_score > RANSOMWARE_ANOMALY_THRESHOLD else "benign"
        except Exception as e:
            logger.error(f"AI anomaly detection failed: {e}")
            raise


# ---------------------------- Flask API Endpoints ---------------------------- #

@ransomware_bp.route("/ransomware/analyze", methods=["POST"])
def analyze_ransomware():
    """Perform ransomware behavior analysis."""
    data = request.json
    file_path = data.get("file_path")

    if not file_path:
        return jsonify({"error": "File path is required"}), 400

    try:
        service = RansomwareDetectionService()
        report = service.analyze_ransomware_behavior(file_path)
        return jsonify(report), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ransomware_bp.route("/ransomware/report/<sample_id>", methods=["GET"])
def retrieve_report(sample_id):
    """Retrieve ransomware report by sample ID."""
    try:
        report = BehaviorLog.objects.get(id=sample_id)
        return jsonify(report.to_json()), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 404


# ---------------------------- CLI FUNCTIONALITY ---------------------------- #

def cli_analyze_ransomware(file_path):
    """CLI function to analyze ransomware behavior."""
    service = RansomwareDetectionService()
    report = service.analyze_ransomware_behavior(file_path)
    print(json.dumps(report, indent=4))


def cli_fetch_report(sample_id):
    """CLI function to fetch a stored ransomware report."""
    try:
        report = BehaviorLog.objects.get(id=sample_id)
        print(json.dumps(report.to_json(), indent=4))
    except Exception as e:
        print(f"[❌] Error: {e}")


# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ransomware Detection CLI")
    parser.add_argument("--analyze", metavar="FILE", help="Analyze ransomware behavior from a file.")
    parser.add_argument("--fetch-report", metavar="SAMPLE_ID", help="Retrieve stored ransomware report.")

    args = parser.parse_args()

    if args.analyze:
        cli_analyze_ransomware(args.analyze)
    elif args.fetch_report:
        cli_fetch_report(args.fetch_report)
    else:
        print("[❌] Invalid CLI command.")

