import os
import json
import logging
import argparse
import subprocess
from typing import List, Dict, Any, Optional
from functools import wraps

# Import dependencies
import numpy as np
from dotenv import load_dotenv

# Internal dependencies
from app.models.behaviorModel import BehaviorLog
from app.services.blockchainService import store_api_logs_on_blockchain, verify_api_logs_on_blockchain
from app.utils.featureExtraction import extract_features_for_ml

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration constants
CUCKOO_PATH = os.getenv("CUCKOO_PATH", "/usr/local/bin/cuckoo")
ANOMALY_THRESHOLD = float(os.getenv("API_ANOMALY_THRESHOLD", "0.7"))


class APIBehaviorAnalysisService:
    @classmethod
    def monitor_api_calls(cls, sandbox_report: Dict[str, Any]) -> List[str]:
        """Extract API calls from a sandbox report."""
        try:
            api_calls = []
            if "behavior" in sandbox_report and "apistats" in sandbox_report["behavior"]:
                for process, calls in sandbox_report["behavior"]["apistats"].items():
                    api_calls.extend(calls)

            if not api_calls:
                logger.warning("No API calls detected in sandbox report")
            
            return api_calls
        except Exception as e:
            logger.error(f"API call monitoring failed: {e}")
            raise

    @classmethod
    def detect_behavioral_anomalies(cls, api_calls: List[str]) -> List[str]:
        """Detect anomalies in API behavior."""
        try:
            features = extract_features_for_ml(api_calls)
            anomaly_score = np.mean(features)

            return [
                call for call in api_calls 
                if cls._is_suspicious(call, anomaly_score)
            ]
        except Exception as e:
            logger.error(f"Behavioral anomaly detection failed: {e}")
            raise

    @staticmethod
    def _is_suspicious(call: str, anomaly_score: float) -> bool:
        """Check if an API call is suspicious."""
        suspicious_keywords = [
            "WriteProcessMemory", "CreateRemoteThread",
            "RegSetValue", "RegDeleteValue",
            "CreateFile", "DeleteFile"
        ]
        return call in suspicious_keywords or anomaly_score > ANOMALY_THRESHOLD

    @classmethod
    def generate_api_behavior_report(cls, file_path: str, sandbox_report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a full API behavior analysis report."""
        try:
            if not sandbox_report:
                sandbox_report = cls.analyze_api_calls_in_sandbox(file_path)

            api_calls = cls.monitor_api_calls(sandbox_report)

            report = {
                "file_path": file_path,
                "api_calls": api_calls,
                "anomalies": cls.detect_behavioral_anomalies(api_calls),
                "risk_assessment": cls.assess_api_risk(api_calls)
            }

            behavior_log = BehaviorLog(file_path=file_path, report=report)
            behavior_log.save()

            blockchain_verification = cls._log_api_calls_on_blockchain(api_calls)
            report["blockchain_verification"] = blockchain_verification

            logger.info(f"API behavior report generated for {file_path}")
            return report
        except Exception as e:
            logger.error(f"API behavior report generation failed: {e}")
            raise

    @staticmethod
    def _log_api_calls_on_blockchain(api_calls: List[str]) -> Dict[str, Any]:
        """Log API calls on blockchain for integrity verification."""
        blockchain_tx_id = store_api_logs_on_blockchain(api_calls)
        return verify_api_logs_on_blockchain(blockchain_tx_id)

    @classmethod
    def analyze_api_calls_in_sandbox(cls, file_path: str) -> Dict[str, Any]:
        """Submit file to Cuckoo Sandbox and retrieve API call report."""
        try:
            submit_command = [CUCKOO_PATH, "submit", file_path]
            submit_result = subprocess.run(submit_command, capture_output=True, text=True, check=True)

            task_id = cls._extract_task_id(submit_result.stdout)
            report_command = [CUCKOO_PATH, "api", f"tasks/report/{task_id}"]
            report_result = subprocess.run(report_command, capture_output=True, text=True, check=True)

            sandbox_report = json.loads(report_result.stdout)
            return sandbox_report
        except Exception as e:
            logger.error(f"Sandbox API call analysis failed: {e}")
            raise

    @staticmethod
    def _extract_task_id(stdout: str) -> str:
        """Extract task ID from Cuckoo Sandbox output."""
        try:
            return stdout.split("ID: ")[1].split("\n")[0].strip()
        except (IndexError, ValueError):
            raise ValueError("Failed to extract task ID from Cuckoo Sandbox output")


# ---------------------------- CLI FUNCTIONALITY ---------------------------- #

def cli_analyze_api(file_path):
    """CLI function to analyze API behavior in a file."""
    result = APIBehaviorAnalysisService.generate_api_behavior_report(file_path)
    print(json.dumps(result, indent=4))

def cli_export_api_logs(export_path):
    """CLI function to export API behavior logs."""
    logs = list(BehaviorLog.objects.all())
    with open(export_path, "w") as f:
        json.dump([log.to_json() for log in logs], f, indent=4)
    print(f"[✔] API behavior logs exported to {export_path}")

def cli_detect_anomalies(file_path):
    """CLI function to detect API behavior anomalies."""
    report = APIBehaviorAnalysisService.generate_api_behavior_report(file_path)
    print(json.dumps({"anomalies": report["anomalies"]}, indent=4))

def cli_verify_api_logs(api_log_json, tx_id):
    """CLI function to verify API behavior logs on the blockchain."""
    with open(api_log_json, "r") as file:
        api_log_data = json.load(file)
    result = verify_api_logs_on_blockchain(api_log_data, tx_id)
    print(json.dumps({"verified": result}, indent=4))


# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Behavior Analysis CLI")
    parser.add_argument("--analyze-api", metavar="FILE", help="Analyze API behavior from a file.")
    parser.add_argument("--export-logs", metavar="EXPORT_PATH", help="Export API logs to a file.")
    parser.add_argument("--detect-anomalies", metavar="FILE", help="Detect anomalies in API behavior.")
    parser.add_argument("--verify-logs", nargs=2, metavar=("LOG_JSON", "TX_ID"), help="Verify API logs on blockchain.")

    args = parser.parse_args()

    if args.analyze_api:
        cli_analyze_api(args.analyze_api)
    elif args.export_logs:
        cli_export_api_logs(args.export_logs)
    elif args.detect_anomalies:
        cli_detect_anomalies(args.detect_anomalies)
    elif args.verify_logs:
        cli_verify_api_logs(args.verify_logs[0], args.verify_logs[1])
    else:
        print("[❌] Invalid CLI command.")

