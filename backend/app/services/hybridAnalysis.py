import os
import json
import hashlib
import logging
import requests
from datetime import datetime
import subprocess
from typing import Dict, List, Any, Optional

from app.models.malwareModel import MalwareModel
from app.models.hybridModel import HybridAnalysisReport
from app.services.blockchainService import blockchain_service
from app.utils.featureExtraction import FeatureExtractor
from app.utils.blockchainUtils import (
    store_on_blockchain,
    get_reputation,
    verify_on_blockchain
)
from app.services.lineageService import LineageAnalysisService
from app.utils.securityUtils import sanitize_file_path, validate_file
from ml.models.mlClassifier import MalwareClassifier
from mongoengine.errors import NotUniqueError

logger = logging.getLogger(__name__)

class HybridAnalysisService:
    def __init__(self):
        self.api_key = os.getenv("HYBRID_ANALYSIS_API_KEY")
        self.lineage_service = LineageAnalysisService()
        self._validate_analysis_tools()
        logger.info("HybridAnalysisService initialized")

    def calculate_hash(self, file_path: str) -> str:
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            raise

    def _validate_analysis_tools(self):
        radare2_path = os.getenv("RADARE2_PATH")
        if not radare2_path or not os.path.exists(radare2_path):
            raise ValueError("Radare2 path is not configured or does not exist")

        ghidra_headless = os.getenv("GHIDRA_HEADLESS")
        ghidra_project_dir = os.getenv("GHIDRA_PROJECT_DIR")
        if not ghidra_headless or not os.path.exists(ghidra_headless):
            raise ValueError("GHIDRA_HEADLESS path is not set or does not exist")
        if not ghidra_project_dir or not os.path.isdir(ghidra_project_dir):
            raise ValueError("GHIDRA_PROJECT_DIR is not set or does not exist")

    def fetch_features(self, file_path: str) -> Optional[Dict[str, Any]]:
        for fetcher in [self.fetch_from_hybrid_analysis, self.fetch_from_virustotal, self.fetch_from_maltiverse]:
            try:
                features = fetcher(file_path)
                if features:
                    return features
            except Exception as e:
                logger.warning(f"[{fetcher.__name__}] Error: {e}")
        return None

    def fetch_from_hybrid_analysis(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            headers = {
                "api-key": self.api_key,
                "User-Agent": "Falcon Sandbox",
                "Content-Type": "application/json"
            }
            sample_hash = self.calculate_hash(file_path)
            url = f"https://www.hybrid-analysis.com/api/v2/report/{sample_hash}"
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                report = response.json()
                if isinstance(report, dict):
                    return self.structure_features(
                        source="HybridAnalysis",
                        score=report.get("threat_score", 0),
                        verdict=report.get("verdict", "unknown"),
                        file_type=report.get("type", "unknown"),
                        domains=report.get("domains", []),
                        tags=report.get("classification_tags", []),
                        reputation=None
                    )
            else:
                logger.warning(f"Failed HybridAnalysis API call for {file_path}: {response.status_code}")
        except Exception as e:
            logger.warning(f"[HybridAnalysis] Exception: {e}")
        return None

    def fetch_from_virustotal(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
            headers = {"x-apikey": vt_api_key}
            sample_hash = self.calculate_hash(file_path)
            vt_url = f"https://www.virustotal.com/api/v3/files/{sample_hash}"
            response = requests.get(vt_url, headers=headers)

            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                total = sum(stats.values())
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                score = int((positives / total) * 100) if total > 0 else 0
                return self.structure_features(
                    source="VirusTotal",
                    score=score,
                    verdict=data.get("meaningful_name", "unknown"),
                    file_type=data.get("type_description", "unknown"),
                    domains=data.get("contacted_domains", []),
                    tags=data.get("tags", []),
                    reputation=None
                )
        except Exception as e:
            logger.warning(f"[VirusTotal] Exception: {e}")
        return None

    def fetch_from_maltiverse(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            mv_api_key = os.getenv("MALTIVERSE_API_KEY")
            headers = {"Authorization": f"Bearer {mv_api_key}"}
            sample_hash = self.calculate_hash(file_path)
            mv_url = f"https://api.maltiverse.com/hash/{sample_hash}"
            response = requests.get(mv_url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                score = data.get("reputation", 0) * 10
                return self.structure_features(
                    source="Maltiverse",
                    score=score,
                    verdict=data.get("classification", "unknown"),
                    file_type=data.get("type", "unknown"),
                    domains=data.get("seen_domains", []),
                    tags=data.get("tags", []),
                    reputation=data.get("reputation", None)
                )
        except Exception as e:
            logger.warning(f"[Maltiverse] Exception: {e}")
        return None

    def structure_features(self, source: str, score: int, verdict: str, file_type: str,
                           domains: List[str], tags: List[str], reputation: Optional[Any]) -> Dict[str, Any]:
        return {
            "source": source,
            "score": score,
            "verdict": verdict,
            "file_type": file_type,
            "domains": domains or [],
            "classification_tags": tags or [],
            "reputation": reputation
        }

    def perform_analysis(self, file_path: str) -> Dict[str, Any]:
        try:
            hybrid_features = self.fetch_features(file_path)
            if not hybrid_features:
                raise ValueError("Hybrid analysis failed to fetch any features.")

            static_results = self.static_analysis(file_path)
            dynamic_results = self.ghidra_analysis(file_path)

            prediction_result, confidence = MalwareClassifier().predict(hybrid_features)
            confidence_score = float(confidence.get("malicious", 0) if isinstance(confidence, dict) else confidence)
            risk_score = min(100.0, confidence_score * 100)

            sample_id = hashlib.sha256(file_path.encode()).hexdigest()

            # Save to database and lineage analysis
            report_id = self.save_analysis_results(
                sample_id=sample_id,
                file_name=os.path.basename(file_path),
                static_features=static_results,
                dynamic_features=dynamic_results,
                hybrid_features=hybrid_features,
                classification_result={"classification": prediction_result}
            )

            # Perform lineage analysis on the saved report
            lineage_result = self.lineage_service.analyze_lineage(report_id)

            return {
                "report_id": report_id,
                "hybrid_features": hybrid_features,
                "static_results": static_results,
                "dynamic_results": dynamic_results,
                "lineage_result": lineage_result
            }

        except Exception as e:
            logger.exception(f"[perform_analysis] Failed: {e}")
            return {"error": f"Analysis failed: {str(e)}"}

    def static_analysis(self, file_path: str) -> Dict[str, Any]:
        try:
            validated_path = sanitize_file_path(file_path)
            validate_file(validated_path)
            radare2_path = os.getenv("RADARE2_PATH")
            command = [radare2_path, "-A", "-q", "-c", "aaa; pdf", validated_path]

            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            return {
                "disassembly": result.stdout,
                "stderr": result.stderr,
                "hash": hashlib.sha256(result.stdout.encode()).hexdigest()
            }
        except Exception as e:
            logger.error(f"Static analysis failed for {file_path}: {e}")
            raise

    def ghidra_analysis(self, file_path: str) -> Dict[str, Any]:
        try:
            validated_path = sanitize_file_path(file_path)
            validate_file(validated_path)

            ghidra_headless = os.getenv("GHIDRA_HEADLESS")
            ghidra_project_dir = os.getenv("GHIDRA_PROJECT_DIR")
            ghidra_script = os.getenv("GHIDRA_ANALYSIS_SCRIPT", "AnalyzeMalware.java")

            project_name = "MalwareProject"
            command = [
                ghidra_headless,
                ghidra_project_dir,
                project_name,
                "-import", validated_path,
                "-scriptPath", ghidra_script
            ]

            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            return {
                "ghidra_output": result.stdout,
                "stderr": result.stderr,
                "hash": hashlib.sha256(result.stdout.encode()).hexdigest()
            }
        except Exception as e:
            logger.error(f"Ghidra analysis failed for {file_path}: {e}")
            raise

    def save_analysis_results(self, sample_id, file_name, static_features, dynamic_features, hybrid_features, classification_result):
        try:
            # Ensure classification_result is a string (or serialized if it's a dictionary)
            if isinstance(classification_result, dict):
                classification_result = json.dumps(classification_result)

            # Ensure that all required fields are present before saving
            file_path = file_name  # Assuming file_name will act as the file path for now

            existing_report = HybridAnalysisReport.objects(sample_id=sample_id).first()
            if existing_report:
                logger.warning(f"Hybrid analysis report already exists for sample_id={sample_id}. Updating existing report.")
                existing_report.update(
                    file_name=file_name,
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                    hybrid_features=hybrid_features,
                    classification_result=classification_result,
                    updated_at=datetime.utcnow()
                )
                return existing_report.id

            report = HybridAnalysisReport(
                sample_id=sample_id,
                file_name=file_name,
                file_path=file_path,  # Add the file_path here
                sample_hash=sample_id,  # Assuming the sample_hash is same as sample_id
                static_features=static_features,
                dynamic_features=dynamic_features,
                hybrid_features=hybrid_features,
                classification_result=classification_result,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )

            report.save()
            logger.info(f"Successfully saved HybridAnalysisReport with sample_id={sample_id}")
            return report.id

        except Exception as e:
            logger.error(f"Failed to save analysis results for {sample_id}: {e}")
            raise

