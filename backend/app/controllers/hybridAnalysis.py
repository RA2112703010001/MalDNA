import os
import json
import logging
import hashlib
import argparse
from flask import Blueprint, jsonify, request
from app.models.malwareModel import MalwareModel
from app.services.staticAnalysis import StaticAnalysisService
from app.services.dynamicAnalysis import DynamicAnalysisService
from app.services.mlClassifier import MalwareClassifier
from app.services.blockchainService import BlockchainService
from app.services.hybridAnalysis import HybridAnalysisService
from app.utils.featureExtraction import FeatureExtractor

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("app")

# Blueprint with corrected URL prefix
hybrid_analysis_bp = Blueprint("hybrid_analysis", __name__, url_prefix="/api/hybrid-analysis")

class HybridAnalysisController:
    def __init__(self):
        self.static_service = StaticAnalysisService()
        self.dynamic_service = DynamicAnalysisService()
        self.classifier = MalwareClassifier(model_type="random_forest")
        self.blockchain_service = BlockchainService()
        self.hybrid_service = HybridAnalysisService()
        logger.info("Hybrid Analysis Controller initialized.")

    @hybrid_analysis_bp.route("/analyze", methods=["POST"])
    def analyze_malware():
        try:
            sample_hash = request.json.get("sample_hash")
            if not sample_hash:
                return jsonify({"error": "Missing sample_hash"}), 400

            hybrid_features = HybridAnalysisService().analyze(sample_hash)
            prediction, confidence = MalwareClassifier().predict(hybrid_features)
            malware_dna = HybridAnalysisController.generate_malware_dna(hybrid_features)

            report_id = HybridAnalysisController.save_analysis_results(
                {}, {}, hybrid_features, prediction, malware_dna
            )
            blockchain_record = BlockchainService().store_evidence(malware_dna)

            return jsonify({
                "report_id": report_id,
                "hybrid_features": hybrid_features,
                "prediction": prediction,
                "confidence": confidence,
                "malware_dna": malware_dna,
                "blockchain_record": blockchain_record
            }), 200

        except Exception as e:
            logger.error(f"Malware analysis failed: {e}")
            return jsonify({"error": "Comprehensive malware analysis failed"}), 500

    @hybrid_analysis_bp.route("/report/<sample_id>", methods=["GET"])
    def retrieve_hybrid_report(sample_id):
        try:
            sample = MalwareModel.objects(sample_id=sample_id).first()
            if not sample:
                return jsonify({"error": "Report not found"}), 404
            return jsonify(sample.to_dict()), 200
        except Exception as e:
            logger.error(f"Failed to retrieve hybrid report: {e}")
            return jsonify({"error": "Failed to retrieve report"}), 500

    @hybrid_analysis_bp.route("/auto_classify", methods=["POST"])
    def auto_classify():
        try:
            binary_path = request.json.get("binary_path")
            static_features = StaticAnalysisService().extract_features(binary_path)
            prediction, confidence = MalwareClassifier().predict(static_features)
            return jsonify({"prediction": prediction, "confidence": confidence}), 200
        except Exception as e:
            logger.error(f"Auto classification failed: {e}")
            return jsonify({"error": "Classification failed"}), 500

    @hybrid_analysis_bp.route("/extract_features", methods=["POST"])
    def extract_features():
        try:
            binary_path = request.json.get("binary_path")
            features = FeatureExtractor.extract_features_for_ml(binary_path)
            return jsonify({"features": features}), 200
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return jsonify({"error": "Feature extraction failed"}), 500

    @staticmethod
    def generate_malware_dna(hybrid_features):
        sorted_data = json.dumps(hybrid_features, sort_keys=True)
        return hashlib.sha256(sorted_data.encode()).hexdigest()[:40]

    @staticmethod
    def save_analysis_results(static_features, dynamic_features, hybrid_features, prediction, malware_dna):
        sample = MalwareModel(
            static_analysis=static_features,
            dynamic_analysis=dynamic_features,
            hybrid_features=hybrid_features,
            prediction=prediction,
            malware_dna=malware_dna
        )
        sample.save()
        return str(sample.sample_id)


# ----------------------------- CLI SUPPORT ----------------------------- #

def cli_analyze_malware(sample_hash):
    try:
        hybrid_features = HybridAnalysisService().analyze(sample_hash)
        prediction, confidence = MalwareClassifier().predict(hybrid_features)
        malware_dna = HybridAnalysisController.generate_malware_dna(hybrid_features)
        report_id = HybridAnalysisController.save_analysis_results({}, {}, hybrid_features, prediction, malware_dna)
        blockchain_record = BlockchainService().store_evidence(malware_dna)

        print(f"[✔] Report ID: {report_id}")
        print(f"Prediction: {prediction} (Confidence: {confidence})")
        print(f"DNA: {malware_dna}")
        print(f"Blockchain: {blockchain_record}")
    except Exception as e:
        print(f"[❌] Analysis failed: {e}")

def cli_retrieve_hybrid_report(sample_id):
    try:
        sample = MalwareModel.objects(sample_id=sample_id).first()
        if not sample:
            print("[❌] Report not found.")
        else:
            print(json.dumps(sample.to_mongo().to_dict(), indent=4, default=str))
    except Exception as e:
        print(f"[❌] Retrieval failed: {e}")

def cli_extract_features(binary_path):
    try:
        features = FeatureExtractor.extract_features_for_ml(binary_path)
        print(json.dumps(features, indent=4))
    except Exception as e:
        print(f"[❌] Extraction failed: {e}")

def cli_auto_classify(binary_path):
    try:
        static_features = StaticAnalysisService().extract_features(binary_path)
        prediction, confidence = MalwareClassifier().predict(static_features)
        print(f"Prediction: {prediction}, Confidence: {confidence}")
    except Exception as e:
        print(f"[❌] Classification failed: {e}")


# --------------------------- CLI HANDLER --------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid Malware Analysis CLI")
    parser.add_argument("--analyze", metavar="SAMPLE_HASH", help="Analyze malware using sample hash")
    parser.add_argument("--report", metavar="SAMPLE_ID", help="Retrieve hybrid report")
    parser.add_argument("--extract", metavar="BINARY_PATH", help="Extract features")
    parser.add_argument("--classify", metavar="BINARY_PATH", help="Classify malware sample")

    args = parser.parse_args()

    if args.analyze:
        cli_analyze_malware(args.analyze)
    elif args.report:
        cli_retrieve_hybrid_report(args.report)
    elif args.extract:
        cli_extract_features(args.extract)
    elif args.classify:
        cli_auto_classify(args.classify)
    else:
        logger.error("❌ Invalid CLI Arguments")

