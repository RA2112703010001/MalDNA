import os
import logging
import argparse
import json
from flask import request, jsonify, Blueprint
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import threat intelligence services
from app.services.threatIntelligence import (
    check_virustotal,
    check_hybrid_analysis,
    check_maltiverse,
    check_ibmxforce,
    ThreatIntelligenceService
)

# Import models
from app.models.threatModel import ThreatIntel, IndicatorOfCompromise

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# MongoDB connection
try:
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
    client = MongoClient(MONGO_URI)
    db = client["MalDNA"]
    logger.info("✅ Successfully connected to MongoDB")
except Exception as e:
    logger.error(f"❌ MongoDB connection error: {e}")
    raise

# Blueprint definition
threat_bp = Blueprint("threat", __name__, url_prefix="/api/threat")

# ------------------- External Intelligence API Endpoints -------------------

@threat_bp.route("/intelligence/virustotal/<file_hash>", methods=["GET"])
def api_virustotal(file_hash):
    result = check_virustotal(file_hash)
    return jsonify(result), 200 if "error" not in result else 500

@threat_bp.route("/intelligence/hybrid_analysis/<file_hash>", methods=["GET"])
def api_hybrid_analysis(file_hash):
    result = check_hybrid_analysis(file_hash)
    return jsonify(result), 200 if "error" not in result else 500

@threat_bp.route("/intelligence/maltiverse/<file_hash>", methods=["GET"])
def api_maltiverse(file_hash):
    result = check_maltiverse(file_hash)
    return jsonify(result), 200 if "error" not in result else 500

@threat_bp.route("/intelligence/ibmxforce/<file_hash>", methods=["GET"])
def api_ibmxforce(file_hash):
    result = check_ibmxforce(file_hash)
    return jsonify(result), 200 if "error" not in result else 500

# ------------------- Internal Threat Intelligence Logic -------------------

@threat_bp.route("/analyze_dna", methods=["POST"])
def analyze_malware_dna():
    try:
        sample_id = request.json.get("sample_id")
        analysis_result = ThreatIntelligenceService.analyze_malware_dna(sample_id)
        return jsonify({"message": "Malware DNA analysis completed", "analysis_result": analysis_result}), 200
    except Exception as e:
        logger.error(f"❌ Malware DNA analysis error: {e}")
        return jsonify({"error": str(e)}), 500

@threat_bp.route("/correlate_dna", methods=["POST"])
def correlate_malware_dna():
    try:
        sample_id_1 = request.json.get("sample_id_1")
        sample_id_2 = request.json.get("sample_id_2")
        correlation_result = ThreatIntelligenceService.correlate_malware_dna(sample_id_1, sample_id_2)
        return jsonify({"message": "Malware DNA correlation completed", "correlation_result": correlation_result}), 200
    except Exception as e:
        logger.error(f"❌ Malware DNA correlation error: {e}")
        return jsonify({"error": str(e)}), 500

@threat_bp.route("/enrich_ioc", methods=["POST"])
def enrich_ioc_data():
    try:
        ioc_value = request.json.get("ioc_value")
        enrichment_result = ThreatIntelligenceService.enrich_ioc(ioc_value)
        return jsonify({"message": "IOC enrichment completed", "enrichment_result": enrichment_result}), 200
    except Exception as e:
        logger.error(f"❌ IoC enrichment error: {e}")
        return jsonify({"error": str(e)}), 500

@threat_bp.route("/ai_correlate", methods=["POST"])
def ai_driven_correlation():
    try:
        result = ThreatIntelligenceService.run_ai_correlation()
        return jsonify({"message": "AI-based correlation executed", "result": result}), 200
    except Exception as e:
        logger.error(f"❌ AI correlation error: {e}")
        return jsonify({"error": str(e)}), 500

@threat_bp.route("/store_blockchain", methods=["POST"])
def store_threat_on_blockchain():
    try:
        data_id = request.json.get("data_id")
        result = ThreatIntelligenceService.store_on_blockchain(data_id)
        return jsonify({"message": "Threat data stored on blockchain", "result": result}), 200
    except Exception as e:
        logger.error(f"❌ Blockchain storage error: {e}")
        return jsonify({"error": str(e)}), 500

@threat_bp.route("/fetch_reports", methods=["GET"])
def fetch_threat_reports():
    """Fetch stored threat intelligence reports from the database."""
    try:
        reports = list(db.threatIntel.find({}, {"_id": 0}))
        return jsonify({"message": "Threat intelligence reports retrieved", "reports": reports}), 200
    except Exception as e:
        logger.error(f"❌ Error fetching threat reports: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------- CLI Functions -------------------

def cli_fetch_threat_reports():
    try:
        reports = list(db.threatIntel.find({}, {"_id": 0}))
        print(json.dumps(reports, indent=4))
    except Exception as e:
        logger.error(f"❌ Error fetching threat reports: {e}")

def cli_bulk_ioc_correlation():
    try:
        iocs = list(db.indicatorsOfCompromise.find({}, {"_id": 0}))
        correlation_results = ThreatIntelligenceService.bulk_correlate_iocs(iocs)
        print(json.dumps(correlation_results, indent=4))
    except Exception as e:
        logger.error(f"❌ Bulk IoC correlation error: {e}")

def cli_collect_threat_intelligence(file_hash):
    try:
        vt_result = check_virustotal(file_hash)
        ha_result = check_hybrid_analysis(file_hash)
        maltiverse_result = check_maltiverse(file_hash)
        ibmxforce_result = check_ibmxforce(file_hash)

        threat_report = {
            "virustotal": vt_result,
            "hybrid_analysis": ha_result,
            "maltiverse": maltiverse_result,
            "ibmxforce": ibmxforce_result
        }

        print(json.dumps(threat_report, indent=4))
    except Exception as e:
        logger.error(f"❌ Threat intelligence collection error: {e}")

# ------------------- CLI Entry Point -------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence CLI Utility")
    parser.add_argument("--fetch-reports", help="Fetch past threat reports from database", action="store_true")
    parser.add_argument("--bulk-ioc", help="Perform bulk IoC correlation", action="store_true")
    parser.add_argument("--collect", help="Collect threat intelligence for a given file hash", type=str)

    args = parser.parse_args()

    if args.fetch_reports:
        cli_fetch_threat_reports()
    elif args.bulk_ioc:
        cli_bulk_ioc_correlation()
    elif args.collect:
        cli_collect_threat_intelligence(args.collect)
    else:
        logger.error("❌ Invalid CLI Arguments")

