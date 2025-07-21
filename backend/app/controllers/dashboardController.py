import json
import logging
import argparse
from flask import Blueprint, jsonify, make_response
from flask_cors import cross_origin
from app.models.malwareModel import MalwareMetadata, MalwareModel
from app.models.dnaModel import DNAMetadata
from app.models.threatModel import ThreatMetadata
from app.models.forensicModel import ForensicMetadata
from pymongo.errors import OperationFailure
import pymongo
from app.controllers.blockchainservice import blockchain_service

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Flask Blueprint
dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

# ---------------------------- Dashboard API ---------------------------- #

@dashboard_bp.route("/stats", methods=["GET"], endpoint="get_dashboard_stats")
@cross_origin(origins="http://127.0.0.1:8080", supports_credentials=True)
def get_dashboard_stats():
    """Retrieve dashboard statistics for malware analysis and threats."""
    try:
        stats = fetch_dashboard_stats()

        response = make_response(jsonify(stats), 200)
        response.headers["Content-Type"] = "application/json"
        return response

    except Exception as e:
        logger.error(f"❌ Error fetching dashboard stats: {str(e)}")
        return make_response(jsonify({"error": "Failed to retrieve dashboard stats"}), 500)

def fetch_dashboard_stats():
    try:
        MalwareModel.fix_invalid_indexes()

        logger.info("Fetching total malware count...")
        total_malware = MalwareModel.objects.count()

        logger.info("Fetching distinct DNA sequences...")
        dna_sequences = MalwareModel.objects(malware_dna__ne=None).distinct("malware_dna")

        logger.info("Fetching active threats with high threat level...")
        active_threats = MalwareModel.objects(threat_level="high").count()

        logger.info("Fetching forensic evidence count...")
        forensic_evidence = MalwareModel.objects(malware_metadata__ne=None).count()

        logger.info("Fetching predictions count...")
        predictions = {
            "benign": MalwareModel.objects(prediction="benign").count(),
            "malicious": MalwareModel.objects(prediction="malicious").count(),
            "suspicious": MalwareModel.objects(prediction="suspicious").count()
        }

        # ✅ Blockchain-related stats using BlockchainService
        blockchain_verified_count = blockchain_service.get_blockchain_verified_count()
        blockchain_tx_entries_count = blockchain_service.get_blockchain_tx_entries_count()

        response = {
            "total_malware": total_malware,
            "dna_sequences": len(dna_sequences),
            "active_threats": active_threats,
            "forensic_evidence": forensic_evidence,
            "predictions": predictions,
            "highRiskThreats": active_threats,
            "uniqueFamilies": len(MalwareModel.objects.distinct("family_name")),
            "blockchain_verified": blockchain_verified_count,
            "blockchain_tx_entries": blockchain_tx_entries_count,
        }
        logger.info("Dashboard stats fetched successfully.")
        return response
    except OperationFailure as e:
        logger.error(f"❌ MongoDB OperationFailure: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"❌ Error fetching dashboard stats: {str(e)}")
        raise

# ---------------------------- CLI FUNCTIONALITY ---------------------------- #

def cli_fetch_dashboard_stats():
    """CLI command to retrieve malware analysis statistics."""
    try:
        stats = fetch_dashboard_stats()
        print(json.dumps(stats, indent=4))
    except Exception as e:
        print(f"[❌] Error fetching dashboard stats: {str(e)}")
        print("Ensure MongoDB is running and the indexes are configured properly.")

def cli_generate_dashboard_report(output_format="json"):
    """CLI command to generate a report on malware analysis and threats."""
    try:
        stats = fetch_dashboard_stats()

        report_file = "dashboard_report.json" if output_format == "json" else "dashboard_report.txt"
        with open(report_file, "w") as f:
            if output_format == "json":
                json.dump(stats, f, indent=4)
            elif output_format == "txt":
                for key, value in stats.items():
                    f.write(f"{key}: {value}\n")
            else:
                print("[❌] Unsupported format! Use 'json' or 'txt'.")
                return

        print(f"[✔] Dashboard report generated: {report_file}")

    except Exception as e:
        print(f"[❌] Error generating dashboard report: {str(e)}")

# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dashboard CLI Utility")
    parser.add_argument("--stats", help="Fetch dashboard statistics", action="store_true")
    parser.add_argument("--generate-report", help="Generate a dashboard report (json/txt)", type=str)

    args = parser.parse_args()

    if args.stats:
        cli_fetch_dashboard_stats()
    elif args.generate_report:
        cli_generate_dashboard_report(args.generate_report)
    else:
        logger.error("❌ Invalid CLI Arguments")
        print("[❌] Invalid CLI Arguments. Use --stats to fetch stats or --generate-report for reports.")

