import os
import logging
import argparse
from functools import wraps
from flask import request, jsonify, Blueprint
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS, cross_origin

# Import services
from app.services.forensicService import ForensicService
from app.services.blockchainService import BlockchainService

# Import models
from app.models.forensicModel import ForensicModel, IncidentTimeline

# Configuration
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
client = MongoClient(MONGO_URI)
db = client["MalDNA"]
logger.info("✅ Successfully connected to MongoDB")

# Blueprint
forensic_bp = Blueprint("forensic", __name__, url_prefix="/api/forensic")
CORS(forensic_bp, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# ------------------- VALIDATIONS -------------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {'dd', 'img', 'vmem', 'raw', 'bin', 'pcap', 'log'}

def validate_file_upload(func):
    @wraps(func)
    def validate_wrapper(*args, **kwargs):
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400
        return func(*args, **kwargs)
    return validate_wrapper

# ------------------- API ENDPOINTS -------------------

@forensic_bp.route("/evidence", methods=["POST"], endpoint="collect_forensic_evidence")
@validate_file_upload
def collect_forensic_evidence():
    try:
        file = request.files["file"]
        filename = secure_filename(file.filename)
        file_path = os.path.join("/tmp/forensic_uploads", filename)
        os.makedirs("/tmp/forensic_uploads", exist_ok=True)
        file.save(file_path)

        forensic_data = ForensicService.collect_forensic_evidence(file_path)
        custody_info = ForensicService.manage_chain_of_custody(file_path)

        forensic_record = ForensicModel(
            filename=filename,
            file_path=file_path,
            forensic_data=forensic_data,
            custody_info=custody_info
        )
        forensic_record.save()

        blockchain_tx_id = ForensicService.store_evidence_on_blockchain(forensic_data)

        logger.info(f"✅ Forensic evidence collected: {filename}")
        return jsonify({
            "message": "Forensic evidence collected successfully",
            "evidence_id": str(forensic_record.id),
            "blockchain_tx_id": blockchain_tx_id
        }), 200

    except Exception as e:
        logger.error(f"❌ Forensic evidence collection error: {e}")
        return jsonify({"error": str(e)}), 500


@forensic_bp.route("/analyze_memory", methods=["POST"], endpoint="analyze_memory_dump")
def analyze_memory_dump():
    try:
        data = request.get_json()
        evidence_id = data.get("evidence_id")
        if not evidence_id:
            return jsonify({"error": "Evidence ID is required"}), 400

        memory_analysis = ForensicService.analyze_memory_by_id(evidence_id)
        rootkit_detection = ForensicService.detect_rootkits_by_id(evidence_id)

        logger.info(f"✅ Memory forensics completed for: {evidence_id}")
        return jsonify({
            "message": "Memory forensics completed",
            "memory_analysis": memory_analysis,
            "rootkit_detection": rootkit_detection
        }), 200

    except Exception as e:
        logger.error(f"❌ Memory forensics error: {e}")
        return jsonify({"error": str(e)}), 500


@forensic_bp.route("/analyze_disk", methods=["POST"], endpoint="analyze_disk_image")
def analyze_disk_image():
    try:
        data = request.get_json()
        evidence_id = data.get("evidence_id")
        if not evidence_id:
            return jsonify({"error": "Evidence ID is required"}), 400

        disk_analysis = ForensicService.analyze_disk_image_by_id(evidence_id)

        logger.info(f"✅ Disk image analysis completed for: {evidence_id}")
        return jsonify({
            "message": "Disk image analysis completed",
            "disk_analysis": disk_analysis
        }), 200

    except Exception as e:
        logger.error(f"❌ Disk image analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@forensic_bp.route("/report", methods=["POST"], endpoint="generate_forensic_report_post")
def generate_forensic_report_post():
    try:
        data = request.get_json()
        sample_id = data.get("sample_id")
        if not sample_id:
            return jsonify({"error": "Sample ID is required"}), 400

        evidence_record = db.forensic.find_one({"_id": ObjectId(sample_id)})
        if not evidence_record:
            return jsonify({"error": "Forensic evidence not found"}), 404

        report = ForensicService.generate_forensic_report(evidence_record["forensic_data"])

        logger.info(f"✅ Forensic report generated for sample ID: {sample_id}")
        return jsonify({
            "message": "Forensic report generated successfully",
            "report": report
        }), 200

    except Exception as e:
        logger.error(f"❌ Report generation error: {e}")
        return jsonify({"error": str(e)}), 500


@forensic_bp.route("/verify_integrity", methods=["GET"], endpoint="verify_evidence_integrity")
def verify_evidence_integrity():
    try:
        evidence_id = request.args.get("evidence_id")
        if not evidence_id:
            return jsonify({"error": "Evidence ID is required"}), 400

        integrity_status = ForensicService.verify_evidence_integrity(evidence_id)

        logger.info(f"✅ Integrity verified for evidence: {evidence_id}")
        return jsonify({
            "message": "Evidence integrity verified",
            "integrity_status": integrity_status
        }), 200

    except Exception as e:
        logger.error(f"❌ Integrity verification error: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------- CLI FUNCTIONS -------------------

def cli_analyze_stored_evidence(evidence_id):
    try:
        evidence_record = db.forensic.find_one({"_id": ObjectId(evidence_id)})
        if not evidence_record:
            logger.error("❌ Forensic evidence not found")
            return

        forensic_data = ForensicService.analyze_stored_evidence(evidence_id)
        logger.info(f"✅ Forensic Analysis for Evidence {evidence_id}: {forensic_data}")

    except Exception as e:
        logger.error(f"❌ Forensic analysis error: {e}")

def cli_fetch_forensic_evidence(evidence_id):
    try:
        evidence_record = db.forensic.find_one({"_id": ObjectId(evidence_id)})
        if not evidence_record:
            logger.error("❌ Evidence not found")
            return
        logger.info(f"✅ Retrieved Forensic Evidence for {evidence_id}: {evidence_record}")

    except Exception as e:
        logger.error(f"❌ Forensic evidence retrieval error: {e}")

def cli_export_forensic_report(evidence_id, export_format="pdf"):
    try:
        evidence_record = db.forensic.find_one({"_id": ObjectId(evidence_id)})
        if not evidence_record:
            logger.error("❌ Evidence not found")
            return

        report_path = ForensicService.export_forensic_report(evidence_id, export_format)
        logger.info(f"✅ Forensic Report Exported: {report_path}")

    except Exception as e:
        logger.error(f"❌ Forensic report export error: {e}")

# ------------------- CLI COMMAND HANDLER -------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forensic Analysis CLI Utility")
    parser.add_argument("--analyze", help="Analyze stored forensic evidence")
    parser.add_argument("--fetch", help="Retrieve forensic evidence from database")
    parser.add_argument("--export", help="Export forensic report")
    parser.add_argument("--format", help="Format for report export (pdf, json)", default="pdf")

    args = parser.parse_args()

    if args.analyze:
        cli_analyze_stored_evidence(args.analyze)
    elif args.fetch:
        cli_fetch_forensic_evidence(args.fetch)
    elif args.export:
        cli_export_forensic_report(args.export, args.format)
    else:
        logger.error("❌ Invalid CLI Arguments")

