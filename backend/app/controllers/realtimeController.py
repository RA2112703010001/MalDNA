import os
import logging
import argparse
import schedule
import time
from functools import wraps
from flask import request, jsonify, Blueprint
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS

# Import services
from app.services.realtimeService import RealtimeService
from app.services.blockchainService import BlockchainService

# Import models
from app.models.behaviorModel import BehaviorModel
from app.models.threatModel import ThreatEvent

# Configuration and logging
from dotenv import load_dotenv
from pymongo import MongoClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
client = MongoClient(MONGO_URI)
db = client["MalDNA"]
logger.info("✅ Successfully connected to MongoDB")

realtime_bp = Blueprint("realtime", __name__, url_prefix="/api/realtime")
CORS(realtime_bp, supports_credentials=True, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/home/kali/MalDNA/dataset/")
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB limit
ALLOWED_EXTENSIONS = {"exe", "dll", "bin", "sys", "bat", "ps1"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------- VALIDATIONS -------------------

def allowed_file(filename):
    """Check if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_upload(func):
    """Decorator to validate file uploads."""
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

@realtime_bp.route("/detect", methods=["POST"], endpoint="real_time_malware_detection")
@validate_file_upload
def real_time_malware_detection():
    """Perform real-time malware detection using AI-driven DNA signatures."""
    try:
        file = request.files["file"]
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        detection_result = RealtimeService.detect_malware_dna(file_path)
        network_analysis = RealtimeService.analyze_network_traffic(file_path)
        memory_scan = RealtimeService.scan_memory_for_threats(file_path)
        ransomware_check = RealtimeService.detect_ransomware_activity(file_path)

        threat_event = ThreatEvent(
            event_type="malware_execution",
            severity="high" if detection_result["malicious"] else "low",
            source_info={"filename": filename, "file_path": file_path},
            risk_score=detection_result.get("risk_score", 0)
        )
        threat_event.save()

        blockchain_tx_id = BlockchainService.store_forensic_evidence_on_blockchain(detection_result)

        logger.info(f"✅ Real-time malware detection completed for {filename}")
        return jsonify({
            "message": "Real-time malware detection completed",
            "detection_result": detection_result,
            "network_analysis": network_analysis,
            "memory_scan": memory_scan,
            "ransomware_check": ransomware_check,
            "blockchain_tx_id": blockchain_tx_id
        }), 200

    except Exception as e:
        logger.error(f"❌ Real-time malware detection error: {e}")
        return jsonify({"error": str(e)}), 500

@realtime_bp.route("/status", methods=["GET"], endpoint="get_realtime_detection_status")
def get_realtime_detection_status():
    """Retrieve real-time detection statistics."""
    try:
        stats = RealtimeService.get_detection_statistics()
        return jsonify({"message": "Real-time detection statistics retrieved", "statistics": stats}), 200
    except Exception as e:
        logger.error(f"❌ Error retrieving detection statistics: {e}")
        return jsonify({"error": str(e)}), 500

@realtime_bp.route("/predict", methods=["POST"], endpoint="ai_threat_prediction")
def ai_threat_prediction():
    """Predict future threats using AI-based anomaly detection."""
    try:
        behavior_id = request.args.get("behavior_id")
        if not behavior_id:
            return jsonify({"error": "Behavior ID is required"}), 400

        behavior_record = db.behavior.find_one({"_id": behavior_id})
        if not behavior_record:
            return jsonify({"error": "Behavior record not found"}), 404

        threat_prediction = RealtimeService.predict_threats_with_ai(behavior_record)

        logger.info(f"✅ AI-powered threat prediction completed for behavior ID: {behavior_id}")
        return jsonify({
            "message": "AI-powered threat prediction completed",
            "threat_prediction": threat_prediction
        }), 200

    except Exception as e:
        logger.error(f"❌ AI threat prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@realtime_bp.route("/incident-response", methods=["POST"], endpoint="automated_incident_response")
def automated_incident_response():
    """Trigger automated incident response measures."""
    try:
        response_actions = RealtimeService.trigger_incident_response()
        logger.info("✅ Automated incident response successfully triggered.")
        return jsonify({
            "message": "Automated incident response triggered.",
            "actions": response_actions
        }), 200
    except Exception as e:
        logger.error(f"❌ Incident response error: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------- CLI FUNCTIONS -------------------

def cli_real_time_scan():
    """CLI command to scan malware samples from the database."""
    try:
        malware_samples = db.malware.find()
        for sample in malware_samples:
            detection_result = RealtimeService.detect_malware_dna(sample["file_path"])
            logger.info(f"✅ Scanned {sample['filename']}: {detection_result}")

    except Exception as e:
        logger.error(f"❌ Real-time scan error: {e}")

def cli_ai_threat_detection():
    """CLI command for AI-based real-time threat detection."""
    try:
        behavior_records = db.behavior.find()
        for behavior in behavior_records:
            threat_prediction = RealtimeService.predict_threats_with_ai(behavior)
            logger.info(f"✅ Predicted threats for behavior {behavior['_id']}: {threat_prediction}")

    except Exception as e:
        logger.error(f"❌ AI threat detection error: {e}")

def cli_schedule_periodic_analysis(interval=10):
    """CLI command to schedule periodic real-time analysis."""
    def periodic_scan():
        logger.info("🔄 Running scheduled real-time malware scan...")
        cli_real_time_scan()

    schedule.every(interval).minutes.do(periodic_scan)
    logger.info(f"✅ Scheduled real-time scanning every {interval} minutes.")
    while True:
        schedule.run_pending()
        time.sleep(60)

# ------------------- CLI COMMAND HANDLER -------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-Time Threat Detection CLI Utility")
    parser.add_argument("--scan", help="Run real-time malware scanning", action="store_true")
    parser.add_argument("--ai-detect", help="Run AI-based threat detection", action="store_true")
    parser.add_argument("--schedule", help="Schedule periodic scanning (minutes)", type=int)

    args = parser.parse_args()

    if args.scan:
        cli_real_time_scan()
    elif args.ai_detect:
        cli_ai_threat_detection()
    elif args.schedule:
        cli_schedule_periodic_analysis(args.schedule)
    else:
        logger.error("❌ Invalid CLI Arguments")

