import os
import logging
import argparse
import datetime
from functools import wraps
from flask import request, jsonify, Blueprint
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv

# Models & Services
from app.models.dnaModel import DNAModel
from app.models.malwareModel import MalwareMetadata, MalwareModel
from app.models.lineageModel import LineageModel, MutationRecord
from app.services.lineageService import LineageAnalysisService
from app.services.dnaService import DNAAnalysisService
from app.services.blockchainService import BlockchainService
from ml.models.gaTracker import GeneticAlgorithmTracker

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# MongoDB setup
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
client = MongoClient(MONGO_URI)
db = client["MalDNA"]
logger.info("✅ Connected to MongoDB")

# Blueprint setup
lineage_bp = Blueprint("lineage", __name__, url_prefix="/api/lineage")
CORS(lineage_bp, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# ------------------- DNA VALIDATION DECORATOR -------------------

def validate_dna_id(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        dna_id = request.args.get("dna_id")
        if not dna_id:
            return jsonify({"error": "DNA ID is required"}), 400
        dna_record = db.dna.find_one({"_id": dna_id})
        if not dna_record:
            return jsonify({"error": "DNA record not found"}), 404
        return func(dna_record, *args, **kwargs)
    return wrapper

# ------------------- API ENDPOINTS -------------------

@lineage_bp.route("/list_ids", methods=["GET"])
def list_all_ids():
    try:
        lineage_ids = [str(r.sample_id) for r in LineageModel.objects.only('sample_id')]
        dna_ids = [str(r.sample_id) for r in DNAModel.objects.only('sample_id')]
        return jsonify({
            "message": "Available sample_ids retrieved",
            "all_ids": {
                "lineage_ids": lineage_ids,
                "dna_ids": dna_ids
            }
        }), 200
    except Exception as e:
        logger.error(f"❌ Error fetching sample_ids: {e}")
        return jsonify({"error": str(e)}), 500

@lineage_bp.route("/reconstruct/<sample_id>", methods=["POST"], endpoint="reconstruct_malware_lineage")
def reconstruct_malware_lineage(sample_id):
    try:
        # Log the lineage reconstruction attempt
        logger.info(f"🔍 Reconstructing lineage for sample_id: {sample_id}")

        # Fetch the Lineage record based on the sample_id
        lineage_record = LineageModel.objects(sample_id=str(sample_id)).first()

        if not lineage_record:
            # Fetch the corresponding MalwareMetadata record
            metadata = MalwareMetadata.objects(sample_id=str(sample_id)).first()  # Ensure sample_id is cast to string
            if not metadata:
                logger.warning(f"⚠️ MalwareMetadata with sample_id={sample_id} not found")  # Log the warning
                return jsonify({"error": "Sample metadata not found"}), 404

            # If the dna_referenceid is missing, generate it and save it
            if not metadata.dna_referenceid:
                referenceid = DNAAnalysisService.generate_dna_referenceid(sample_id)
                metadata.dna_referenceid = referenceid
                metadata.save()
                logger.debug(f"Generated DNA Reference ID: {metadata.dna_referenceid}")

            # Create a new Lineage record if none exists
            lineage_record = LineageModel(
                sample_id=sample_id,
                dna_referenceid=metadata.dna_referenceid,
                dna_fingerprint=metadata.dna_fingerprint,
                timestamp=datetime.datetime.utcnow(),
                mutations=[],
                verified=False
            ).save()

        # Current fingerprint for comparison
        current_fingerprint = lineage_record.dna_fingerprint
        all_dna_records = DNAAnalysisService.fetch_all_dna()

        # Initialize the GeneticAlgorithmTracker
        ga_tracker = GeneticAlgorithmTracker()

        mutations = []
        for record in all_dna_records:
            if record.get("filename") and record.get("dna_fingerprint") and record.get("malware_id") != sample_id:
                score = DNAAnalysisService.compare_two_dna(current_fingerprint, record["dna_fingerprint"])
                logger.debug(f"Comparing fingerprints: {current_fingerprint} with {record['dna_fingerprint']}")
                logger.debug(f"Similarity score: {score}")

                if score < 0.85:
                    # Track mutations using the GeneticAlgorithmTracker
                    sample_mutations = ga_tracker.track_mutations(record["dna_fingerprint"])

                    mutations.append(
                        MutationRecord(
                            ancestor_id=record["malware_id"],
                            ancestor_referenceid=record["dna_fingerprint"],
                            similarity_score=round(score, 4),
                            mutation_type="Genetic Divergence",
                            mutation_date=datetime.datetime.utcnow(),
                            mutations=sample_mutations  # Store the tracked mutations
                        )
                    )

        # If mutations exist, add them to the lineage record
        if mutations:
            lineage_record.mutations.extend(mutations)
            lineage_record.verified = True
            lineage_record.save()

        # Construct the lineage tree
        lineage_tree = {
            "root": "common_ancestor",  # Placeholder for actual ancestor logic
            "branches": [
                {
                    "sample_id": s.sample_id,
                    "family_name": s.family_name,
                    "dna": s.dna_sequence,
                    "mutations": len(s.mutations),
                    "mutation_rate": len(s.mutations) / len(s.dna_sequence) if s.dna_sequence else 0,
                    "fingerprint": s.dna_fingerprint
                } for s in [lineage_record]  # Only returning the current sample for simplicity
            ]
        }

        # Return the reconstructed lineage details in the response
        logger.info(f"✅ Reconstructed lineage for sample_id {sample_id}.")
        return jsonify({
            "lineage_data": lineage_tree,
            "message": "Lineage reconstruction completed"
        }), 200

    except Exception as e:
        logger.error(f"❌ Error reconstructing lineage: {e}")
        return jsonify({"error": "Failed to reconstruct lineage"}), 500


@lineage_bp.route("/ai_predict", methods=["POST"])
@validate_dna_id
def predict_lineage_with_ai(dna_record):
    try:
        prediction = LineageAnalysisService.predict_lineage_with_ai(dna_record["dna_fingerprint"])
        return jsonify({"message": "AI-powered prediction completed", "predicted_lineage": prediction}), 200
    except Exception as e:
        logger.error(f"❌ AI lineage prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@lineage_bp.route("/blockchain_verify", methods=["GET"])
def verify_lineage_on_blockchain():
    try:
        lineage_id = request.args.get("lineage_id")
        if not lineage_id:
            return jsonify({"error": "Lineage ID is required"}), 400
        result = LineageAnalysisService.verify_lineage_on_blockchain(lineage_id)
        return jsonify({"message": "Blockchain verification completed", "verification_result": result}), 200
    except Exception as e:
        logger.error(f"❌ Blockchain lineage verification error: {e}")
        return jsonify({"error": str(e)}), 500

@lineage_bp.route("/history/<sample_id>", methods=["GET"])
def get_mutation_history(sample_id):
    try:
        history = LineageAnalysisService.get_mutation_history(sample_id)
        return jsonify({"message": "Mutation history retrieved", "history": history or []}), 200
    except Exception as e:
        logger.error(f"❌ Error retrieving mutation history: {e}")
        return jsonify({"error": str(e)}), 500

@lineage_bp.route("/predict", methods=["POST"])
def predict_future_mutations():
    try:
        data = request.get_json()
        sample_id = data.get("sample_id")
        prediction = LineageAnalysisService.predict_future_mutations(sample_id)
        return jsonify({"message": "Future mutation prediction completed", "prediction": prediction or []}), 200
    except Exception as e:
        logger.error(f"❌ Future mutation prediction error: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------- CLI COMMANDS -------------------

def cli_list_all_ids():
    try:
        lineage_ids = [str(r.sample_id) for r in LineageModel.objects.only("sample_id")]
        dna_ids = [str(r.sample_id) for r in DNAModel.objects.only("sample_id")]
        print("Lineage IDs:", lineage_ids)
        print("DNA IDs:", dna_ids)
    except Exception as e:
        print("Error listing IDs:", e)

def cli_reconstruct_lineage(sample_id):
    try:
        result = LineageAnalysisService.reconstruct_lineage(sample_id)
        print("Reconstruction Result:", result)
    except Exception as e:
        print("Error reconstructing lineage:", e)

def cli_ai_lineage_prediction(dna_id):
    try:
        dna_record = db.dna.find_one({"_id": dna_id})
        if not dna_record:
            print(f"DNA ID {dna_id} not found.")
            return
        result = LineageAnalysisService.predict_lineage_with_ai(dna_record["dna_fingerprint"])
        print("AI Prediction:", result)
    except Exception as e:
        print("Error in AI prediction:", e)

def cli_verify_lineage_on_blockchain(lineage_id):
    try:
        result = LineageAnalysisService.verify_lineage_on_blockchain(lineage_id)
        print("Blockchain Verification Result:", result)
    except Exception as e:
        print("Error verifying blockchain lineage:", e)

# ------------------- CLI ENTRY POINT -------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Lineage CLI Utility")
    parser.add_argument("--list-ids", action="store_true", help="List all available sample IDs")
    parser.add_argument("--reconstruct", help="Reconstruct malware lineage for a sample")
    parser.add_argument("--predict-ai", help="Predict malware lineage using AI (pass dna_id)")
    parser.add_argument("--verify-blockchain", help="Verify lineage on blockchain (pass lineage_id)")

    args = parser.parse_args()

    if args.list_ids:
        cli_list_all_ids()
    elif args.reconstruct:
        cli_reconstruct_lineage(args.reconstruct)
    elif args.predict_ai:
        cli_ai_lineage_prediction(args.predict_ai)
    elif args.verify_blockchain:
        cli_verify_lineage_on_blockchain(args.verify_blockchain)
    else:
        print("⚠️ Please provide a valid command. Use --help to see options.")

