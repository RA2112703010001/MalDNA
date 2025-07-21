import os
import logging
import uuid
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS, cross_origin
from mongoengine import connect
import numpy as np
import matplotlib.pyplot as plt
# Services
from app.services.dnaService import DNAAnalysisService

# Models
from app.models.dnaModel import DNAModel
from app.models.malwareModel import MalwareMetadata

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# MongoDB Connection
DB_NAME = os.getenv("DB_NAME", "maldna_db")
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
connect(DB_NAME, host=MONGODB_URI)

# Config
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/home/kali/MalDNA/dataset/")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

dna_bp = Blueprint("dna", __name__, url_prefix="/api/dna")

# WARNING: CORS is set to allow all origins. This is insecure for production.
CORS(dna_bp, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# ==========================
# ✅ Utility Functions
# ==========================

def generate_dna_fingerprint(file_path):
    """
    Generates a DNA fingerprint from the given file.
    Extracts opcode sequence, encodes it into a feature vector, and generates a DNA fingerprint.
    """
    opcode_sequence = DNAAnalysisService.extract_opcode_sequence(file_path)
    feature_vector = DNAAnalysisService.encode_feature_vector(opcode_sequence)
    return DNAAnalysisService.generate_dna_fingerprint(feature_vector)

# ==========================
# ✅ Routes
# ==========================
@dna_bp.route("/dna/generate", methods=["POST"])
@cross_origin()
def generate_dna():
    """
    Endpoint to generate DNA fingerprint from a provided file or sample_id.
    Saves the fingerprint in the database and returns the result.
    """
    try:
        file = request.files.get('file')
        data = request.form  # Using request.form to access multipart data (e.g., sample_id)
        sample_id = data.get('sample_id')

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
        elif sample_id:
            sample = MalwareMetadata.objects(sample_id=sample_id).first()
            if not sample:
                return jsonify({"error": "Sample not found"}), 404
            file_path = sample.file_path
            filename = sample.filename
        else:
            return jsonify({"error": "No file or sample_id provided"}), 400

        # Generate DNA fingerprint from the file
        dna_fingerprint = generate_dna_fingerprint(file_path)
        source_sample_id = sample_id or str(uuid.uuid4())  # Ensure this is passed as `source_sample_id`

        # Save DNA entry to the database
        dna_entry = DNAModel(sample_id=sample_id, source_sample_id=source_sample_id, filename=filename, dna_fingerprint=dna_fingerprint)
        dna_entry.save()

        return jsonify({
            "message": "DNA fingerprint generated successfully",
            "dna_fingerprint": dna_fingerprint
        }), 200

    except Exception as e:
        logger.error(f"DNA generation error: {e}")
        return jsonify({"error": str(e)}), 500

@dna_bp.route("/dna/similarity/<sample_id_1>/<sample_id_2>", methods=["GET"])
def compare_dna_pair(sample_id_1, sample_id_2):
    """
    Endpoint to compare two DNA fingerprints and return similarity score.
    """
    try:
        sample1 = DNAModel.objects(sample_id=sample_id_1).first()
        sample2 = DNAModel.objects(sample_id=sample_id_2).first()
        if not sample1 or not sample2:
            return jsonify({"error": "One or both samples not found"}), 404

        score = DNAAnalysisService.compare_two_dna(sample1.dna_fingerprint, sample2.dna_fingerprint)

        return jsonify({
            "message": "DNA similarity comparison completed",
            "sample_id_1": sample_id_1,
            "sample_id_2": sample_id_2,
            "similarity_score": score
        }), 200

    except Exception as e:
        logger.error(f"DNA similarity error: {e}")
        return jsonify({"error": str(e)}), 500
@dna_bp.route("/dna/mutations/<sample_id>", methods=["GET"])
def detect_mutations(sample_id):
    """
    Endpoint to detect mutations in a given DNA fingerprint.
    """
    try:
        sample = DNAModel.objects(sample_id=sample_id).first()
        if not sample:
            return jsonify({"error": "Sample not found"}), 404

        # Fetch another sample to compare with (e.g., previous sample or reference)
        reference_sample = DNAModel.objects(sample_id=sample.sample_id).first()  # This assumes malware_id links to the same malware
        if not reference_sample:
            return jsonify({"error": "Reference sample not found"}), 404

        # Detect mutations by comparing the DNA fingerprints
        mutations = DNAAnalysisService.detect_mutations(sample.dna_fingerprint, reference_sample.dna_fingerprint)

        return jsonify({
            "message": "Mutation detection completed",
            "mutations": mutations
        }), 200

    except Exception as e:
        logger.error(f"Mutation detection error: {e}")
        return jsonify({"error": str(e)}), 500

@dna_bp.route("/dna/family/<family_name>", methods=["GET"])
def get_family_lineage(family_name):
    """
    Endpoint to retrieve DNA family lineage by family name.
    """
    try:
        results = DNAAnalysisService.get_family_by_name(family_name)
        return jsonify({
            "message": "Family retrieval successful",
            "family_name": family_name,
            "members": results
        }), 200
    except Exception as e:
        logger.error(f"DNA family retrieval error: {e}")
        return jsonify({"error": str(e)}), 500

@dna_bp.route("/dna/similarity/<sample_filename>", methods=["GET"])
def visualize_dna_sequence(sample_filename):
    """
    Endpoint to retrieve DNA similarity graph data for visualization.
    """
    try:
        graph_data = DNAAnalysisService.visualize_dna_sequence(sample_filename)
        return jsonify({
            "message": "Graph visualization data retrieved",
            "graph_data": graph_data
        }), 200
    except Exception as e:
        logger.error(f"Graph generation error: {e}")
        return jsonify({"error": str(e)}), 500


@dna_bp.route("/dna/batch_compare", methods=["POST"])
def batch_compare():
    """
    Endpoint to perform batch DNA comparisons.
    """
    try:
        sample_ids = request.json.get('sample_ids', [])
        if not sample_ids:
            return jsonify({"error": "No sample IDs provided"}), 400

        results = {}
        for sample_id in sample_ids:
            sample = DNAModel.objects(sample_id=sample_id).first()
            if sample:
                results[sample_id] = DNAAnalysisService.compare_dna(sample.dna_fingerprint)
            else:
                results[sample_id] = "Sample Not Found"

        return jsonify({
            "message": "Batch comparison completed",
            "results": results
        }), 200

    except Exception as e:
        logger.error(f"Batch DNA comparison error: {e}")
        return jsonify({"error": str(e)}), 500

# ==========================
# ✅ CLI Utilities
# ==========================

def cli_generate_dna(sample_id):
    """
    CLI utility to generate DNA fingerprint from a sample ID.
    """
    try:
        sample = MalwareMetadata.objects(sample_id=sample_id).first()
        if not sample:
            logger.error("❌ Sample not found")
            return
        dna_fingerprint = generate_dna_fingerprint(sample.file_path)
        sample_id = sample.sample_id or str(uuid.uuid4())
        DNAModel(sample_id=sample_id, filename=sample.filename, dna_fingerprint=dna_fingerprint).save()
        logger.info(f"✅ DNA Fingerprint: {dna_fingerprint}")
    except Exception as e:
        logger.error(f"❌ CLI DNA generation failed: {e}")

