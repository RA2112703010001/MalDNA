import os
import logging
import argparse
from flask import Blueprint, request, jsonify
from dotenv import load_dotenv
from pymongo import MongoClient

# Dataset Service Functions
from app.services.dataset_service import (
    list_datasets,
    add_sample_to_dataset,
    remove_sample_from_dataset,
    label_sample,
    export_dataset_by_id,
    fetch_samples_from_collection,
    version_dataset,
    get_label_history
)

# Load environment
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
client = MongoClient(MONGO_URI)
db = client["MalDNA"]

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Blueprint
dataset_bp = Blueprint("dataset_controller", __name__, url_prefix="/api/dataset")

# ------------------- ROUTES -------------------

@dataset_bp.route('/list', methods=['GET'])
def get_datasets():
    try:
        datasets = list_datasets()
        logger.info("📂 Listed all datasets")
        return jsonify({'datasets': datasets}), 200
    except Exception as e:
        logger.error(f"❌ Error listing datasets: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/add_sample', methods=['POST'])
def add_sample():
    try:
        data = request.get_json()
        dataset_id = data.get('dataset_id')
        sample_id = data.get('sample_id')

        if not dataset_id or not sample_id:
            return jsonify({'error': 'Dataset ID and Sample ID are required'}), 400

        result = add_sample_to_dataset(dataset_id, sample_id)
        logger.info(f"➕ Sample {sample_id} added to Dataset {dataset_id}")
        return jsonify({'message': result}), 200
    except Exception as e:
        logger.error(f"❌ Failed to add sample: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/remove_sample', methods=['POST'])
def remove_sample():
    try:
        data = request.get_json()
        dataset_id = data.get('dataset_id')
        sample_id = data.get('sample_id')

        if not dataset_id or not sample_id:
            return jsonify({'error': 'Dataset ID and Sample ID are required'}), 400

        result = remove_sample_from_dataset(dataset_id, sample_id)
        logger.info(f"➖ Sample {sample_id} removed from Dataset {dataset_id}")
        return jsonify({'message': result}), 200
    except Exception as e:
        logger.error(f"❌ Failed to remove sample: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/label_sample', methods=['POST'])
def label_sample_endpoint():
    try:
        data = request.get_json()
        sample_id = data.get('sample_id')
        label = data.get('label')

        if not sample_id or not label:
            return jsonify({'error': 'Sample ID and Label are required'}), 400

        result = label_sample(sample_id, label)
        logger.info(f"🏷️ Sample {sample_id} labeled as '{label}'")
        return jsonify({'message': result}), 200
    except Exception as e:
        logger.error(f"❌ Labeling failed: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/label_history/<sample_id>', methods=['GET'])
def get_sample_label_history(sample_id):
    try:
        history = get_label_history(sample_id)
        logger.info(f"📜 Label history fetched for Sample {sample_id}")
        return jsonify({'history': history}), 200
    except Exception as e:
        logger.error(f"❌ Failed to retrieve label history: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/export/<dataset_id>', methods=['GET'])
def export_dataset(dataset_id):
    try:
        exported_data = export_dataset_by_id(dataset_id)
        logger.info(f"📤 Exported Dataset {dataset_id}")
        return jsonify(exported_data), 200
    except Exception as e:
        logger.error(f"❌ Export failed: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/samples/from_collection', methods=['POST'])
def fetch_samples():
    try:
        data = request.get_json()
        collection_name = data.get('collection_name')

        if not collection_name:
            return jsonify({'error': 'Collection name is required'}), 400

        samples = fetch_samples_from_collection(collection_name)
        logger.info(f"📥 Fetched samples from collection: {collection_name}")
        return jsonify({'samples': samples}), 200
    except Exception as e:
        logger.error(f"❌ Failed to fetch samples: {e}")
        return jsonify({'error': str(e)}), 500


@dataset_bp.route('/version/<dataset_id>', methods=['POST'])
def versionize_dataset(dataset_id):
    try:
        version_info = version_dataset(dataset_id)
        logger.info(f"🧬 Versioning complete for Dataset {dataset_id}")
        return jsonify({'version_info': version_info}), 200
    except Exception as e:
        logger.error(f"❌ Versioning failed: {e}")
        return jsonify({'error': str(e)}), 500

# ------------------- CLI SUPPORT -------------------

def cli_export_dataset(dataset_id):
    try:
        data = export_dataset_by_id(dataset_id)
        logger.info(f"📦 Exported dataset: {data}")
    except Exception as e:
        logger.error(f"❌ Export error: {e}")

def cli_version_dataset(dataset_id):
    try:
        version = version_dataset(dataset_id)
        logger.info(f"📌 Version info: {version}")
    except Exception as e:
        logger.error(f"❌ Versioning error: {e}")

def cli_list_datasets():
    try:
        datasets = list_datasets()
        logger.info(f"📂 Datasets:\n{datasets}")
    except Exception as e:
        logger.error(f"❌ Listing error: {e}")

# ------------------- CLI ENTRY POINT -------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dataset CLI Utility")
    parser.add_argument("--list", action="store_true", help="List all datasets")
    parser.add_argument("--export", help="Export dataset by ID")
    parser.add_argument("--version", help="Create version of dataset by ID")

    args = parser.parse_args()

    if args.list:
        cli_list_datasets()
    elif args.export:
        cli_export_dataset(args.export)
    elif args.version:
        cli_version_dataset(args.version)
    else:
        logger.warning("⚠️ Invalid CLI arguments. Use --help for available options.")

