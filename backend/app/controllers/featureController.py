import os
import logging
import argparse
import json
import pandas as pd
import numpy as np
from datetime import datetime
from flask import Blueprint, request, jsonify
from app.models.malwareModel import ProcessedFeatures

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Flask Blueprint
feature_bp = Blueprint("feature", __name__, url_prefix="/api/features")

# ---------------------------- API Endpoints ---------------------------- #

@feature_bp.route("/", methods=["GET"], endpoint="get_features")
def get_features():
    """Retrieve processed features with optional filtering."""
    try:
        data_source = request.args.get("data_source")
        feature_method = request.args.get("feature_method")
        model_type = request.args.get("model_type")
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")

        start_date = datetime.fromisoformat(start_date_str) if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str) if end_date_str else None

        features = ProcessedFeatures.retrieve_features(
            data_source=data_source,
            feature_extraction_method=feature_method,
            model_type=model_type,
            start_date=start_date,
            end_date=end_date
        )

        feature_list = [{
            "id": str(feature.id),
            "timestamp": feature.timestamp.isoformat(),
            "data_source": feature.data_source,
            "feature_method": feature.feature_extraction_method,
            "feature_count": feature.feature_count,
            "model_type": feature.model_type,
            "performance_metrics": feature.performance_metrics
        } for feature in features]

        return jsonify({"features": feature_list, "total_count": len(feature_list)}), 200

    except Exception as e:
        logger.error(f"Error retrieving features: {e}")
        return jsonify({"error": "Failed to retrieve features", "details": str(e)}), 500

@feature_bp.route("/<feature_id>", methods=["GET"], endpoint="get_feature_details")
def get_feature_details(feature_id):
    """Get detailed information about a specific feature set."""
    try:
        feature_doc = ProcessedFeatures.objects.get(id=feature_id)
        return jsonify({
            "id": str(feature_doc.id),
            "timestamp": feature_doc.timestamp.isoformat(),
            "data_source": feature_doc.data_source,
            "feature_method": feature_doc.feature_extraction_method,
            "feature_names": feature_doc.feature_names,
            "mean_values": feature_doc.mean_values,
            "std_values": feature_doc.std_values,
            "model_type": feature_doc.model_type,
            "performance_metrics": feature_doc.performance_metrics,
            "visualization_paths": feature_doc.visualization_paths
        }), 200

    except ProcessedFeatures.DoesNotExist:
        return jsonify({"error": "Feature set not found"}), 404
    except Exception as e:
        logger.error(f"Error retrieving feature details: {e}")
        return jsonify({"error": "Failed to retrieve feature details", "details": str(e)}), 500

@feature_bp.route("/summary", methods=["GET"], endpoint="get_feature_summary")
def get_feature_summary():
    """Get summary of all processed feature sets."""
    try:
        features = ProcessedFeatures.objects()
        summary = {
            "total_feature_sets": len(features),
            "data_sources": set(),
            "feature_methods": set(),
            "model_types": set(),
            "date_range": {"earliest": None, "latest": None}
        }

        for feature_set in features:
            summary["data_sources"].add(feature_set.data_source)
            summary["feature_methods"].add(feature_set.feature_extraction_method)
            summary["model_types"].add(feature_set.model_type)

        if features:
            summary["date_range"]["earliest"] = min(f.timestamp for f in features).isoformat()
            summary["date_range"]["latest"] = max(f.timestamp for f in features).isoformat()

        return jsonify(summary), 200

    except Exception as e:
        logger.error(f"Error generating feature summary: {e}")
        return jsonify({"error": "Failed to generate feature summary", "details": str(e)}), 500

@feature_bp.route("/upload", methods=["POST"], endpoint="upload_processed_features")
def upload_processed_features():
    """Upload processed features (admin-only logic removed)."""
    try:
        data = request.json
        required_fields = ["features", "labels", "data_source", "feature_extraction_method"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        feature_doc = ProcessedFeatures.store_features(
            features_df=pd.DataFrame(data["features"]),
            labels=np.array(data["labels"]),
            data_source=data["data_source"],
            feature_extraction_method=data["feature_extraction_method"],
            model_type=data.get("model_type"),
            performance_metrics=data.get("performance_metrics"),
            visualization_paths=data.get("visualization_paths")
        )

        return jsonify({"message": "Features uploaded successfully", "feature_id": str(feature_doc.id)}), 201

    except Exception as e:
        logger.error(f"Error uploading features: {e}")
        return jsonify({"error": "Failed to upload features", "details": str(e)}), 500

# ---------------------------- CLI FUNCTIONALITY ---------------------------- #

def cli_get_features():
    """CLI command to retrieve all features."""
    try:
        features = ProcessedFeatures.objects()
        for feature in features:
            print(f"ID: {feature.id}, Data Source: {feature.data_source}, Features: {len(feature.feature_names)}")
    except Exception as e:
        print(f"[❌] Failed to retrieve features: {e}")

def cli_get_feature_details(feature_id):
    """CLI command to get feature details."""
    try:
        feature = ProcessedFeatures.objects.get(id=feature_id)
        print(json.dumps(feature.to_mongo().to_dict(), indent=4, default=str))
    except ProcessedFeatures.DoesNotExist:
        print("[❌] Feature set not found.")
    except Exception as e:
        print(f"[❌] Error retrieving feature details: {e}")

def cli_get_feature_summary():
    """CLI command to get feature summary."""
    try:
        features = ProcessedFeatures.objects()
        print(f"Total Feature Sets: {len(features)}")
        print(f"Data Sources: {[f.data_source for f in features]}")
        print(f"Feature Extraction Methods: {[f.feature_extraction_method for f in features]}")
    except Exception as e:
        print(f"[❌] Failed to retrieve feature summary: {e}")

def cli_upload_features(json_file):
    """CLI command to upload processed features from a JSON file."""
    try:
        with open(json_file, "r") as file:
            data = json.load(file)

        required_fields = ["features", "labels", "data_source", "feature_extraction_method"]
        for field in required_fields:
            if field not in data:
                print(f"[❌] Missing required field: {field}")
                return

        feature_doc = ProcessedFeatures.store_features(
            features_df=pd.DataFrame(data["features"]),
            labels=np.array(data["labels"]),
            data_source=data["data_source"],
            feature_extraction_method=data["feature_extraction_method"],
            model_type=data.get("model_type"),
            performance_metrics=data.get("performance_metrics"),
            visualization_paths=data.get("visualization_paths")
        )

        print(f"[✔] Features uploaded successfully with ID: {feature_doc.id}")

    except Exception as e:
        print(f"[❌] Failed to upload features: {e}")

# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Feature Management CLI")
    parser.add_argument("--list", action="store_true", help="List all features")
    parser.add_argument("--details", metavar="FEATURE_ID", help="Get details of a specific feature set")
    parser.add_argument("--summary", action="store_true", help="Get feature summary")
    parser.add_argument("--upload", metavar="JSON_FILE", help="Upload processed features from a JSON file")

    args = parser.parse_args()

    if args.list:
        cli_get_features()
    elif args.details:
        cli_get_feature_details(args.details)
    elif args.summary:
        cli_get_feature_summary()
    elif args.upload:
        cli_upload_features(args.upload)
    else:
        logger.error("❌ Invalid CLI Arguments")

