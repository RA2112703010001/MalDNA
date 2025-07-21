import os
import json
import argparse
import hashlib
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from collections import Counter
from datetime import datetime

# Blockchain + AI Modules
from app.blockchainUtils import BlockchainHandler  # Blockchain storage module
from ai.anomalyDetection import AnomalyDetector  # AI-driven anomaly detection

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("feature_extraction.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Data Directory
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

class FeatureExtractor:
    def __init__(self, pca_components: int = 5):
        """
        Feature extraction with AI anomaly detection and blockchain verification.
        Args:
            pca_components (int): Number of PCA components for dimensionality reduction.
        """
        self.static_features = []
        self.dynamic_features = []
        self.blockchain = BlockchainHandler()
        self.anomaly_detector = AnomalyDetector()
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=pca_components)

    def extract_static_features(self, binary_path: str) -> Dict:
        """Extract static features from a malware binary."""
        try:
            static_data = {
                "file_size": os.path.getsize(binary_path),
                "file_extension": os.path.splitext(binary_path)[1],
                "entropy": self._calculate_entropy(binary_path),
            }
            self.static_features.append(static_data)
            logger.info(f"Extracted static features from {binary_path}")
            return static_data
        except Exception as e:
            logger.error(f"Static feature extraction failed: {e}")
            return {}

    def extract_dynamic_features(self, sandbox_log: str) -> Dict:
        """Extract dynamic features from sandbox logs."""
        try:
            with open(sandbox_log, "r") as f:
                log_data = json.load(f)

            dynamic_data = {
                "api_calls": len(log_data.get("api_calls", [])),
                "network_connections": len(log_data.get("network_traffic", {})),
            }
            self.dynamic_features.append(dynamic_data)
            logger.info(f"Extracted dynamic features from {sandbox_log}")
            return dynamic_data
        except Exception as e:
            logger.error(f"Dynamic feature extraction failed: {e}")
            return {}

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of a file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                byte_counts = Counter(data)
                total_bytes = len(data)
                return -sum(count / total_bytes * np.log2(count / total_bytes) for count in byte_counts.values())
        except Exception as e:
            logger.error(f"Entropy calculation failed: {e}")
            return 0.0

    def transform_features(self) -> pd.DataFrame:
        """Transform extracted features and detect AI-based anomalies."""
        try:
            combined_features = [dict(**static, **dynamic) for static, dynamic in zip(self.static_features, self.dynamic_features)]
            df = pd.DataFrame(combined_features)

            self.handle_missing_data(df)
            scaled_features = self.scaler.fit_transform(df)
            reduced_features = self.pca.fit_transform(scaled_features)

            # AI-Driven Anomaly Detection
            df["anomaly_score"] = self.anomaly_detector.detect_anomalies(reduced_features)

            return df
        except Exception as e:
            logger.error(f"Feature transformation failed: {e}")
            return pd.DataFrame()

    def handle_missing_data(self, df: pd.DataFrame):
        """Handle missing feature data."""
        df.fillna(df.mean(), inplace=True)

    def save_features(self, features: pd.DataFrame, output_file: str = "processed_data.json") -> str:
        """Save extracted features, store hash on blockchain, and validate with AI."""
        try:
            output_path = os.path.join(DATA_DIR, output_file)
            features.to_json(output_path, orient="records")

            # Generate hash and store on blockchain
            feature_hash = self._calculate_file_hash(output_path)
            blockchain_tx = self.blockchain.store_feature_hash(feature_hash)

            # AI-Driven Integrity Verification
            anomaly_detected = self.anomaly_detector.verify_anomaly_score(features)
            verification_status = "Tampered" if anomaly_detected else "Valid"

            logger.info(f"Features saved to {output_path} (Blockchain TX: {blockchain_tx}, AI Integrity: {verification_status})")
            return output_path
        except Exception as e:
            logger.error(f"Saving features failed: {e}")
            return ""

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a feature file."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Hashing failed: {e}")
            return ""

    def verify_feature_integrity(self, file_path: str) -> bool:
        """Verify feature file integrity against blockchain records and AI analysis."""
        file_hash = self._calculate_file_hash(file_path)
        blockchain_status = self.blockchain.verify_feature_hash(file_hash)
        ai_verification = self.anomaly_detector.verify_anomaly_score(pd.read_json(file_path))

        final_status = blockchain_status and not ai_verification
        logger.info(f"Blockchain Verification: {'Valid' if blockchain_status else 'Tampered'}, AI Detection: {'Tampered' if ai_verification else 'Valid'}")
        return final_status

def parse_arguments():
    """Parse CLI arguments for feature extraction and AI-blockchain verification."""
    parser = argparse.ArgumentParser(description="Feature Extraction CLI with AI + Blockchain Verification.")
    parser.add_argument("--static", type=str, help="Path to binary file for static analysis")
    parser.add_argument("--dynamic", type=str, help="Path to sandbox log for dynamic analysis")
    parser.add_argument("--transform", action="store_true", help="Transform extracted features")
    parser.add_argument("--save", type=str, help="Save extracted features to a file")
    parser.add_argument("--verify", type=str, help="Verify feature file integrity using AI + blockchain")
    return parser.parse_args()

def main():
    """Main CLI execution function."""
    args = parse_arguments()
    extractor = FeatureExtractor()

    if args.static:
        extractor.extract_static_features(args.static)
    if args.dynamic:
        extractor.extract_dynamic_features(args.dynamic)
    if args.transform:
        feature_df = extractor.transform_features()
        logger.info(f"Transformed Features:\n{feature_df.head()}")
    if args.save:
        extractor.save_features(feature_df, args.save)
    if args.verify:
        is_valid = extractor.verify_feature_integrity(args.verify)
        logger.info(f"Final Integrity Check: {'Valid' if is_valid else 'Tampered'}")

if __name__ == "__main__":
    main()

