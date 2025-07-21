import os
import json
import logging
import joblib
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any, Tuple, Union
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from app.utils.securityUtils import sanitize_file_path

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MODEL_DIR = "/home/kali/MalDNA/backend/models"
os.makedirs(MODEL_DIR, exist_ok=True)

class MalwareClassifier:
    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type
        self.model = self._initialize_model()
        self.scaler = StandardScaler()
        self.model_path = os.path.join(MODEL_DIR, f"{model_type}_malware_model.pkl")
        self.scaler_path = os.path.join(MODEL_DIR, f"{model_type}_scaler.pkl")
        self.feature_order_path = os.path.join(MODEL_DIR, f"{model_type}_feature_order.json")

    def _initialize_model(self) -> BaseEstimator:
        if self.model_type == "random_forest":
            return RandomForestClassifier(n_estimators=100, random_state=42)
        elif self.model_type == "svm":
            return SVC(probability=True, kernel="linear", random_state=42)
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")

    def train_model(self, dataset_path: str, test_size: float = 0.2) -> Dict[str, Any]:
        try:
            sanitized_path = sanitize_file_path(dataset_path)
            if not os.path.exists(sanitized_path):
                raise FileNotFoundError("Dataset file does not exist.")

            df = pd.read_csv(sanitized_path)
            if "label" not in df.columns:
                raise ValueError("Dataset must contain a 'label' column")

            df.fillna(0, inplace=True)
            X = df.drop(columns=["label"])
            y = df["label"]

            feature_order = list(X.columns)
            with open(self.feature_order_path, "w") as f:
                json.dump(feature_order, f)

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )

            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            self.model.fit(X_train_scaled, y_train)

            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)

            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred, output_dict=True)

            logger.info(f"Model training completed with accuracy: {accuracy:.4f}")
            return {
                "status": "success",
                "accuracy": accuracy,
                "classification_report": report,
                "model_path": self.model_path,
                "scaler_path": self.scaler_path,
                "feature_order": feature_order,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Training failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def preprocess_hybrid_features(self, raw_features: Union[Dict[str, Any], np.ndarray]) -> np.ndarray:
        try:
            if not os.path.exists(self.feature_order_path):
                raise FileNotFoundError("Feature order file is missing. Please train the model first.")
            if not os.path.exists(self.scaler_path):
                raise FileNotFoundError("Scaler not found. Please train the model first.")

            with open(self.feature_order_path, "r") as f:
                feature_order = json.load(f)

            input_vector = []
            for feature in feature_order:
                value = raw_features.get(feature, 0) if isinstance(raw_features, dict) else 0
                input_vector.append(value)

            feature_array = np.array([input_vector], dtype=np.float64)
            self.scaler = joblib.load(self.scaler_path)
            scaled = self.scaler.transform(feature_array)
            return scaled

        except Exception as e:
            logger.error(f"Feature preprocessing failed: {str(e)}")
            raise e

    def predict(self, features: Union[Dict[str, Any], np.ndarray]) -> Tuple[str, Dict[str, float]]:
        try:
            if not os.path.exists(self.model_path) or not os.path.exists(self.scaler_path):
                raise FileNotFoundError("Trained model or scaler not found. Please train the model first.")

            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)

            processed_features = self.preprocess_hybrid_features(features)
            prediction = self.model.predict(processed_features)[0]

            confidence_scores = {}
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(processed_features)[0]
                confidence_scores = dict(zip(map(str, self.model.classes_), proba.tolist()))
            else:
                confidence_scores = {"confidence": "Not available"}

            predicted_label = "malicious" if prediction == 1 else "benign"
            return predicted_label, confidence_scores

        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            raise e

    def evaluate_model(self, dataset_path: str) -> Dict[str, Any]:
        try:
            df = pd.read_csv(sanitize_file_path(dataset_path))
            if "label" not in df.columns:
                raise ValueError("Evaluation dataset must contain 'label' column")

            df.fillna(0, inplace=True)
            X = df.drop(columns=["label"])
            y = df["label"]

            with open(self.feature_order_path, "r") as f:
                feature_order = json.load(f)

            X = X[feature_order]
            X_scaled = self.scaler.transform(X)
            y_pred = self.model.predict(X_scaled)

            accuracy = accuracy_score(y, y_pred)
            report = classification_report(y, y_pred, output_dict=True)
            matrix = confusion_matrix(y, y_pred).tolist()

            return {
                "status": "success",
                "accuracy": accuracy,
                "classification_report": report,
                "confusion_matrix": matrix
            }
        except Exception as e:
            logger.error(f"Evaluation failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def deploy_model(self, model_path: str, version: str = "latest") -> Dict[str, Any]:
        try:
            sanitized_path = sanitize_file_path(model_path)
            if not os.path.exists(sanitized_path):
                raise FileNotFoundError(f"Model file not found: {sanitized_path}")
            self.model = joblib.load(sanitized_path)

            return {
                "status": "success",
                "model_type": self.model_type,
                "version": version,
                "deployment_time": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Deployment failed: {str(e)}")
            return {"status": "error", "message": str(e)}

# --------------------------- CLI HANDLER --------------------------- #

def cli_train(args):
    classifier = MalwareClassifier(model_type=args.model_type)
    result = classifier.train_model(args.dataset)
    print(json.dumps(result, indent=4))

def cli_predict(args):
    classifier = MalwareClassifier(model_type=args.model_type)
    with open(args.input, "r") as f:
        features = json.load(f)
    label, confidence = classifier.predict(features)
    result = {
        "status": "success",
        "predicted_label": label,
        "confidence_scores": confidence,
        "timestamp": datetime.utcnow().isoformat()
    }
    print(json.dumps(result, indent=4))

def cli_evaluate(args):
    classifier = MalwareClassifier(model_type=args.model_type)
    result = classifier.evaluate_model(args.dataset)
    print(json.dumps(result, indent=4))

def cli_deploy(args):
    classifier = MalwareClassifier(model_type=args.model_type)
    result = classifier.deploy_model(args.model, args.version)
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Classifier CLI")
    subparsers = parser.add_subparsers(help="Available commands")

    parser_train = subparsers.add_parser("train", help="Train a model")
    parser_train.add_argument("--dataset", required=True, help="CSV file containing labeled dataset")
    parser_train.add_argument("--model_type", choices=["random_forest", "svm"], default="random_forest")
    parser_train.set_defaults(func=cli_train)

    parser_predict = subparsers.add_parser("predict", help="Classify a sample")
    parser_predict.add_argument("--input", required=True, help="Path to JSON file with feature values")
    parser_predict.add_argument("--model_type", choices=["random_forest", "svm"], default="random_forest")
    parser_predict.set_defaults(func=cli_predict)

    parser_eval = subparsers.add_parser("evaluate", help="Evaluate the trained model")
    parser_eval.add_argument("--dataset", required=True, help="CSV file for evaluation")
    parser_eval.add_argument("--model_type", choices=["random_forest", "svm"], default="random_forest")
    parser_eval.set_defaults(func=cli_evaluate)

    parser_deploy = subparsers.add_parser("deploy", help="Deploy a trained model")
    parser_deploy.add_argument("--model", required=True, help="Path to model file")
    parser_deploy.add_argument("--version", default="latest", help="Version tag for deployment")
    parser_deploy.add_argument("--model_type", choices=["random_forest", "svm"], default="random_forest")
    parser_deploy.set_defaults(func=cli_deploy)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

