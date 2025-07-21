import os
import json
import logging
import joblib
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from app.utils.securityUtils import sanitize_file_path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
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
            raise ValueError("Unsupported model type")

    def load_model(self, model_path: str) -> BaseEstimator:
        sanitized_path = sanitize_file_path(model_path)
        if not os.path.exists(sanitized_path):
            raise FileNotFoundError(f"Model file not found: {sanitized_path}")
        logger.info(f"Loading model from {sanitized_path}")
        self.model = joblib.load(sanitized_path)
        return self.model

    def train_model(self, dataset_path: str, test_size: float = 0.2) -> Dict[str, Any]:
        try:
            sanitized_path = sanitize_file_path(dataset_path)
            df = pd.read_csv(sanitized_path)

            if "label" not in df.columns:
                raise ValueError("Missing 'label' column in dataset")

            df = df.fillna(0)
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

            logger.info(f"Model trained. Accuracy: {accuracy:.4f}")
            return {"accuracy": accuracy, "classification_report": report}
        except Exception as e:
            logger.error(f"Training failed: {str(e)}")
            return {"error": str(e)}

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if not os.path.exists(self.model_path) or not os.path.exists(self.scaler_path):
                raise FileNotFoundError("Trained model or scaler not found. Please train the model first.")

            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)

            if not os.path.exists(self.feature_order_path):
                raise FileNotFoundError("Feature order file missing. Model must be retrained.")

            with open(self.feature_order_path, "r") as f:
                feature_order = json.load(f)

            input_keys = set(features.keys())
            expected_keys = set(feature_order)

            if input_keys != expected_keys:
                raise ValueError(
                    f"Feature mismatch. Expected features: {sorted(expected_keys)}, but got: {sorted(input_keys)}"
                )

            sorted_values = [features[key] for key in feature_order]
            sample_scaled = self.scaler.transform([sorted_values])
            prediction = self.model.predict(sample_scaled)[0]

            confidence_scores = {}
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(sample_scaled)[0]
                confidence_scores = dict(zip(map(str, self.model.classes_), proba.tolist()))
            else:
                confidence_scores = "Confidence scores not available for this model."

            return {
                "predicted_label": "malicious" if prediction == 1 else "benign",
                "confidence_scores": confidence_scores,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def evaluate_model(self, dataset_path: str) -> Dict[str, Any]:
        try:
            df = pd.read_csv(sanitize_file_path(dataset_path))

            if "label" not in df.columns:
                raise ValueError("Missing 'label' column in dataset")

            df = df.fillna(0)
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
                "accuracy": accuracy,
                "classification_report": report,
                "confusion_matrix": matrix
            }
        except Exception as e:
            logger.error(f"Evaluation failed: {str(e)}")
            return {"error": str(e)}

    def deploy_model(self, model_path: str, version: str = "latest") -> Dict[str, Any]:
        try:
            sanitized_path = sanitize_file_path(model_path)
            if not os.path.exists(sanitized_path):
                raise FileNotFoundError(f"Model file not found: {sanitized_path}")
            self.load_model(sanitized_path)

            return {
                "status": "success",
                "model_type": self.model_type,
                "version": version,
                "deployment_time": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Deployment failed: {str(e)}")
            return {"error": str(e)}

# --------------------------- CLI HANDLER --------------------------- #

def cli_train(args):
    classifier = MalwareClassifier(model_type=args.model_type)
    result = classifier.train_model(args.dataset)
    print(json.dumps(result, indent=4))

def cli_predict(args):
    classifier = MalwareClassifier(model_type=args.model_type)
    with open(args.input, "r") as f:
        features = json.load(f)
    result = classifier.predict(features)
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
    parser_deploy.add_argument("--model", required=True, help="Path to trained model (.pkl)")
    parser_deploy.add_argument("--version", default="latest", help="Model version")
    parser_deploy.add_argument("--model_type", choices=["random_forest", "svm"], default="random_forest")
    parser_deploy.set_defaults(func=cli_deploy)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

