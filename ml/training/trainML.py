import os
import json
import logging
import argparse
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Constants
LOGS_DIR = "./logs"
MODELS_DIR = "./models"
FEATURE_ORDER_PATH = "/home/kali/MalDNA/backend/models/random_forest_feature_order.json"

# Create required directories
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(FEATURE_ORDER_PATH), exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "trainML.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ml.training.trainML")


class MLTrainer:
    """
    CLI-Based Machine Learning Trainer for Malware Classification
    """

    def __init__(self, dataset: str, model_type: str = "random_forest", test_size: float = 0.2):
        self.dataset = dataset
        self.model_type = model_type
        self.test_size = test_size

        self.models = {
            "random_forest": RandomForestClassifier(n_estimators=100, random_state=42),
        }

        if model_type not in self.models:
            raise ValueError(f"Unsupported model type: {model_type}")

        self.model = self.models[model_type]
        self.scaler = StandardScaler()
        self.timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    def detect_label_column(self, df: pd.DataFrame) -> str:
        non_numeric = df.select_dtypes(exclude=["number"]).columns.tolist()
        if non_numeric:
            candidate = sorted(non_numeric, key=lambda col: df[col].nunique())[0]
            logger.info(f"🧠 Detected label column (non-numeric): {candidate}")
            return candidate
        fallback = df.columns[-1]
        logger.warning(f"⚠ Fallback: Detected label column (numeric): {fallback}")
        return fallback

    def load_dataset(self):
        try:
            logger.info(f"📂 Loading dataset from: {self.dataset}")
            df = pd.read_csv(self.dataset)

            label_col = self.detect_label_column(df)
            y = df[label_col]

            valid_classes = y.value_counts()
            valid_classes = valid_classes[valid_classes > 1].index
            df = df[df[label_col].isin(valid_classes)]
            y = df[label_col]

            logger.info(f"✅ Filtered dataset size after removing rare labels: {len(df)}")

            X = df.drop(columns=[label_col])
            X = X.select_dtypes(include=["number"])

            # Save feature order for inference consistency
            feature_order = X.columns.tolist()
            with open(FEATURE_ORDER_PATH, "w") as f:
                json.dump(feature_order, f, indent=4)
            logger.info(f"📌 Feature order saved to: {FEATURE_ORDER_PATH}")

            num_samples = len(y)
            num_classes = y.nunique()

            if isinstance(self.test_size, float):
                test_count = int(num_samples * self.test_size)
            else:
                test_count = self.test_size

            train_count = num_samples - test_count

            if train_count < num_classes or test_count < num_classes:
                adjusted_test_count = max(num_classes, num_samples - num_classes)
                adjusted_test_size = adjusted_test_count / num_samples
                logger.warning(f"⚠ Not enough samples per class for stratification.")
                logger.warning(f"🔧 Adjusting test_size to {adjusted_test_size:.2f} ({adjusted_test_count} samples)")
                self.test_size = adjusted_test_size

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.test_size, stratify=y, random_state=42
            )

            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            logger.info(f"✅ Dataset loaded. Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")
            return X_train_scaled, X_test_scaled, y_train, y_test, label_col, df.shape

        except Exception as e:
            logger.error(f"❌ Dataset loading error: {e}")
            raise

    def train(self):
        try:
            X_train, X_test, y_train, y_test, label_col, shape = self.load_dataset()

            logger.info(f"🔄 Training {self.model_type} model...")
            self.model.fit(X_train, y_train)

            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred, output_dict=True)

            logger.info(f"✅ Training completed. Accuracy: {accuracy:.4f}")

            # Save model and scaler
            base_name = f"{self.model_type}_{self.timestamp}"
            model_path = os.path.join(MODELS_DIR, f"{base_name}_model.pkl")
            scaler_path = os.path.join(MODELS_DIR, f"{base_name}_scaler.pkl")

            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)

            logger.info(f"🧠 Model saved to: {model_path}")
            logger.info(f"📊 Scaler saved to: {scaler_path}")

            # Save training metadata
            metadata = {
                "model_type": self.model_type,
                "timestamp": self.timestamp,
                "dataset": self.dataset,
                "dataset_shape": shape,
                "label_column": label_col,
                "test_size": self.test_size,
                "accuracy": accuracy,
                "classification_report": report
            }

            metadata_path = os.path.join(LOGS_DIR, f"{base_name}_results.json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=4)

            return {
                "status": "success",
                "model_path": model_path,
                "scaler_path": scaler_path,
                "log_path": metadata_path,
                "accuracy": accuracy
            }

        except Exception as e:
            logger.error(f"❌ ML Training error: {e}")
            return {"status": "failed", "error": str(e)}


# CLI Execution
def main():
    parser = argparse.ArgumentParser(description="Machine Learning Model Training CLI for Malware Classification")
    parser.add_argument("--dataset", type=str, required=True, help="Path to the dataset (.csv)")
    parser.add_argument("--model", type=str, default="random_forest", help="Model type: random_forest")
    parser.add_argument("--test_size", type=float, default=0.2, help="Test size (float or int)")
    args = parser.parse_args()

    trainer = MLTrainer(dataset=args.dataset, model_type=args.model, test_size=args.test_size)
    result = trainer.train()

    if result["status"] == "success":
        print(f"\n✅ Training succeeded!")
        print(f"📁 Model: {result['model_path']}")
        print(f"📊 Scaler: {result['scaler_path']}")
        print(f"📝 Metadata: {result['log_path']}")
        print(f"🎯 Accuracy: {result['accuracy']:.4f}\n")
    else:
        print(f"\n❌ Training failed: {result['error']}\n")


if __name__ == "__main__":
    main()

