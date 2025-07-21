import os
import json
import logging
import argparse
import time
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Any

# ML Libraries
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# MongoDB Schema
from mongoengine import Document, StringField, FloatField, DictField, DateTimeField, IntField, BooleanField

# Blockchain Integration (Optional)
from app.services.blockchainService import blockchain_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Machine Learning Training Model**
# --------------------------------------------
class MachineLearningTraining(Document):
    """
    MongoDB model to track Machine Learning (ML) training sessions.
    """

    # 🎯 **Algorithm Configuration**
    training_id = StringField(primary_key=True, default=lambda: str(os.urandom(16).hex()), unique=True)
    model_type = StringField(required=True)
    test_size = FloatField(required=True)
    cv_folds = IntField(required=True)
    data_path = StringField(required=True)
    
    # 📊 **Training Results**
    training_results = DictField(default={
        'best_params': {},
        'best_score': 0,
        'classification_report': {},
        'confusion_matrix': []
    })

    # 🚀 **Performance Metrics**
    execution_time = FloatField(default=0.0)  # Stores training duration (in seconds)

    # 🔗 **Blockchain Verification**
    blockchain_tx_id = StringField()
    blockchain_verified = BooleanField(default=False)

    # 🕒 **Timestamps**
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    # 📌 **Indexing & Optimization**
    meta = {
        "collection": "machine_learning_training",
        "indexes": [
            {'fields': ['-created_at']},
            {'fields': ['model_type']}
        ]
    }

    # --------------------------------------------
    # 📌 **Blockchain Integration**
    # --------------------------------------------
    def store_on_blockchain(self):
        """
        Store ML training metadata on blockchain for verification.
        """
        try:
            blockchain_tx = blockchain_service.store_data_on_blockchain(json.dumps(self.to_dict()))
            self.blockchain_tx_id = blockchain_tx
            self.blockchain_verified = True
            self.save()

            logger.info(f"ML training stored on blockchain with TX: {blockchain_tx}")
        except Exception as e:
            logger.error(f"Blockchain storage failed: {e}")
            raise

    # --------------------------------------------
    # 📌 **Utility Functions**
    # --------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the training instance to a dictionary.
        """
        return {
            "training_id": self.training_id,
            "model_type": self.model_type,
            "test_size": self.test_size,
            "cv_folds": self.cv_folds,
            "data_path": self.data_path,
            "training_results": self.training_results,
            "execution_time": self.execution_time,
            "blockchain_tx_id": self.blockchain_tx_id,
            "blockchain_verified": self.blockchain_verified,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def update_results(self, results: Dict[str, Any], execution_time: float):
        """
        Update ML training results after training.
        """
        self.training_results = results
        self.execution_time = execution_time
        self.updated_at = datetime.utcnow()
        self.save()

    def __repr__(self):
        return f"<MachineLearningTraining(model_type={self.model_type}, best_score={self.training_results.get('best_score', 0)})>"

# --------------------------------------------
# 🚀 **CLI-Based Training Automation**
# --------------------------------------------
def run_machine_learning_training(args):
    """
    CLI function to train an ML model and log results.
    """
    logger.info("🚀 Starting Machine Learning Training...")

    # Load dataset
    try:
        data = pd.read_csv(args.data_path)
    except Exception as e:
        logger.error(f"Failed to load dataset: {e}")
        return

    # Extract features and labels
    X = data.iloc[:, :-1].values
    y = data.iloc[:, -1].values

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=args.test_size, random_state=42)

    # Model selection
    if args.model_type == "random_forest":
        model = RandomForestClassifier()
        param_grid = {"n_estimators": [50, 100, 200], "max_depth": [5, 10, 20]}
    else:
        logger.error(f"Unsupported model type: {args.model_type}")
        return

    # Hyperparameter tuning
    grid_search = GridSearchCV(model, param_grid, cv=args.cv_folds, scoring="accuracy")
    
    start_time = time.time()
    grid_search.fit(X_train, y_train)
    execution_time = time.time() - start_time

    # Evaluate the best model
    best_model = grid_search.best_estimator_
    y_pred = best_model.predict(X_test)

    # Store results
    training_results = {
        "best_params": grid_search.best_params_,
        "best_score": grid_search.best_score_,
        "classification_report": classification_report(y_test, y_pred, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
    }

    # Save model
    model_path = f"models/{args.model_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pkl"
    os.makedirs("models", exist_ok=True)
    joblib.dump(best_model, model_path)

    # Store training session
    training_session = MachineLearningTraining(
        model_type=args.model_type,
        test_size=args.test_size,
        cv_folds=args.cv_folds,
        data_path=args.data_path,
        training_results=training_results,
        execution_time=execution_time
    )

    training_session.save()
    logger.info("✅ ML Training Completed Successfully!")

    # Store on blockchain (Optional)
    if args.store_on_blockchain:
        training_session.store_on_blockchain()

    return training_session.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run an ML Model and Save Training Data")
    
    parser.add_argument("--model_type", type=str, required=True, choices=["random_forest"], help="Type of model to train")
    parser.add_argument("--test_size", type=float, required=True, help="Test set size (0.1 - 0.5)")
    parser.add_argument("--cv_folds", type=int, required=True, help="Number of cross-validation folds")
    parser.add_argument("--data_path", type=str, required=True, help="Path to dataset")
    parser.add_argument("--store_on_blockchain", action="store_true", help="Store training session on blockchain")

    args = parser.parse_args()
    run_machine_learning_training(args)

