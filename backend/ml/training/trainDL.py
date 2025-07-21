import os
import json
import logging
import argparse
import tensorflow as tf
import numpy as np
import pandas as pd
from typing import Dict, Any
from datetime import datetime
from models.dlModel import MalwareDLModel

# Logging Configuration
LOGS_DIR = "./logs"
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "trainDL.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DLTrainer:
    """
    Deep Learning Trainer for CLI-Driven Model Training.
    
    Allows configuration of hyperparameters, logs training progress,
    and validates model performance.
    """

    def __init__(self, model_type: str = "hybrid", data_path: str = None, epochs: int = 10, batch_size: int = 32):
        """
        Initialize trainer with model type and training parameters.

        Args:
            model_type (str): Type of deep learning model ("cnn", "rnn", "transformer", "hybrid").
            data_path (str): Path to dataset CSV file.
            epochs (int): Number of training epochs.
            batch_size (int): Batch size for training.
        """
        self.model_type = model_type
        self.data_path = data_path
        self.epochs = epochs
        self.batch_size = batch_size

        # Initialize Model
        self.model = MalwareDLModel(model_type=self.model_type)

    def train(self):
        """
        Train the deep learning model using the provided dataset with real-time monitoring.
        """
        try:
            if not self.data_path or not os.path.exists(self.data_path):
                raise FileNotFoundError("Dataset not found. Provide a valid data path.")

            logger.info(f"🔄 Starting training for {self.model_type} model...")

            # Training with real-time updates
            history = self.model.train(
                data_path=self.data_path,
                epochs=self.epochs,
                batch_size=self.batch_size
            )

            logger.info("✅ Training completed successfully.")

            # Save training logs
            log_path = os.path.join(LOGS_DIR, "training_logs.json")
            with open(log_path, "w") as f:
                json.dump(history.history, f, indent=4)

            # Run Automated Model Validation
            validation_result = self.model.evaluate_model()

            return {
                "status": "success",
                "log_path": log_path,
                "validation_metrics": validation_result
            }

        except Exception as e:
            logger.error(f"❌ Training error: {e}")
            return {"status": "failed", "error": str(e)}

# CLI Argument Parser
def main():
    parser = argparse.ArgumentParser(description="Deep Learning Model Training CLI")

    parser.add_argument("--model", type=str, default="hybrid", choices=["cnn", "rnn", "transformer", "hybrid"],
                        help="Specify the deep learning model type.")
    parser.add_argument("--data", type=str, required=True, help="Path to dataset CSV file.")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs.")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size for training.")

    args = parser.parse_args()
    trainer = DLTrainer(model_type=args.model, data_path=args.data, epochs=args.epochs, batch_size=args.batch_size)
    
    result = trainer.train()
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()

