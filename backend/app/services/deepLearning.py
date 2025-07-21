import os
import json
import logging
import argparse
import numpy as np
import tensorflow as tf
from typing import List, Dict, Any

# Scikit-learn dependencies
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

# Internal dependencies
from app.models.mlModel import MLModel
from app.services.blockchainService import store_model_on_blockchain, verify_model_on_blockchain
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration constants
MODEL_SAVE_PATH = os.getenv("MODEL_SAVE_PATH", "/tmp/ml_models")
RANDOM_SEED = int(os.getenv("RANDOM_SEED", "42"))
DEFAULT_EPOCHS = int(os.getenv("DEFAULT_EPOCHS", "10"))
DEFAULT_BATCH_SIZE = int(os.getenv("DEFAULT_BATCH_SIZE", "32"))

class DeepLearningService:
    @staticmethod
    def preprocess_data(features: np.ndarray) -> np.ndarray:
        """Preprocess features using standard scaling."""
        try:
            scaler = StandardScaler()
            return scaler.fit_transform(features)
        except Exception as e:
            logger.error(f"Data preprocessing failed: {e}")
            raise

    @classmethod
    def train_neural_network(cls, features: np.ndarray, labels: np.ndarray) -> tf.keras.Model:
        """Train a neural network for malware classification."""
        try:
            features = cls.preprocess_data(features)
            X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=RANDOM_SEED)
            
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(128, activation='relu', input_shape=(features.shape[1],)),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            model.fit(X_train, y_train, epochs=DEFAULT_EPOCHS, batch_size=DEFAULT_BATCH_SIZE, validation_data=(X_test, y_test), verbose=0)
            
            logger.info("Neural network training complete")
            return model
        except Exception as e:
            logger.error(f"Neural network training failed: {e}")
            raise

    @classmethod
    def train_cnn_opcode_analysis(cls, opcode_sequences: List[List[int]], labels: np.ndarray, max_length: int = 1000) -> tf.keras.Model:
        """Train a CNN for opcode analysis."""
        try:
            padded_sequences = tf.keras.preprocessing.sequence.pad_sequences(opcode_sequences, maxlen=max_length, padding='post')
            reshaped_data = np.array(padded_sequences).reshape(-1, max_length, 1)
            
            X_train, X_test, y_train, y_test = train_test_split(reshaped_data, labels, test_size=0.2, random_state=RANDOM_SEED)
            
            model = tf.keras.Sequential([
                tf.keras.layers.Conv1D(64, kernel_size=5, activation='relu', input_shape=(max_length, 1)),
                tf.keras.layers.MaxPooling1D(pool_size=2),
                tf.keras.layers.Flatten(),
                tf.keras.layers.Dense(128, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            model.fit(X_train, y_train, epochs=DEFAULT_EPOCHS, batch_size=DEFAULT_BATCH_SIZE, validation_data=(X_test, y_test), verbose=0)
            
            logger.info("CNN opcode analysis training complete")
            return model
        except Exception as e:
            logger.error(f"CNN opcode analysis failed: {e}")
            raise

    @classmethod
    def generate_model_report(cls, model: tf.keras.Model, features: np.ndarray, labels: np.ndarray) -> Dict[str, Any]:
        """Generate a classification report for the trained model."""
        try:
            predictions = model.predict(features)
            binary_predictions = (predictions > 0.5).astype(int)
            
            report = classification_report(labels, binary_predictions, output_dict=True)
            cm = confusion_matrix(labels, binary_predictions)
            
            blockchain_verification = cls.verify_model_integrity(model)
            
            full_report = {
                "classification_report": report,
                "confusion_matrix": cm.tolist(),
                "blockchain_verification": blockchain_verification
            }
            
            ml_model = MLModel(model=model.get_weights(), report=full_report)
            ml_model.save()
            
            logger.info("Model report generated successfully")
            return full_report
        except Exception as e:
            logger.error(f"Model report generation failed: {e}")
            raise

    @staticmethod
    def verify_model_integrity(model: tf.keras.Model) -> Dict[str, Any]:
        """Verify model integrity using blockchain."""
        try:
            model_hash = hash(str(model.get_weights()))
            blockchain_tx_id = store_model_on_blockchain(model_hash)
            verification_result = verify_model_on_blockchain(blockchain_tx_id)
            return verification_result
        except Exception as e:
            logger.error(f"Model verification failed: {e}")
            raise

    @staticmethod
    def perform_gpu_inference(model: tf.keras.Model, features: np.ndarray) -> np.ndarray:
        """Perform GPU-accelerated inference."""
        try:
            with tf.device('/GPU:0'):
                return model.predict(features)
        except Exception as e:
            logger.warning(f"GPU inference failed, falling back to CPU: {e}")
            return model.predict(features)


# ---------------------------- CLI HANDLER ---------------------------- #

def cli_train_nn(args):
    """CLI wrapper for training neural network."""
    features = np.load(args.features)
    labels = np.load(args.labels)
    model = DeepLearningService.train_neural_network(features, labels)
    model.save(args.model_path)


def cli_train_cnn(args):
    """CLI wrapper for training CNN opcode analysis."""
    opcode_sequences = np.load(args.opcode_sequences, allow_pickle=True)
    labels = np.load(args.labels)
    model = DeepLearningService.train_cnn_opcode_analysis(opcode_sequences, labels)
    model.save(args.model_path)


def cli_generate_report(args):
    """CLI wrapper for generating model report."""
    model = tf.keras.models.load_model(args.model)
    features = np.load(args.features)
    labels = np.load(args.labels)
    report = DeepLearningService.generate_model_report(model, features, labels)
    print(json.dumps(report, indent=4))


def cli_verify_model(args):
    """CLI wrapper for verifying model integrity."""
    model = tf.keras.models.load_model(args.model)
    verification = DeepLearningService.verify_model_integrity(model)
    print(json.dumps(verification, indent=4))


def cli_infer(args):
    """CLI wrapper for performing inference."""
    model = tf.keras.models.load_model(args.model)
    features = np.load(args.features)
    predictions = DeepLearningService.perform_gpu_inference(model, features)
    print(predictions)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deep Learning Service CLI")
    subparsers = parser.add_subparsers(help="Commands")

    parser_nn = subparsers.add_parser("train_nn", help="Train Neural Network")
    parser_nn.set_defaults(func=cli_train_nn)

    parser_cnn = subparsers.add_parser("train_cnn", help="Train CNN Opcode Analysis")
    parser_cnn.set_defaults(func=cli_train_cnn)

    args = parser.parse_args()
    args.func(args)

