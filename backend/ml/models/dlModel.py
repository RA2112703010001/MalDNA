import os
import json
import logging
import argparse
import numpy as np
import pandas as pd
import tensorflow as tf
from typing import Dict, Any, Tuple

# Deep Learning Modules
from tensorflow.keras import models, layers, callbacks
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dl_model.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Paths Configuration
MODEL_DIR = "./saved_models"
DATA_DIR = "./data"
LOGS_DIR = "./logs"
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

class DeepLearningModel:
    def __init__(self, model_type: str = "cnn", input_shape: Tuple = (100, 1), threshold: float = 0.5):
        self.model_type = model_type
        self.input_shape = input_shape
        self.threshold = threshold

        # Load or Create Model
        self.model = self._load_or_create_model()
        self.scaler = StandardScaler()

    def _load_or_create_model(self) -> models.Model:
        """Load a pre-trained model or create a new one."""
        model_path = os.path.join(MODEL_DIR, f"{self.model_type}_model.h5")
        if os.path.exists(model_path):
            logger.info(f"Loading existing model from {model_path}")
            return models.load_model(model_path)
        logger.info(f"Creating a new {self.model_type} model")
        return self._build_cnn_model()

    def _build_cnn_model(self) -> models.Model:
        """Builds a CNN-based malware classification model."""
        inputs = layers.Input(shape=self.input_shape)
        x = layers.Conv1D(64, 3, activation="relu")(inputs)
        x = layers.MaxPooling1D(2)(x)
        x = layers.Conv1D(128, 3, activation="relu")(x)
        x = layers.GlobalAveragePooling1D()(x)
        x = layers.Dense(64, activation="relu")(x)
        x = layers.Dropout(0.5)(x)
        outputs = layers.Dense(1, activation="sigmoid")(x)
        model = models.Model(inputs, outputs)

        model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        return model

    def preprocess_data(self, data_path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Loads and preprocesses dataset from CSV."""
        df = pd.read_csv(data_path)
        X = np.array([json.loads(x) for x in df["features"]])
        y = df["label"].values

        # Data Normalization
        X = self.scaler.fit_transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)

        # Train-Test Split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        return X_train, X_test, y_train, y_test

    def train(self, data_path: str, epochs: int = 50, batch_size: int = 32):
        """Trains the deep learning model."""
        X_train, X_test, y_train, y_test = self.preprocess_data(data_path)

        # Model Callbacks
        callbacks_list = [
            callbacks.EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True),
            callbacks.ModelCheckpoint(os.path.join(MODEL_DIR, f"{self.model_type}_best.h5"), save_best_only=True),
        ]

        history = self.model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=epochs, batch_size=batch_size, callbacks=callbacks_list)
        self.model.save(os.path.join(MODEL_DIR, f"{self.model_type}_final.h5"))
        logger.info("Training completed and model saved.")

    def evaluate(self, data_path: str):
        """Evaluates model performance."""
        X_train, X_test, y_train, y_test = self.preprocess_data(data_path)
        loss, accuracy = self.model.evaluate(X_test, y_test)
        logger.info(f"Model Evaluation - Loss: {loss}, Accuracy: {accuracy}")

    def predict(self, sample_data: np.ndarray) -> Dict[str, Any]:
        """Predicts whether a sample is malicious or benign."""
        sample_data = self.scaler.transform(sample_data.reshape(1, -1, 1))
        prediction = self.model.predict(sample_data)
        predicted_class = "malicious" if prediction[0][0] > self.threshold else "benign"
        return {"predicted_class": predicted_class, "confidence_score": float(prediction[0][0])}

    def batch_process(self, batch_path: str):
        """Processes multiple samples in batch."""
        batch_data = np.load(batch_path)["samples"]
        predictions = [self.predict(sample) for sample in batch_data]
        logger.info(f"Batch Processing Completed: {predictions}")

# CLI Argument Parser
def main():
    parser = argparse.ArgumentParser(description="Deep Learning Malware Detection CLI")

    parser.add_argument("--train", type=str, help="Train model using dataset CSV")
    parser.add_argument("--evaluate", type=str, help="Evaluate model using dataset CSV")
    parser.add_argument("--predict", type=str, help="Predict malware status from a sample JSON file")
    parser.add_argument("--batch-process", type=str, help="Process batch samples from a .npz file")

    args = parser.parse_args()
    model = DeepLearningModel()

    if args.train:
        logger.info("Starting Training...")
        model.train(args.train)

    elif args.evaluate:
        logger.info("Evaluating Model...")
        model.evaluate(args.evaluate)

    elif args.predict:
        with open(args.predict, "r") as f:
            sample_data = np.array(json.load(f)["features"])
        result = model.predict(sample_data)
        print(json.dumps(result, indent=4))

    elif args.batch_process:
        logger.info("Processing Batch Samples...")
        model.batch_process(args.batch_process)

if __name__ == "__main__":
    main()

