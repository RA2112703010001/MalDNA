import os
import json
import logging
import argparse
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

# ML Libraries
import numpy as np
import tensorflow as tf  # Can be replaced with PyTorch if needed

# MongoDB Schema
from mongoengine import Document, StringField, IntField, FloatField, DictField, ListField, DateTimeField, BooleanField

# Blockchain Integration (Optional)
from app.services.blockchainService import blockchain_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Deep Learning Training Model**
# --------------------------------------------
class DeepLearningTraining(Document):
    """
    MongoDB model to track Deep Learning training sessions.
    """

    # 🎯 **Model Information**
    model_id = StringField(primary_key=True, default=lambda: str(os.urandom(16).hex()), unique=True)
    model_type = StringField(required=True, choices=["CNN", "RNN", "LSTM", "Transformer", "GAN", "Ensemble"])
    framework = StringField(required=True, choices=["TensorFlow", "PyTorch", "Keras", "Scikit-Learn"])

    # 🔢 **Hyperparameters & Training Config**
    input_shape = ListField(IntField(), required=True)
    epochs = IntField(required=True)
    batch_size = IntField(required=True)
    learning_rate = FloatField(default=0.001)
    optimizer = StringField(default="adam")
    
    # 📂 **Dataset & Storage**
    data_path = StringField(required=True)
    model_checkpoint_path = StringField(default="")  # Stores saved model checkpoints

    # 📊 **Training History**
    training_history = DictField(default={
        'accuracy': [],
        'val_accuracy': [],
        'loss': [],
        'val_loss': []
    })
    
    # 🚀 **Performance Metrics**
    execution_time = FloatField(default=0.0)  # Stores training duration (in seconds)
    final_accuracy = FloatField(default=0.0)
    final_loss = FloatField(default=0.0)

    # ⚡ **System Utilization**
    gpu_utilization = FloatField(default=0.0)
    cpu_utilization = FloatField(default=0.0)

    # 🔗 **Blockchain Verification**
    blockchain_tx_id = StringField()
    blockchain_verified = BooleanField(default=False)

    # 🕒 **Timestamps**
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    # 📌 **Indexing & Optimization**
    meta = {
        "collection": "deep_learning_training",
        "indexes": [
            {'fields': ['-created_at']},
            {'fields': ['model_type']},
            {'fields': ['framework']}
        ]
    }

    # --------------------------------------------
    # 📌 **Blockchain Integration**
    # --------------------------------------------
    def store_on_blockchain(self):
        """
        Store model metadata on blockchain for verification.
        """
        try:
            blockchain_tx = blockchain_service.store_data_on_blockchain(json.dumps(self.to_dict()))
            self.blockchain_tx_id = blockchain_tx
            self.blockchain_verified = True
            self.save()

            logger.info(f"Model training stored on blockchain with TX: {blockchain_tx}")
        except Exception as e:
            logger.error(f"Blockchain storage failed: {e}")
            raise

    # --------------------------------------------
    # 📌 **Utility Functions**
    # --------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the model instance to a dictionary.
        """
        return {
            "model_id": self.model_id,
            "model_type": self.model_type,
            "framework": self.framework,
            "input_shape": self.input_shape,
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "learning_rate": self.learning_rate,
            "optimizer": self.optimizer,
            "data_path": self.data_path,
            "model_checkpoint_path": self.model_checkpoint_path,
            "training_history": self.training_history,
            "execution_time": self.execution_time,
            "final_accuracy": self.final_accuracy,
            "final_loss": self.final_loss,
            "gpu_utilization": self.gpu_utilization,
            "cpu_utilization": self.cpu_utilization,
            "blockchain_tx_id": self.blockchain_tx_id,
            "blockchain_verified": self.blockchain_verified,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def update_metrics(self, accuracy: float, loss: float, execution_time: float):
        """
        Update model metrics after training.
        """
        self.final_accuracy = accuracy
        self.final_loss = loss
        self.execution_time = execution_time
        self.updated_at = datetime.utcnow()
        self.save()

    def __repr__(self):
        return f"<DeepLearningTraining(model_type={self.model_type}, epochs={self.epochs}, accuracy={self.final_accuracy})>"

# --------------------------------------------
# 🚀 **CLI-Based Training Automation**
# --------------------------------------------
def train_model_cli(args):
    """
    CLI function to train a deep learning model and log results.
    """
    logger.info("🚀 Starting Deep Learning Model Training...")

    # Load dataset (Dummy dataset used for now)
    x_train, y_train = np.random.rand(1000, *args.input_shape), np.random.randint(2, size=(1000,))
    x_test, y_test = np.random.rand(200, *args.input_shape), np.random.randint(2, size=(200,))

    # Build a simple model
    model = tf.keras.Sequential([
        tf.keras.layers.Flatten(input_shape=args.input_shape),
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer=args.optimizer, loss='binary_crossentropy', metrics=['accuracy'])

    # Train model
    start_time = time.time()
    history = model.fit(x_train, y_train, validation_data=(x_test, y_test), epochs=args.epochs, batch_size=args.batch_size)
    execution_time = time.time() - start_time

    # Save model
    model.save(args.model_checkpoint_path)

    # Store training data
    training_session = DeepLearningTraining(
        model_type=args.model_type,
        framework=args.framework,
        input_shape=args.input_shape,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        optimizer=args.optimizer,
        data_path=args.data_path,
        model_checkpoint_path=args.model_checkpoint_path,
        training_history={
            'accuracy': history.history['accuracy'],
            'val_accuracy': history.history['val_accuracy'],
            'loss': history.history['loss'],
            'val_loss': history.history['val_loss']
        },
        execution_time=execution_time,
        final_accuracy=history.history['accuracy'][-1],
        final_loss=history.history['loss'][-1]
    )

    training_session.save()
    logger.info("✅ Training Completed Successfully!")

    # Store on blockchain (Optional)
    if args.store_on_blockchain:
        training_session.store_on_blockchain()

    return training_session.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train a Deep Learning Model and Save Training Data")
    
    parser.add_argument("--model_type", type=str, required=True, help="Model type (CNN, RNN, Transformer, etc.)")
    parser.add_argument("--framework", type=str, required=True, help="Framework (TensorFlow, PyTorch, etc.)")
    parser.add_argument("--input_shape", nargs="+", type=int, required=True, help="Input shape of the model")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size")
    parser.add_argument("--learning_rate", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--optimizer", type=str, default="adam", help="Optimizer")
    parser.add_argument("--data_path", type=str, required=True, help="Path to dataset")
    parser.add_argument("--model_checkpoint_path", type=str, required=True, help="Where to save trained model")
    parser.add_argument("--store_on_blockchain", action="store_true", help="Store training session on blockchain")

    args = parser.parse_args()
    train_model_cli(args)

