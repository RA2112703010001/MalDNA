import os
import json
import logging
import argparse
import numpy as np
from datetime import datetime
from models.gaTracker import GeneticAlgorithmModel

# Logging Configuration
LOGS_DIR = "./logs"
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "trainGA.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class GATrainer:
    """
    CLI-Based Genetic Algorithm Trainer
    
    Supports mutation tracking, dataset automation, and performance monitoring.
    """

    def __init__(self, population_size: int = 50, generations: int = 100, mutation_rate: float = 0.05, dataset: str = None):
        """
        Initialize GA training parameters.

        Args:
            population_size (int): Number of individuals per generation.
            generations (int): Total number of generations.
            mutation_rate (float): Mutation probability.
            dataset (str): Path to dataset for training.
        """
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.dataset = dataset or self.auto_select_dataset()

        # Initialize Genetic Algorithm Model
        self.ga_model = GeneticAlgorithmModel(
            population_size=self.population_size,
            generations=self.generations,
            mutation_rate=self.mutation_rate
        )

    def auto_select_dataset(self) -> str:
        """
        Automatically select a dataset for training based on availability.

        Returns:
            str: Path to selected dataset.
        """
        data_dir = "./data"
        available_datasets = [f for f in os.listdir(data_dir) if f.endswith(".csv")]

        if not available_datasets:
            raise FileNotFoundError("No dataset found in the data directory.")

        selected_dataset = os.path.join(data_dir, available_datasets[0])
        logger.info(f"📌 Automatically selected dataset: {selected_dataset}")
        return selected_dataset

    def train(self):
        """
        Train the Genetic Algorithm model and monitor progress.
        """
        try:
            logger.info(f"🔄 Starting GA training with {self.population_size} individuals for {self.generations} generations...")

            # Train with real-time logging
            history = self.ga_model.train(self.dataset)

            logger.info("✅ GA Training completed successfully.")

            # Save training logs
            log_path = os.path.join(LOGS_DIR, "ga_training_logs.json")
            with open(log_path, "w") as f:
                json.dump(history, f, indent=4)

            # Run Automated Performance Evaluation
            performance_report = self.ga_model.evaluate()

            return {
                "status": "success",
                "log_path": log_path,
                "performance_metrics": performance_report
            }

        except Exception as e:
            logger.error(f"❌ GA Training error: {e}")
            return {"status": "failed", "error": str(e)}

# CLI Argument Parser
def main():
    parser = argparse.ArgumentParser(description="Genetic Algorithm Training CLI")

    parser.add_argument("--population", type=int, default=50, help="Population size per generation.")
    parser.add_argument("--generations", type=int, default=100, help="Total number of generations.")
    parser.add_argument("--mutation_rate", type=float, default=0.05, help="Mutation rate.")
    parser.add_argument("--dataset", type=str, help="Path to dataset (optional).")

    args = parser.parse_args()
    trainer = GATrainer(population_size=args.population, generations=args.generations, mutation_rate=args.mutation_rate, dataset=args.dataset)
    
    result = trainer.train()
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()

