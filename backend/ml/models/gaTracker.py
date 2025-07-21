import os
import json
import logging
import argparse
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from typing import Dict, Any, List
import hashlib

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ga_tracker.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Paths Configuration
MUTATION_DIR = "./mutations"
LOGS_DIR = "./logs"
os.makedirs(MUTATION_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

class GeneticAlgorithmTracker:
    """
    Tracks Genetic Algorithm (GA) mutation data and supports CLI-based retrieval and prediction.
    """

    def __init__(self):
        """Initialize GA Tracker"""
        self.mutation_data = []

    def track_mutation(self, generation: int, mutation_rate: float, fitness_scores: List[float]):
        """
        Tracks a new mutation entry.
        
        Args:
            generation (int): Generation number.
            mutation_rate (float): Mutation rate for this generation.
            fitness_scores (List[float]): Fitness scores after mutation.
        """
        mutation_entry = {
            "generation": generation,
            "mutation_rate": mutation_rate,
            "average_fitness": np.mean(fitness_scores),
            "max_fitness": np.max(fitness_scores),
            "min_fitness": np.min(fitness_scores),
            "timestamp": datetime.utcnow().isoformat()
        }
        self.mutation_data.append(mutation_entry)
        self._save_mutation_data()
        logger.info(f"Tracked mutation for Generation {generation}.")

    def _save_mutation_data(self):
        """Saves mutation data to a JSON file."""
        file_path = os.path.join(MUTATION_DIR, "mutation_log.json")
        with open(file_path, "w") as f:
            json.dump(self.mutation_data, f, indent=4)
        logger.info(f"Mutation data saved to {file_path}")

    def retrieve_mutation_data(self) -> List[Dict[str, Any]]:
        """Retrieves stored mutation data."""
        file_path = os.path.join(MUTATION_DIR, "mutation_log.json")
        if not os.path.exists(file_path):
            logger.warning("No mutation data found.")
            return []
        
        with open(file_path, "r") as f:
            data = json.load(f)
        return data

    def visualize_mutations(self):
        """
        Generates a visualization of mutation fitness scores.
        """
        data = self.retrieve_mutation_data()
        if not data:
            logger.warning("No mutation data available for visualization.")
            return
        
        generations = [entry["generation"] for entry in data]
        avg_fitness = [entry["average_fitness"] for entry in data]
        max_fitness = [entry["max_fitness"] for entry in data]
        min_fitness = [entry["min_fitness"] for entry in data]

        plt.figure(figsize=(10, 5))
        sns.lineplot(x=generations, y=avg_fitness, label="Avg Fitness", marker="o")
        sns.lineplot(x=generations, y=max_fitness, label="Max Fitness", marker="s")
        sns.lineplot(x=generations, y=min_fitness, label="Min Fitness", marker="d")
        plt.xlabel("Generation")
        plt.ylabel("Fitness Score")
        plt.title("Mutation Fitness Progression")
        plt.legend()
        plt.grid(True)

        plot_path = os.path.join(LOGS_DIR, "mutation_visualization.png")
        plt.savefig(plot_path)
        logger.info(f"Mutation visualization saved at {plot_path}")
        plt.show()

    def predict(self, dna_fingerprint: str) -> List[str]:
        """
        Predicts possible future mutations based on the given DNA fingerprint.

        Args:
            dna_fingerprint (str): The current DNA fingerprint.

        Returns:
            List[str]: List of predicted mutation patterns.
        """
        hash_val = hashlib.sha256(dna_fingerprint.encode()).hexdigest()
        predictions = [
            f"mut_{hash_val[i:i+4]}" for i in range(0, len(hash_val), 12)
        ]
        logger.info(f"Predicted {len(predictions)} mutations from fingerprint.")
        return predictions[:5]  # Top 5 predictions

# CLI Argument Parser
def main():
    parser = argparse.ArgumentParser(description="Genetic Algorithm Mutation Tracker CLI")

    parser.add_argument("--track", nargs=3, metavar=("GEN", "MUT_RATE", "FITNESS"),
                        help="Track a mutation (GENERATION, MUTATION_RATE, FITNESS_SCORES_JSON)")
    parser.add_argument("--retrieve", action="store_true", help="Retrieve stored mutation data")
    parser.add_argument("--visualize", action="store_true", help="Generate mutation visualization")
    parser.add_argument("--predict", metavar="FINGERPRINT", help="Predict future mutations from a DNA fingerprint")

    args = parser.parse_args()
    tracker = GeneticAlgorithmTracker()

    if args.track:
        generation = int(args.track[0])
        mutation_rate = float(args.track[1])
        fitness_scores = json.loads(args.track[2])
        tracker.track_mutation(generation, mutation_rate, fitness_scores)

    elif args.retrieve:
        data = tracker.retrieve_mutation_data()
        print(json.dumps(data, indent=4))

    elif args.visualize:
        tracker.visualize_mutations()

    elif args.predict:
        predictions = tracker.predict(args.predict)
        print(json.dumps(predictions, indent=4))

if __name__ == "__main__":
    main()

