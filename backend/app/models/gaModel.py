import os
import json
import logging
import argparse
import time
import random
from datetime import datetime
from typing import Dict, List, Any, Optional

# MongoDB Schema
from mongoengine import Document, StringField, FloatField, ListField, DateTimeField, IntField, BooleanField

# Blockchain Integration (Optional)
from app.services.blockchainService import blockchain_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Genetic Algorithm Training Model**
# --------------------------------------------
class GeneticAlgorithmTraining(Document):
    """
    MongoDB model to track Genetic Algorithm (GA) training sessions.
    """

    # 🎯 **Algorithm Configuration**
    training_id = StringField(primary_key=True, default=lambda: str(os.urandom(16).hex()), unique=True)
    population_size = IntField(required=True)
    generations = IntField(required=True)
    mutation_rate = FloatField(required=True)
    crossover_rate = FloatField(required=True)
    
    # 📂 **Dataset & Storage**
    data_path = StringField(required=True)
    best_solution = StringField(default="")  # Stores the best solution found
    
    # 📊 **Training History**
    fitness_history = ListField(FloatField(), default=list)
    diversity_history = ListField(FloatField(), default=list)
    
    # 🚀 **Performance Metrics**
    execution_time = FloatField(default=0.0)  # Stores training duration (in seconds)
    final_fitness = FloatField(default=0.0)
    final_diversity = FloatField(default=0.0)

    # 🔗 **Blockchain Verification**
    blockchain_tx_id = StringField()
    blockchain_verified = BooleanField(default=False)

    # 🕒 **Timestamps**
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    # 📌 **Indexing & Optimization**
    meta = {
        "collection": "genetic_algorithm_training",
        "indexes": [
            {'fields': ['-created_at']},
            {'fields': ['population_size', 'generations']}
        ]
    }

    # --------------------------------------------
    # 📌 **Blockchain Integration**
    # --------------------------------------------
    def store_on_blockchain(self):
        """
        Store GA training metadata on blockchain for verification.
        """
        try:
            blockchain_tx = blockchain_service.store_data_on_blockchain(json.dumps(self.to_dict()))
            self.blockchain_tx_id = blockchain_tx
            self.blockchain_verified = True
            self.save()

            logger.info(f"GA training stored on blockchain with TX: {blockchain_tx}")
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
            "population_size": self.population_size,
            "generations": self.generations,
            "mutation_rate": self.mutation_rate,
            "crossover_rate": self.crossover_rate,
            "data_path": self.data_path,
            "best_solution": self.best_solution,
            "fitness_history": self.fitness_history,
            "diversity_history": self.diversity_history,
            "execution_time": self.execution_time,
            "final_fitness": self.final_fitness,
            "final_diversity": self.final_diversity,
            "blockchain_tx_id": self.blockchain_tx_id,
            "blockchain_verified": self.blockchain_verified,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def update_metrics(self, fitness: float, diversity: float, execution_time: float):
        """
        Update GA performance metrics after training.
        """
        self.final_fitness = fitness
        self.final_diversity = diversity
        self.execution_time = execution_time
        self.updated_at = datetime.utcnow()
        self.save()

    def __repr__(self):
        return f"<GeneticAlgorithmTraining(population_size={self.population_size}, generations={self.generations}, fitness={self.final_fitness})>"

# --------------------------------------------
# 🚀 **CLI-Based Training Automation**
# --------------------------------------------
def run_genetic_algorithm(args):
    """
    CLI function to train a Genetic Algorithm and log results.
    """
    logger.info("🚀 Starting Genetic Algorithm Training...")

    # Initialize population (Dummy initialization)
    population = [random.uniform(0, 1) for _ in range(args.population_size)]
    fitness_history = []
    diversity_history = []

    start_time = time.time()
    for gen in range(args.generations):
        # Simulated fitness calculation
        fitness_scores = [random.uniform(0, 1) for _ in population]
        best_fitness = max(fitness_scores)
        avg_diversity = random.uniform(0, 1)  # Simulated diversity metric
        
        # Store history
        fitness_history.append(best_fitness)
        diversity_history.append(avg_diversity)

        # Genetic operations (Dummy)
        new_population = [
            (random.choice(population) + random.choice(population)) / 2 for _ in range(args.population_size)
        ]
        population = new_population

        logger.info(f"🧬 Generation {gen+1}/{args.generations} - Best Fitness: {best_fitness:.4f}, Diversity: {avg_diversity:.4f}")

    execution_time = time.time() - start_time
    best_solution = f"Best individual from last generation: {max(population)}"

    # Store training session
    training_session = GeneticAlgorithmTraining(
        population_size=args.population_size,
        generations=args.generations,
        mutation_rate=args.mutation_rate,
        crossover_rate=args.crossover_rate,
        data_path=args.data_path,
        best_solution=best_solution,
        fitness_history=fitness_history,
        diversity_history=diversity_history,
        execution_time=execution_time,
        final_fitness=fitness_history[-1],
        final_diversity=diversity_history[-1]
    )

    training_session.save()
    logger.info("✅ GA Training Completed Successfully!")

    # Store on blockchain (Optional)
    if args.store_on_blockchain:
        training_session.store_on_blockchain()

    return training_session.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a Genetic Algorithm and Save Training Data")
    
    parser.add_argument("--population_size", type=int, required=True, help="Size of the population")
    parser.add_argument("--generations", type=int, required=True, help="Number of generations")
    parser.add_argument("--mutation_rate", type=float, required=True, help="Mutation rate")
    parser.add_argument("--crossover_rate", type=float, required=True, help="Crossover rate")
    parser.add_argument("--data_path", type=str, required=True, help="Path to dataset")
    parser.add_argument("--store_on_blockchain", action="store_true", help="Store training session on blockchain")

    args = parser.parse_args()
    run_genetic_algorithm(args)

