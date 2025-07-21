import os
import logging
import argparse
import json
from typing import List, Dict, Any, Optional
from mongoengine import connect

# Internal modules
from app.models.lineageModel import LineageModel
from app.models.dnaModel import DNAModel
from app.services.blockchainService import BlockchainService
from app.services.dnaService import DNAAnalysisService  # ✅ Use this for dna_fingerprint logic
from ml.models.gaTracker import GeneticAlgorithmTracker

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# MongoDB connection
connect(
    db="maldna_db",
    host="mongodb://127.0.0.1:27017/maldna_db",
    alias="default"
)

class LineageAnalysisService:
    """Service class for malware lineage reconstruction and mutation tracking."""

    blockchain_service = BlockchainService()

    @staticmethod
    def reconstruct_lineage(sample_id: Optional[str] = None) -> Dict[str, Any]:
        try:
            logger.info(f"🔍 Reconstructing lineage for sample_id: {sample_id}")
            samples = [LineageModel.objects(sample_id=sample_id).first()] if sample_id else LineageModel.objects()
            if not samples:
                logger.warning("⚠️ No samples found for lineage reconstruction.")
                return {"error": "No samples available for lineage reconstruction."}

            lineage_data = {
                "root": "common_ancestor",
                "branches": []
            }

            for sample in samples:
                if not sample:
                    continue

                if not sample.dna_fingerprint:
                    if sample.dna_sequence:
                        sample.dna_fingerprint = DNAAnalysisService.generate_dna_fingerprint(sample.dna_sequence)
                        sample.save()
                        logger.info(f"🧬 Generated missing fingerprint for {sample.sample_id}")
                    else:
                        logger.warning(f"⚠️ Sample {sample.sample_id} missing both fingerprint and sequence.")
                        continue

                ga_tracker = GeneticAlgorithmTracker()
                mutations = ga_tracker.track_mutations(sample.dna_fingerprint)
                mutation_rate = len(mutations) / len(sample.dna_sequence) if sample.dna_sequence else 0

                sample.mutations = mutations
                sample.mutation_rate = mutation_rate
                sample.save()

                lineage_data["branches"].append({
                    "sample_id": sample.sample_id,
                    "family_name": sample.family_name or "unknown_family",
                    "dna": sample.dna_sequence,
                    "mutations": len(sample.mutations),
                    "mutation_rate": sample.mutation_rate,
                    "fingerprint": sample.dna_fingerprint
                })

            logger.info(f"✅ Reconstructed lineage from {len(lineage_data['branches'])} samples.")
            return {
                "lineage_data": lineage_data,
                "message": "Lineage reconstruction completed" if lineage_data["branches"] else "No samples available"
            }
        except Exception as e:
            logger.error(f"❌ Lineage reconstruction failed: {e}")
            return {"error": str(e)}

    @staticmethod
    def get_lineage(malware_dna: str) -> Dict[str, Any]:
        try:
            sample = LineageModel.objects(dna_sequence=malware_dna).first()
            if sample:
                logger.info(f"✅ Lineage found for DNA: {malware_dna}")
                return sample.reconstruct_malware_lineage()
            else:
                logger.warning(f"⚠️ No lineage found for DNA: {malware_dna}")
                return {"error": "Lineage data not found"}
        except Exception as e:
            logger.error(f"❌ Failed to get lineage: {e}")
            return {"error": str(e)}

    @staticmethod
    def predict_lineage_with_ai(dna_record: DNAModel) -> Dict[str, Any]:
        try:
            logger.info(f"🔍 Predicting lineage using AI for sample_id: {dna_record.sample_id}")

            # Ensure that the DNA record has a fingerprint
            if not dna_record.dna_fingerprint and dna_record.dna_sequence:
                dna_record.dna_fingerprint = DNAAnalysisService.generate_dna_fingerprint(dna_record.dna_sequence)
                dna_record.save()

            # Use AI-based model to predict lineage (You can replace this with your model)
            ai_predictor = AIPredictor()  # Assuming `AIPredictor` is your AI prediction model
            predicted_lineage = ai_predictor.predict(dna_record.dna_fingerprint)

            logger.info(f"✅ Lineage prediction successful for sample_id: {dna_record.sample_id}")
            return {
                "sample_id": dna_record.sample_id,
                "predicted_lineage": predicted_lineage
            }
        except Exception as e:
            logger.error(f"❌ AI-based lineage prediction failed: {e}")
            return {"error": str(e)}

    @staticmethod
    def track_mutations(sample_id: str) -> Dict[str, Any]:
        try:
            logger.info(f"🔍 Tracking mutations for sample_id: {sample_id}")
            sample = LineageModel.objects(sample_id=sample_id).first()
            if not sample:
                return {"error": "Sample not found"}

            if not sample.dna_fingerprint and sample.dna_sequence:
                sample.dna_fingerprint = DNAAnalysisService.generate_dna_fingerprint(sample.dna_sequence)
                sample.save()

            ga_tracker = GeneticAlgorithmTracker()
            mutations = ga_tracker.track_mutations(sample.dna_fingerprint)

            return {
                "sample_id": sample_id,
                "mutation_count": len(mutations),
                "mutations": mutations
            }
        except Exception as e:
            logger.error(f"❌ Mutation tracking failed: {e}")
            return {"error": str(e)}

    @staticmethod
    def generate_phylogenetic_tree() -> Dict[str, Any]:
        try:
            logger.info("🔍 Generating phylogenetic tree.")
            samples = LineageModel.objects()

            tree = {
                "root": "ancestor",
                "branches": [
                    {
                        "sample_id": s.sample_id,
                        "mutations": len(s.mutations),
                        "sequence": s.dna_sequence,
                        "family_name": s.family_name
                    } for s in samples
                ]
            }

            logger.info("✅ Phylogenetic tree generated.")
            return tree
        except Exception as e:
            logger.error(f"❌ Failed to generate tree: {e}")
            return {"error": str(e)}

    @staticmethod
    def verify_lineage_on_blockchain(sample_id: str) -> Dict[str, Any]:
        try:
            logger.info(f"🔍 Verifying lineage for {sample_id} on blockchain.")
            sample = LineageModel.objects(sample_id=sample_id).first()
            if not sample:
                return {"error": "Sample not found"}

            if not sample.dna_fingerprint and sample.dna_sequence:
                sample.dna_fingerprint = DNAAnalysisService.generate_dna_fingerprint(sample.dna_sequence)
                sample.save()

            # Use the blockchain service to store lineage data
            result = LineageAnalysisService.blockchain_service.store_on_blockchain({
                "sample_id": sample.sample_id,
                "dna_fingerprint": sample.dna_fingerprint
            })

            logger.info("✅ Blockchain verification complete.")
            return result
        except Exception as e:
            logger.error(f"❌ Blockchain verification failed: {e}")
            return {"error": str(e)}

    @staticmethod
    def get_mutation_history(sample_id: str) -> List[str]:
        try:
            logger.info(f"🔍 Fetching mutation history for {sample_id}")
            lineage_record = LineageModel.objects(sample_id=sample_id).first()
            if not lineage_record:
                return []

            if not lineage_record.mutation_history:
                logger.info(f"⚠️ No mutation history found for {sample_id}.")
                return []

            logger.info(f"✅ Mutation history fetched successfully.")
            return lineage_record.mutation_history
        except Exception as e:
            logger.error(f"❌ Fetching mutation history failed: {e}")
            return {"error": str(e)}

    @staticmethod
    def predict_future_mutations(sample_id: str) -> List[str]:
        try:
            logger.info(f"🔍 Predicting future mutations for {sample_id}")
            dna_record = DNAModel.objects(sample_id=sample_id).first()
            if not dna_record:
                return []

            if not dna_record.dna_fingerprint and dna_record.dna_sequence:
                dna_record.dna_fingerprint = DNAAnalysisService.generate_dna_fingerprint(dna_record.dna_sequence)
                dna_record.save()

            ga = GeneticAlgorithmTracker()
            prediction = ga.predict(dna_record.dna_fingerprint)
            logger.info(f"✅ Prediction successful.")
            return prediction
        except Exception as e:
            logger.error(f"❌ Future mutation prediction failed: {e}")
            return []

# ---------------------------- CLI INTERFACE ---------------------------- #

def cli_reconstruct_lineage():
    print("Reconstructing malware lineage...")
    result = LineageAnalysisService.reconstruct_lineage()
    print(json.dumps(result, indent=2))

def cli_track_mutations(sample_id: str):
    print(f"Tracking mutations for sample {sample_id}...")
    result = LineageAnalysisService.track_mutations(sample_id)
    print(json.dumps(result, indent=2))

def cli_generate_phylogenetic_tree():
    print("Generating phylogenetic tree...")
    result = LineageAnalysisService.generate_phylogenetic_tree()
    print(json.dumps(result, indent=2))

def cli_verify_lineage(sample_id: str):
    print(f"Verifying lineage for sample {sample_id} on blockchain...")
    result = LineageAnalysisService.verify_lineage_on_blockchain(sample_id)
    print(json.dumps(result, indent=2))

def cli_get_mutation_history(sample_id: str):
    print(f"Fetching mutation history for sample {sample_id}...")
    result = LineageAnalysisService.get_mutation_history(sample_id)
    print(json.dumps(result, indent=2))

def cli_predict_future_mutations(sample_id: str):
    print(f"Predicting future mutations for sample {sample_id}...")
    result = LineageAnalysisService.predict_future_mutations(sample_id)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MalDNA Lineage Analysis CLI")
    parser.add_argument("--reconstruct", action="store_true", help="Reconstruct malware lineage tree.")
    parser.add_argument("--track", metavar="DNA_ID", help="Track mutations of a DNA sample.")
    parser.add_argument("--phylogenetic", action="store_true", help="Generate phylogenetic tree.")
    parser.add_argument("--verify", metavar="LINEAGE_ID", help="Verify lineage on blockchain.")
    parser.add_argument("--history", metavar="SAMPLEID", help="Fetch mutation history.")
    parser.add_argument("--predict", metavar="SAMPLEID", help="Predict future mutations.")

    args = parser.parse_args()

    if args.reconstruct:
        cli_reconstruct_lineage()
    elif args.track:
        cli_track_mutations(args.track)
    elif args.phylogenetic:
        cli_generate_phylogenetic_tree()
    elif args.verify:
        cli_verify_lineage(args.verify)
    elif args.history:
        cli_get_mutation_history(args.history)
    elif args.predict:
        cli_predict_future_mutations(args.predict)
    else:
        print("[❌] No valid CLI argument provided.")

