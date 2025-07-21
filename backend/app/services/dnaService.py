import os
import json
import hashlib
import logging
import argparse
import base64
from typing import List, Dict, Any, Optional
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import CountVectorizer
from pymongo import MongoClient
import numpy as np
import matplotlib.pyplot as plt

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/maldna_db")
client = MongoClient(MONGO_URI)
db = client["MalDNA"]

class DNAAnalysisService:
    """Service class for malware DNA analysis, fingerprinting, and similarity comparison."""

    @staticmethod
    def extract_opcode_sequence(file_path: str) -> str:
        """Mock function to extract opcode sequence from a binary file (extendable)."""
        try:
            with open(file_path, 'rb') as f:
                binary = f.read()
            # Convert binary to hex to simulate opcode-like string
            opcode_sequence = ' '.join([hex(b)[2:] for b in binary[:200]])
            logger.info(f"✅ Extracted opcode sequence from {file_path}")
            return opcode_sequence
        except Exception as e:
            logger.error(f"❌ Opcode extraction failed: {e}")
            return ""

    @staticmethod
    def encode_feature_vector(opcode_sequence: str) -> List[int]:
        """Encode opcode sequence into a numerical feature vector using bag-of-words."""
        try:
            vectorizer = CountVectorizer()
            features = vectorizer.fit_transform([opcode_sequence])
            vector = features.toarray()[0]
            logger.info("✅ Opcode sequence encoded to feature vector")
            return vector.tolist()
        except Exception as e:
            logger.error(f"❌ Feature vector encoding failed: {e}")
            return []
    @staticmethod
    def generate_dna_referenceid(dna_fingerprint: str, malware_id: Optional[str] = None, filename: Optional[str] = None) -> str:
        """Generate a unique DNA reference ID for tracking malware DNA samples."""
        try:
            # Concatenate DNA fingerprint with malware ID and filename to ensure uniqueness
            reference_str = dna_fingerprint
            if malware_id:
                reference_str += malware_id
            if filename:
                reference_str += filename

            # Create a unique reference ID using SHA-256 hash
            reference_id = hashlib.sha256(reference_str.encode()).hexdigest()
            logger.info(f"✅ Generated DNA reference ID: {reference_id}")
            return reference_id
        except Exception as e:
            logger.error(f"❌ Error generating DNA reference ID: {e}")
            return ""
    @staticmethod
    def generate_dna_fingerprint(feature_vector: List[int], malware_id: Optional[str] = None, filename: Optional[str] = None) -> str:
        """Generate DNA fingerprint from encoded feature vector using SHA-256."""
        try:
            serialized = json.dumps(feature_vector)
            dna_fingerprint = hashlib.sha256(serialized.encode()).hexdigest()
            logger.info(f"✅ Generated DNA Fingerprint: {dna_fingerprint}")

            # Automatically store in MongoDB if metadata is provided
            if malware_id and filename:
                DNAAnalysisService.store_dna(malware_id, filename, dna_fingerprint)

            return dna_fingerprint
        except Exception as e:
            logger.error(f"❌ DNA fingerprint generation failed: {e}")
            return ""

    @staticmethod
    def detect_mutations(dna_fingerprint_1: str, dna_fingerprint_2: str) -> str:
        """Detect mutations between two DNA fingerprints (using some mutation comparison logic)."""
        try:
            # First, compare the fingerprints to detect changes
            score = DNAAnalysisService.compare_two_dna(dna_fingerprint_1, dna_fingerprint_2)
            
            # Set a threshold for what constitutes a mutation (you can adjust this value)
            mutation_threshold = 0.8  # e.g., 0.8 similarity or below could be considered a mutation
            
            if score < mutation_threshold:
                mutation_status = "Mutation Detected"
            else:
                mutation_status = "No Mutation Detected"

            logger.info(f"✅ Mutation status: {mutation_status}")
            return mutation_status
        except Exception as e:
            logger.error(f"❌ Mutation detection failed: {e}")
            return "Error detecting mutations"

    @staticmethod
    def _convert_hex_to_vector(hex_string: str) -> List[int]:
        """Convert hex string fingerprint to numerical byte vector."""
        try:
            # Strip any non-hex characters and ensure proper length
            hex_string = ''.join(filter(lambda x: x in '0123456789abcdefABCDEF', hex_string))

            # Check if the cleaned hex string has an odd number of characters
            if len(hex_string) % 2 != 0:
                logger.warning("⚠️ DNA fingerprint hex string has an odd number of characters. Padding to ensure even length.")
                hex_string = "0" + hex_string  # Padding to make it even length

            byte_vector = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
            logger.info(f"✅ Byte vector for visualization: {byte_vector}")
            return byte_vector

        except ValueError:
            logger.error("❌ Invalid hex string format for DNA fingerprint.")
            return []

    @staticmethod
    def compare_two_dna(dna_fingerprint_1: str, dna_fingerprint_2: str) -> float:
        """Compares two DNA hex fingerprints using cosine similarity of byte vectors."""
        if not dna_fingerprint_1 or not dna_fingerprint_2:
            raise ValueError("Both DNA fingerprints must be provided")

        vec1 = np.array(DNAAnalysisService._convert_hex_to_vector(dna_fingerprint_1)).reshape(1, -1)
        vec2 = np.array(DNAAnalysisService._convert_hex_to_vector(dna_fingerprint_2)).reshape(1, -1)

        if vec1.shape[1] != vec2.shape[1]:
            logger.warning("⚠️ DNA vectors have different lengths. Padding shorter vector.")
            max_len = max(vec1.shape[1], vec2.shape[1])
            vec1 = np.pad(vec1, ((0, 0), (0, max_len - vec1.shape[1])), 'constant')
            vec2 = np.pad(vec2, ((0, 0), (0, max_len - vec2.shape[1])), 'constant')

        score = cosine_similarity(vec1, vec2)[0][0]
        logger.info(f"✅ Cosine similarity between fingerprints: {score:.4f}")
        return float(score)

    @staticmethod
    def store_dna(malware_id: str, filename: str, dna_fingerprint: str) -> str:
        """Store DNA fingerprint in MongoDB, avoiding duplicates."""
        try:
            existing = db.dna.find_one({"filename": filename})
            if existing:
                db.dna.update_one(
                    {"filename": filename},
                    {"$set": {"malware_id": malware_id, "dna_fingerprint": dna_fingerprint}}
                )
                logger.info(f"🟡 DNA updated for {filename}")
                return str(existing["_id"])

            inserted_id = db.dna.insert_one({
                "malware_id": malware_id,
                "filename": filename,
                "dna_fingerprint": dna_fingerprint,
            }).inserted_id
            logger.info(f"✅ DNA stored in DB with ID: {inserted_id}")
            return str(inserted_id)
        except Exception as e:
            logger.error(f"❌ Error storing DNA in DB: {e}")
            return ""

    @staticmethod
    def visualize_dna_sequence(dna_fingerprint: str) -> None:
        """Visualize DNA fingerprint through a graphical sequence representation."""
        try:
            # Convert the hex fingerprint to a list of numerical values (byte representation)
            byte_vector = DNAAnalysisService._convert_hex_to_vector(dna_fingerprint)

            # Check if the byte_vector is empty or not
            if not byte_vector:
                logger.error("❌ No valid byte data found for DNA fingerprint visualization.")
                return

            # Log the byte vector to verify
            logger.info(f"✅ Byte vector for visualization: {byte_vector}")

            # Plotting the DNA fingerprint sequence as a graph
            plt.figure(figsize=(10, 5))
            plt.plot(byte_vector, color='blue', marker='o')
            plt.title("DNA Fingerprint Sequence Visualization")
            plt.xlabel("Byte Index")
            plt.ylabel("Byte Value")
            plt.grid(True)
            plt.show()
            logger.info("✅ DNA fingerprint sequence visualized successfully.")
        except Exception as e:
            logger.error(f"❌ Error visualizing DNA fingerprint: {e}")

    @staticmethod
    def vector_from_fingerprint(dna_fingerprint: str) -> List[int]:
        """Convert DNA fingerprint to fixed-length numerical vector."""
        return [int(dna_fingerprint[i:i+8], 16) % 256 for i in range(0, len(dna_fingerprint), 8)]

    @staticmethod
    def fetch_all_dna() -> List[Dict[str, str]]:
        """Fetch all DNA records from MongoDB."""
        try:
            records = db.dna.find({}, {"_id": 0})
            return list(records)
        except Exception as e:
            logger.error(f"❌ Error fetching DNA records: {e}")
            return []

    @staticmethod
    def generate_dna_sequence(file_path: str) -> Dict[str, Any]:
        """Generate a DNA-like sequence, features, and hash from file content."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            sequence_string = base64.b64encode(data).decode("utf-8")[:500]
            dna_hash = hashlib.sha256(data).hexdigest()
            extracted_features = {
                "length": len(data),
                "entropy": round(DNAAnalysisService._calculate_entropy(data), 4),
            }

            return {
                "sequence": sequence_string,
                "features": extracted_features,
                "hash": dna_hash,
            }

        except Exception as e:
            logger.error(f"[❌] Error generating DNA sequence: {e}")
            return {}

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        from math import log2
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * log2(p)

        return entropy

    @staticmethod
    def get_family_by_name(family_name: str) -> Optional[Dict[str, Any]]:
        """Fetch a DNA family by its name from MongoDB."""
        try:
            family = db.dna_families.find_one({"name": family_name})
            if not family:
                logger.warning(f"⚠️ DNA family {family_name} not found.")
                return None

            logger.info(f"✅ DNA family {family_name} retrieved.")
            return family
        except Exception as e:
            logger.error(f"❌ Error fetching DNA family: {e}")
            return None

