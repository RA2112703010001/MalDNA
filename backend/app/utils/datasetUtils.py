import os
import logging
from pymongo import MongoClient
from datetime import datetime
from mongoengine import DoesNotExist
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017/maldna_db")
# Logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class DatasetProcessor:
    """Utility class to process a folder of malware samples automatically."""

    @staticmethod
    def ingest_dataset(dataset_path):
        """
        Ingests all files in a dataset directory and creates MalwareMetadata entries.
        Avoids duplicates by checking filename.
        """
        if not os.path.isdir(dataset_path):
            logger.error(f"❌ Invalid dataset directory: {dataset_path}")
            return []

        logger.info(f"📂 Ingesting dataset from: {dataset_path}")
        ingested = []

        for root, dirs, files in os.walk(dataset_path):
            for filename in files:
                full_path = os.path.join(root, filename)

                # Check for duplicate
                if MalwareMetadata.objects(filename=filename).first():
                    logger.warning(f"⚠️ Sample already exists: {filename}")
                    continue

                # Register metadata
                malware = MalwareMetadata(
                    filename=filename,
                    file_path=full_path,
                    uploaded_at=datetime.utcnow(),
                    status="ingested"
                )
                malware.save()
                ingested.append(malware)
                logger.info(f"✅ Ingested: {filename}")

        logger.info(f"📥 Total ingested samples: {len(ingested)}")
        return ingested

    @staticmethod
    def process_dataset(dataset_path, limit=None):
        """
        Processes ingested samples: analysis + blockchain.
        Optionally limits the number of processed files.
        """
        logger.info("🚀 Starting full dataset processing...")
        ingested_samples = DatasetProcessor.ingest_dataset(dataset_path)
        processed = []
        count = 0

        for sample in ingested_samples:
            if limit and count >= limit:
                break
            logger.info(f"🧪 Processing {sample.filename}")
            result = MalwareService.analyze_malware(sample.id)
            if result:
                processed.append(result)
                count += 1

        logger.info(f"✅ Dataset processing complete. Processed: {len(processed)} samples.")
        return processed


# ------------------- Utility Functions ------------------- #
def get_collection(collection_name):
    """Get a MongoDB collection."""
    client = MongoClient(MONGODB_URI)  # Correct usage of MongoClient with MONGODB_URI
    db = client["maldna_db"]  # Use your database name
    return db[collection_name]
def update_sample_label(sample_id, new_label, updated_by):
    """Updates the label/classification of a sample."""
    from app.models.malwareModel import MalwareMetadata  # Lazy import to avoid circular import
    from mongoengine import DoesNotExist

    try:
        sample = MalwareMetadata.objects.get(id=sample_id)
        old_label = sample.label
        sample.label = new_label
        sample.label_updated_at = datetime.utcnow()
        sample.label_updated_by = updated_by
        sample.save()
        log_label_change(sample.filename, old_label, new_label, updated_by)
        logger.info(f"🔁 Label updated: {sample.filename} from '{old_label}' → '{new_label}'")
        return True
    except DoesNotExist:
        logger.error(f"❌ Sample not found with ID: {sample_id}")
        return False


def log_label_change(filename, old_label, new_label, updated_by):
    """Logs a label update for audit/history tracking."""
    log_msg = f"📝 Label change | File: {filename} | From: {old_label} → To: {new_label} | By: {updated_by} | At: {datetime.utcnow()}"
    logger.info(log_msg)
    # Optionally persist this log to MongoDB (e.g., AuditLog collection)


def log_dataset_version(dataset_name, description, author):
    """Logs dataset versioning metadata."""
    logger.info(f"📦 Dataset Version Logged | Dataset: {dataset_name} | Desc: {description} | By: {author} | At: {datetime.utcnow()}")
    # Optionally store this in a `DatasetVersion` collection if tracking versions


def get_sample_by_id(sample_id):
    """Fetches a sample by its MongoDB ObjectId."""
    from app.models.malwareModel import MalwareMetadata  # Lazy import to avoid circular import
    from mongoengine import DoesNotExist

    try:
        return MalwareMetadata.objects.get(id=sample_id)
    except DoesNotExist:
        logger.warning(f"⚠️ No sample found with ID: {sample_id}")
        return None


# ---------------------- CLI Support ---------------------- #

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="📦 Dataset Processor for MalDNA")
    parser.add_argument("--path", required=True, help="Path to dataset folder")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of samples to process")

    args = parser.parse_args()
    DatasetProcessor.process_dataset(args.path, args.limit)

