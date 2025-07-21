from bson import ObjectId
from pymongo import DESCENDING
from datetime import datetime
from app.models.dataset_model import get_collection
from app.services.malwareService import analyze_sample_and_store
from app.utils.blockchainUtils import store_on_blockchain

# Collections
datasets_collection = get_collection("datasets")
samples_collection = get_collection("samples")
labels_log_collection = get_collection("labels_log")
dataset_versions_collection = get_collection("dataset_versions")


def list_datasets():
    datasets = list(datasets_collection.find({}, {"_id": 1, "name": 1, "description": 1, "created_at": 1}))
    for dataset in datasets:
        dataset["_id"] = str(dataset["_id"])
    return datasets


def add_sample_to_dataset(dataset_id, sample_id):
    dataset = datasets_collection.find_one({"_id": ObjectId(dataset_id)})
    if not dataset:
        raise ValueError("Dataset not found")

    if sample_id in dataset.get("samples", []):
        raise ValueError("Sample already exists in dataset")

    # Add the sample
    datasets_collection.update_one(
        {"_id": ObjectId(dataset_id)},
        {"$addToSet": {"samples": sample_id}, "$set": {"updated_at": datetime.utcnow()}}
    )
    log_version(dataset_id)

    # Automatically trigger malware analysis
    try:
        analysis_result = analyze_sample_and_store(sample_id)
    except Exception as e:
        raise RuntimeError(f"Failed to analyze sample: {str(e)}")

    # Automatically store result on blockchain
    try:
        store_on_blockchain(sample_id, analysis_result)
    except Exception as e:
        raise RuntimeError(f"Failed to store sample on blockchain: {str(e)}")

    return "Sample added, analyzed, and stored on blockchain successfully"


def remove_sample_from_dataset(dataset_id, sample_id):
    datasets_collection.update_one(
        {"_id": ObjectId(dataset_id)},
        {"$pull": {"samples": sample_id}, "$set": {"updated_at": datetime.utcnow()}}
    )
    log_version(dataset_id)
    return "Sample removed from dataset"


def label_sample(sample_id, label):
    timestamp = datetime.utcnow()
    samples_collection.update_one(
        {"_id": ObjectId(sample_id)},
        {"$set": {"label": label, "labeled_at": timestamp}}
    )
    labels_log_collection.insert_one({
        "sample_id": ObjectId(sample_id),
        "label": label,
        "timestamp": timestamp
    })
    return "Sample labeled and logged"


def export_dataset_by_id(dataset_id):
    dataset = datasets_collection.find_one({"_id": ObjectId(dataset_id)})
    if not dataset:
        raise ValueError("Dataset not found")

    sample_ids = dataset.get("samples", [])
    samples = list(samples_collection.find({"_id": {"$in": [ObjectId(sid) for sid in sample_ids]}}))

    for sample in samples:
        sample["_id"] = str(sample["_id"])
        sample["dataset_id"] = dataset_id

    return {"dataset": dataset_id, "samples": samples}


def fetch_samples_from_collection(collection_name, query={}):
    """Fetch samples from a MongoDB collection based on query."""
    collection = get_collection(collection_name)
    samples = list(collection.find(query))
    for s in samples:
        s["_id"] = str(s["_id"])
    return samples


def get_label_history(sample_id):
    history = list(labels_log_collection.find({"sample_id": ObjectId(sample_id)}).sort("timestamp", DESCENDING))
    for h in history:
        h["_id"] = str(h["_id"])
        h["sample_id"] = str(h["sample_id"])
    return history


def log_version(dataset_id):
    dataset = datasets_collection.find_one({"_id": ObjectId(dataset_id)})
    if not dataset:
        return
    dataset["_id"] = str(dataset["_id"])
    dataset_versions_collection.insert_one({
        "dataset_id": dataset["_id"],
        "snapshot": dataset,
        "timestamp": datetime.utcnow()
    })


# ✅ Add this utility function so it can be imported
def version_dataset(dataset: dict) -> dict:
    """
    Create a versioned snapshot of the dataset with a version field.
    This is useful for tracking dataset changes over time.
    """
    versioned = dataset.copy()
    versioned["versioned_at"] = datetime.utcnow().isoformat()
    versioned["version_tag"] = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    return versioned

