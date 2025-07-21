from bson import ObjectId
from datetime import datetime
from app.utils.datasetUtils import get_collection


# MongoDB Collections
datasets_collection = get_collection("datasets")
samples_collection = get_collection("samples")
labels_log_collection = get_collection("labels_log")
dataset_versions_collection = get_collection("dataset_versions")

# Dataset Operations

def get_dataset_by_id(dataset_id):
    return datasets_collection.find_one({"_id": ObjectId(dataset_id)})

def get_all_datasets():
    datasets = list(datasets_collection.find())
    for d in datasets:
        d["_id"] = str(d["_id"])
    return datasets

def insert_dataset(name, description, samples=None):
    now = datetime.utcnow()
    dataset = {
        "name": name,
        "description": description,
        "samples": samples or [],
        "created_at": now,
        "updated_at": now
    }
    result = datasets_collection.insert_one(dataset)
    return str(result.inserted_id)

def delete_dataset(dataset_id):
    return datasets_collection.delete_one({"_id": ObjectId(dataset_id)})

def update_dataset_samples(dataset_id, sample_id, action="add"):
    update_op = {"$addToSet": {"samples": sample_id}} if action == "add" else {"$pull": {"samples": sample_id}}
    update_op["$set"] = {"updated_at": datetime.utcnow()}
    result = datasets_collection.update_one({"_id": ObjectId(dataset_id)}, update_op)
    
    if action == "add":
        # Log version after modification
        log_dataset_version(dataset_id)
        
        # Automatically analyze the sample
        try:
            analysis_result = analyze_sample_and_store(sample_id)
        except Exception as e:
            raise RuntimeError(f"Analysis failed for sample {sample_id}: {str(e)}")
        
        # Store on blockchain
        try:
            store_on_blockchain(sample_id, analysis_result)
        except Exception as e:
            raise RuntimeError(f"Blockchain storage failed for sample {sample_id}: {str(e)}")

    return result

# Sample Operations

def insert_sample(data):
    result = samples_collection.insert_one(data)
    return str(result.inserted_id)

def get_sample_by_id(sample_id):
    return samples_collection.find_one({"_id": ObjectId(sample_id)})

def get_samples_by_ids(sample_ids):
    object_ids = [ObjectId(sid) for sid in sample_ids]
    samples = list(samples_collection.find({"_id": {"$in": object_ids}}))
    for s in samples:
        s["_id"] = str(s["_id"])
    return samples

def delete_sample(sample_id):
    return samples_collection.delete_one({"_id": ObjectId(sample_id)})

def update_sample_label(sample_id, label):
    return samples_collection.update_one(
        {"_id": ObjectId(sample_id)},
        {"$set": {"label": label, "labeled_at": datetime.utcnow()}}
    )

# Label History

def log_label_change(sample_id, label):
    timestamp = datetime.utcnow()
    labels_log_collection.insert_one({
        "sample_id": ObjectId(sample_id),
        "label": label,
        "timestamp": timestamp
    })

def get_label_history(sample_id):
    history = list(labels_log_collection.find({"sample_id": ObjectId(sample_id)}).sort("timestamp", -1))
    for h in history:
        h["_id"] = str(h["_id"])
        h["sample_id"] = str(h["sample_id"])
    return history

# Dataset Versioning

def log_dataset_version(dataset_id):
    dataset = get_dataset_by_id(dataset_id)
    if not dataset:
        return
    snapshot = dataset.copy()
    snapshot["_id"] = str(snapshot["_id"])
    dataset_versions_collection.insert_one({
        "dataset_id": str(dataset_id),
        "snapshot": snapshot,
        "timestamp": datetime.utcnow()
    })

def get_dataset_version_history(dataset_id):
    history = list(dataset_versions_collection.find({"dataset_id": str(dataset_id)}).sort("timestamp", -1))
    for h in history:
        h["_id"] = str(h["_id"])
    return history

