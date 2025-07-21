import os
import json
import logging
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field, validator

# MongoDB Integration
from mongoengine import (
    Document, StringField, DateTimeField, DictField, ListField, FloatField, BooleanField, ValidationError
)

# AI Prediction Service (Mocked for Now)
from app.services.aiThreatPrediction import ai_prediction_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Real-time Detection Event Schema**
# --------------------------------------------
class RealtimeDetectionSchema(BaseModel):
    """Pydantic schema for real-time detection event validation"""
    event_id: str = Field(..., description="Unique identifier for the event")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str = Field(..., description="Source IP address of the event")
    destination_ip: str = Field(..., description="Destination IP address of the event")
    event_type: str = Field(..., description="Type of event detected")
    risk_score: float = Field(..., ge=0, le=100, description="Risk score (0-100)")
    is_malicious: bool = Field(default=False, description="Indicates if the event is malicious")
    anomaly_detected: bool = Field(default=False, description="Indicates if an anomaly was detected")

    @validator("event_id")
    def validate_event_id(cls, v):
        """Ensure event ID is valid"""
        if len(v) < 8:
            raise ValueError("Invalid event ID")
        return v

# --------------------------------------------
# 📌 **MongoDB Model for Real-time Detection**
# --------------------------------------------
class RealtimeDetection(Document):
    """
    MongoDB model for storing real-time detection logs.
    """
    event_id = StringField(primary_key=True, required=True)
    timestamp = DateTimeField(default=datetime.utcnow)
    source_ip = StringField(required=True)
    destination_ip = StringField(required=True)
    event_type = StringField(required=True)
    risk_score = FloatField(default=0.0)
    is_malicious = BooleanField(default=False)
    anomaly_detected = BooleanField(default=False)

    ai_prediction = DictField(default={})

    meta = {
        "collection": "realtime_detection",
        "indexes": ["event_id", "-timestamp", "is_malicious"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert real-time detection record to dictionary.
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "event_type": self.event_type,
            "risk_score": self.risk_score,
            "is_malicious": self.is_malicious,
            "anomaly_detected": self.anomaly_detected,
            "ai_prediction": self.ai_prediction
        }

# --------------------------------------------
# 📌 **AI-assisted Threat Prediction Schema**
# --------------------------------------------
class AIThreatPredictionSchema(BaseModel):
    """Pydantic schema for AI-assisted threat predictions"""
    event_id: str = Field(..., description="Unique identifier for the event")
    predicted_threat_type: str = Field(..., description="Predicted type of threat")
    confidence_score: float = Field(..., ge=0, le=1, description="AI model confidence score")
    recommended_action: str = Field(..., description="AI-suggested mitigation action")

# --------------------------------------------
# 🔥 **CLI Utility for Real-time Detection**
# --------------------------------------------
def store_realtime_detection(event_id: str, source_ip: str, destination_ip: str, event_type: str, risk_score: float, is_malicious: bool = False, anomaly_detected: bool = False) -> Dict[str, Any]:
    """
    Store real-time detection event in the database.
    """
    logger.info(f"🚀 Storing real-time detection event {event_id}...")

    # Validate Using Pydantic Schema
    event_data = RealtimeDetectionSchema(
        event_id=event_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        event_type=event_type,
        risk_score=risk_score,
        is_malicious=is_malicious,
        anomaly_detected=anomaly_detected
    )

    # Store in MongoDB
    detection_record = RealtimeDetection(
        event_id=event_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        event_type=event_type,
        risk_score=risk_score,
        is_malicious=is_malicious,
        anomaly_detected=anomaly_detected
    )
    detection_record.save()

    logger.info(f"✅ Real-time detection event stored successfully")
    return detection_record.to_dict()

# --------------------------------------------
# 📌 **Retrieve Real-time Detection Events**
# --------------------------------------------
def retrieve_realtime_detection(event_id: str) -> Dict[str, Any]:
    """
    Retrieve real-time detection event data.
    """
    logger.info(f"📄 Retrieving real-time detection event {event_id}...")

    detection_record = RealtimeDetection.objects(event_id=event_id).first()
    if not detection_record:
        return {"error": "Real-time detection event not found"}

    return detection_record.to_dict()

# --------------------------------------------
# 📌 **AI-assisted Threat Prediction**
# --------------------------------------------
def ai_assisted_threat_prediction(event_id: str) -> Dict[str, Any]:
    """
    Perform AI-based threat prediction on a real-time detection event.
    """
    logger.info(f"🔍 Running AI-based threat prediction for event {event_id}...")

    detection_record = RealtimeDetection.objects(event_id=event_id).first()
    if not detection_record:
        return {"error": "Event not found for AI prediction"}

    # AI Prediction (Mocked for Now)
    prediction_result = ai_prediction_service.predict(detection_record.to_dict())

    # Validate AI Prediction Schema
    AIThreatPredictionSchema(
        event_id=event_id,
        predicted_threat_type=prediction_result["predicted_threat_type"],
        confidence_score=prediction_result["confidence_score"],
        recommended_action=prediction_result["recommended_action"]
    )

    # Store AI Prediction
    detection_record.ai_prediction = prediction_result
    detection_record.save()

    logger.info(f"✅ AI-assisted threat prediction stored for event {event_id}")
    return detection_record.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time Detection Management")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Store Real-time Detection Event
    store_parser = subparsers.add_parser("store", help="Store real-time detection event")
    store_parser.add_argument("--event_id", required=True, help="Event ID")
    store_parser.add_argument("--source_ip", required=True, help="Source IP")
    store_parser.add_argument("--destination_ip", required=True, help="Destination IP")
    store_parser.add_argument("--event_type", required=True, help="Type of event detected")
    store_parser.add_argument("--risk_score", type=float, required=True, help="Risk score (0-100)")
    store_parser.add_argument("--is_malicious", action="store_true", help="Flag if event is malicious")
    store_parser.add_argument("--anomaly_detected", action="store_true", help="Flag if anomaly was detected")

    # 📌 Retrieve Real-time Detection Event
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve real-time detection event")
    retrieve_parser.add_argument("--event_id", required=True, help="Event ID")

    # 📌 AI-assisted Threat Prediction
    ai_parser = subparsers.add_parser("predict", help="AI-assisted threat prediction")
    ai_parser.add_argument("--event_id", required=True, help="Event ID for AI prediction")

    args = parser.parse_args()

    # Execute Command
    if args.command == "store":
        detection_record = store_realtime_detection(
            args.event_id, args.source_ip, args.destination_ip, args.event_type, args.risk_score, args.is_malicious, args.anomaly_detected
        )
        print(json.dumps(detection_record, indent=4))

    elif args.command == "retrieve":
        detection_data = retrieve_realtime_detection(args.event_id)
        print(json.dumps(detection_data, indent=4))

    elif args.command == "predict":
        prediction_data = ai_assisted_threat_prediction(args.event_id)
        print(json.dumps(prediction_data, indent=4))
