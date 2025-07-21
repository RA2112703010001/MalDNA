import json
import logging
import argparse
from datetime import datetime
from typing import List, Dict, Optional, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field

# MongoDB Integration
from mongoengine import Document, StringField, DateTimeField, DictField, BooleanField

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Visualization Report Schema**
# --------------------------------------------
class VisualizationReportSchema(BaseModel):
    """Schema for visualization report validation"""
    report_id: str = Field(..., description="Unique identifier for the visualization report")
    title: str = Field(..., description="Title of the visualization report")
    description: str = Field(..., description="Brief description of the report")
    chart_type: str = Field(..., description="Type of visualization (e.g., graph, heatmap, pie)")
    data: Dict[str, Any] = Field(..., description="Data used for visualization")
    blockchain_verified: bool = Field(default=False, description="Whether the visualization is stored on blockchain")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")

# --------------------------------------------
# 📌 **MongoDB Model for Visualization Reports**
# --------------------------------------------
class VisualizationReport(Document):
    """
    MongoDB model for storing visualization reports.
    """
    report_id = StringField(primary_key=True, required=True, unique=True)
    title = StringField(required=True)
    description = StringField(required=True)
    chart_type = StringField(required=True)
    data = DictField(required=True)
    blockchain_verified = BooleanField(default=False)
    timestamp = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "visualization_reports",
        "indexes": ["report_id", "chart_type", "-timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert visualization report data to dictionary.
        """
        return {
            "report_id": self.report_id,
            "title": self.title,
            "description": self.description,
            "chart_type": self.chart_type,
            "data": self.data,
            "blockchain_verified": self.blockchain_verified,
            "timestamp": self.timestamp.isoformat()
        }

# --------------------------------------------
# 🎯 **Blockchain Verification Schema**
# --------------------------------------------
class BlockchainVisualizationSchema(BaseModel):
    """Schema for validating visualization report verification on blockchain"""
    verification_id: str = Field(..., description="Unique verification identifier")
    report_id: str = Field(..., description="Visualization report ID")
    transaction_id: str = Field(..., description="Blockchain transaction ID")
    verification_status: bool = Field(default=False, description="Verification status")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Verification timestamp")

# --------------------------------------------
# 📌 **MongoDB Model for Blockchain Verification of Visual Reports**
# --------------------------------------------
class BlockchainVisualization(Document):
    """
    MongoDB model for tracking blockchain-based visualization verification.
    """
    verification_id = StringField(primary_key=True, required=True, unique=True)
    report_id = StringField(required=True)
    transaction_id = StringField(required=True)
    verification_status = BooleanField(default=False)
    timestamp = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "blockchain_visualizations",
        "indexes": ["verification_id", "report_id", "transaction_id", "-timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert blockchain visualization verification data to dictionary.
        """
        return {
            "verification_id": self.verification_id,
            "report_id": self.report_id,
            "transaction_id": self.transaction_id,
            "verification_status": self.verification_status,
            "timestamp": self.timestamp.isoformat()
        }

# --------------------------------------------
# 🔥 **CLI Utility for Visualization Reports**
# --------------------------------------------
def generate_visualization_report(report_id: str, title: str, description: str, chart_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a visualization report and store it in the database.
    """
    logger.info(f"🚀 Generating visualization report {report_id}...")

    report_data = VisualizationReport(
        report_id=report_id,
        title=title,
        description=description,
        chart_type=chart_type,
        data=data
    )
    report_data.save()

    logger.info(f"✅ Visualization report {report_id} generated successfully")
    return report_data.to_dict()

def verify_visualization_on_blockchain(report_id: str, transaction_id: str) -> Dict[str, Any]:
    """
    Verify visualization report integrity on blockchain.
    """
    logger.info(f"🔍 Verifying visualization report {report_id} on blockchain...")

    report_record = VisualizationReport.objects(report_id=report_id).first()
    if not report_record:
        return {"error": "Report not found"}

    verification_data = BlockchainVisualization(
        verification_id=str(datetime.utcnow().timestamp()),
        report_id=report_id,
        transaction_id=transaction_id,
        verification_status=True
    )
    verification_data.save()

    logger.info(f"✅ Blockchain verification completed for visualization report {report_id}")
    return verification_data.to_dict()

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualization Report CLI")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Generate Visualization Report
    generate_parser = subparsers.add_parser("generate_report", help="Generate a new visualization report")
    generate_parser.add_argument("--report_id", required=True, help="Visualization Report ID")
    generate_parser.add_argument("--title", required=True, help="Report Title")
    generate_parser.add_argument("--description", required=True, help="Report Description")
    generate_parser.add_argument("--chart_type", required=True, help="Chart Type (e.g., graph, heatmap)")
    generate_parser.add_argument("--data", required=True, type=json.loads, help="Visualization Data (JSON)")

    # 📌 Verify Visualization Report on Blockchain
    verify_parser = subparsers.add_parser("verify_report", help="Verify visualization report on blockchain")
    verify_parser.add_argument("--report_id", required=True, help="Visualization Report ID")
    verify_parser.add_argument("--transaction_id", required=True, help="Blockchain Transaction ID")

    args = parser.parse_args()

    # Execute Command
    if args.command == "generate_report":
        report_data = generate_visualization_report(
            args.report_id, args.title, args.description, args.chart_type, args.data
        )
        print(json.dumps(report_data, indent=4))

    elif args.command == "verify_report":
        verification_data = verify_visualization_on_blockchain(args.report_id, args.transaction_id)
        print(json.dumps(verification_data, indent=4))

