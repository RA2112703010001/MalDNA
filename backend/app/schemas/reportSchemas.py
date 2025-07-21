import os
import json
import logging
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

# Pydantic for Schema Validation
from pydantic import BaseModel, Field, validator

# MongoDB Integration
from mongoengine import Document, StringField, DateTimeField, DictField, ListField

# PDF Generation
from weasyprint import HTML

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 🎯 **Report Metadata Schema**
# --------------------------------------------
class ReportMetadataSchema(BaseModel):
    """Pydantic schema for report metadata"""
    report_id: str = Field(..., description="Unique identifier for the report")
    generation_timestamp: datetime = Field(default_factory=datetime.utcnow)
    report_type: str = Field(..., description="Type of report")
    output_format: str = Field(default='html', description="Output format of the report")

# --------------------------------------------
# 📌 **MongoDB Report Storage**
# --------------------------------------------
class ReportStorage(Document):
    """
    MongoDB model for storing generated malware reports.
    """
    report_id = StringField(primary_key=True, required=True)
    report_type = StringField(required=True)
    generation_timestamp = DateTimeField(default=datetime.utcnow)
    output_format = StringField(default="html")
    content = DictField(required=True)

    meta = {
        "collection": "malware_reports",
        "indexes": ["report_id", "report_type", "-generation_timestamp"]
    }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert report storage object to dictionary.
        """
        return {
            "report_id": self.report_id,
            "report_type": self.report_type,
            "generation_timestamp": self.generation_timestamp.isoformat(),
            "output_format": self.output_format,
            "content": self.content
        }

# --------------------------------------------
# 📌 **Report Generation Utility**
# --------------------------------------------
def generate_report(report_type: str, entity_id: str, output_format: str = "html") -> Dict[str, Any]:
    """
    Generate a malware analysis report and store it in MongoDB.
    """
    logger.info(f"🚀 Generating {report_type} report for Entity ID: {entity_id}...")

    # Simulated Report Content
    report_content = {
        "entity_id": entity_id,
        "findings": "Malware analysis findings go here...",
        "recommendations": ["Update antivirus", "Patch vulnerabilities", "Monitor network traffic"],
        "risk_assessment": {"severity": "high", "score": 85}
    }

    # Store in MongoDB
    report_id = f"{report_type}_{entity_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    report_storage = ReportStorage(
        report_id=report_id,
        report_type=report_type,
        output_format=output_format,
        content=report_content
    )
    report_storage.save()

    # Export Report
    if output_format == "pdf":
        export_report_to_pdf(report_storage.to_dict())

    return report_storage.to_dict()

# --------------------------------------------
# 📌 **Bulk Report Retrieval**
# --------------------------------------------
def retrieve_reports(report_type: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve stored malware analysis reports.
    """
    logger.info(f"📄 Retrieving last {limit} reports...")

    query = {}
    if report_type:
        query["report_type"] = report_type

    reports = ReportStorage.objects(**query).order_by("-generation_timestamp")[:limit]
    return [report.to_dict() for report in reports]

# --------------------------------------------
# 📌 **Report Export to PDF**
# --------------------------------------------
def export_report_to_pdf(report_data: Dict[str, Any], output_dir: str = "reports"):
    """
    Convert a report to a PDF file.
    """
    os.makedirs(output_dir, exist_ok=True)
    pdf_filename = f"{report_data['report_id']}.pdf"
    pdf_path = os.path.join(output_dir, pdf_filename)

    html_content = f"""
    <html>
    <head><title>{report_data['report_type']} Report</title></head>
    <body>
        <h1>{report_data['report_type']} Report</h1>
        <p><strong>Generated At:</strong> {report_data['generation_timestamp']}</p>
        <h2>Findings</h2>
        <p>{report_data['content']['findings']}</p>
        <h2>Recommendations</h2>
        <ul>
            {''.join(f"<li>{rec}</li>" for rec in report_data['content']['recommendations'])}
        </ul>
        <h2>Risk Assessment</h2>
        <p><strong>Severity:</strong> {report_data['content']['risk_assessment']['severity']}</p>
        <p><strong>Risk Score:</strong> {report_data['content']['risk_assessment']['score']}</p>
    </body>
    </html>
    """

    HTML(string=html_content).write_pdf(pdf_path)
    logger.info(f"✅ Report exported to {pdf_path}")

    return pdf_path

# --------------------------------------------
# 🔥 **CLI Argument Parser**
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Report Automation")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 📌 Generate Report
    generate_parser = subparsers.add_parser("generate", help="Generate a new report")
    generate_parser.add_argument("--report_type", required=True, help="Type of report (e.g., forensic, ransomware, threat_intel)")
    generate_parser.add_argument("--entity_id", required=True, help="Entity ID for which report is generated")
    generate_parser.add_argument("--output_format", default="html", choices=["html", "pdf"], help="Report output format")

    # 📌 Retrieve Reports
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve stored reports")
    retrieve_parser.add_argument("--report_type", help="Filter by report type")
    retrieve_parser.add_argument("--limit", type=int, default=10, help="Number of reports to retrieve")

    args = parser.parse_args()

    # Execute Command
    if args.command == "generate":
        report = generate_report(args.report_type, args.entity_id, args.output_format)
        print(json.dumps(report, indent=4))

    elif args.command == "retrieve":
        reports = retrieve_reports(args.report_type, args.limit)
        print(json.dumps(reports, indent=4))

