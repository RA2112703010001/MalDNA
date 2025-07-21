import csv
import json
import logging
import argparse
from io import StringIO
from datetime import datetime
from flask import Blueprint, request, jsonify, make_response, Response
from flask_cors import cross_origin
from app.models.userModel import User
from app.utils.logging import LoggingService
from app.utils.permissions import PermissionService

# Blueprint
audit_bp = Blueprint("audit", __name__, url_prefix="/api/audit")
logger = logging.getLogger(__name__)

# ---------------------------- GET AUDIT LOGS ---------------------------- #
@audit_bp.route("/logs", methods=["GET"], endpoint="get_audit_logs")
@cross_origin(origins="http://127.0.0.1:8080", supports_credentials=True)
def get_audit_logs():
    """Retrieve audit logs with optional filtering and pagination."""
    try:
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        filter_user_id = request.args.get("user_id")
        action = request.args.get("action")
        resource_type = request.args.get("resource_type")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))

        start_date = datetime.fromisoformat(start_date_str) if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str) if end_date_str else None

        logs = LoggingService.get_audit_logs(
            user_id=filter_user_id, action=action, resource_type=resource_type,
            start_date=start_date, end_date=end_date, limit=None
        )

        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        paginated_logs = logs[start_index:end_index]

        # Note: No user filtering is required in this modified code, so it's omitted.

        response_data = {
            "logs": [log.to_dict() for log in paginated_logs],
            "total_logs": len(logs),
            "page": page,
            "per_page": per_page,
            "total_pages": (len(logs) + per_page - 1) // per_page,
        }

        return make_response(jsonify(response_data), 200)

    except Exception as e:
        logger.error(f"❌ Failed to retrieve audit logs: {e}")
        return jsonify({"error": "Failed to retrieve audit logs", "details": str(e)}), 500


# ---------------------------- EXPORT AUDIT LOGS ---------------------------- #
@audit_bp.route("/logs/export", methods=["GET"], endpoint="export_audit_logs")
@cross_origin(origins="http://127.0.0.1:8080", supports_credentials=True)
def export_audit_logs():
    """Export audit logs as JSON or CSV files."""
    try:
        export_format = request.args.get("format", "json")
        start_date = datetime.fromisoformat(request.args.get("start_date")) if request.args.get("start_date") else None
        end_date = datetime.fromisoformat(request.args.get("end_date")) if request.args.get("end_date") else None

        logs = LoggingService.get_audit_logs(start_date=start_date, end_date=end_date)

        if export_format == "csv":
            csv_output = StringIO()
            writer = csv.writer(csv_output)
            writer.writerow(["ID", "User ID", "Username", "Action", "Resource Type", "Resource ID", "Timestamp", "Status", "Details"])
            for log in logs:
                writer.writerow([
                    log.id, log.user_id, log.username, log.action,
                    log.resource_type, log.resource_id, log.timestamp, log.status, log.details
                ])
            response = Response(csv_output.getvalue(), mimetype="text/csv")
            response.headers["Content-Disposition"] = "attachment; filename=audit_logs.csv"
            return response

        else:
            export_data = [log.to_dict() for log in logs]
            response = make_response(jsonify(export_data), 200)
            response.headers["Access-Control-Allow-Origin"] = "http://127.0.0.1:8080"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response

    except Exception as e:
        logger.error(f"❌ Failed to export audit logs: {e}")
        return jsonify({"error": "Failed to export audit logs", "details": str(e)}), 500


# ---------------------------- GET AUDIT LOG ANALYTICS ---------------------------- #
@audit_bp.route("/logs/analytics", methods=["GET"], endpoint="get_audit_log_analytics")
@cross_origin(origins="http://127.0.0.1:8080", supports_credentials=True)
def get_audit_log_analytics():
    """Return time-series system activity stats."""
    try:
        analytics_data = LoggingService.get_activity_analytics()
        return jsonify({"analytics": analytics_data}), 200
    except Exception as e:
        logger.error(f"❌ Failed to fetch audit analytics: {e}")
        return jsonify({"error": "Failed to fetch analytics", "details": str(e)}), 500


# ---------------------------- CLI FUNCTIONS ---------------------------- #
def cli_export_audit_logs(format="json", start_date=None, end_date=None):
    try:
        logs = LoggingService.get_audit_logs(start_date=start_date, end_date=end_date)

        if format == "csv":
            with open("audit_logs.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "User ID", "Username", "Action", "Resource Type", "Resource ID", "Timestamp", "Status", "Details"])
                for log in logs:
                    writer.writerow([
                        log.id, log.user_id, log.username, log.action,
                        log.resource_type, log.resource_id, log.timestamp, log.status, log.details
                    ])
            print("[✔] Audit logs exported to audit_logs.csv")
        else:
            with open("audit_logs.json", "w") as f:
                json.dump([log.to_dict() for log in logs], f, indent=4)
            print("[✔] Audit logs exported to audit_logs.json")
    except Exception as e:
        print(f"[❌] Failed to export logs: {e}")


def cli_detect_security_anomalies():
    try:
        anomalies = LoggingService.detect_security_anomalies()
        print("[✔] Security anomaly detection completed.")
        print(json.dumps(anomalies, indent=4))
    except Exception as e:
        print(f"[❌] Security anomaly detection failed: {e}")


# ---------------------------- CLI HANDLER ---------------------------- #
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit Log CLI Utility")
    parser.add_argument("--export", help="Export audit logs (json/csv)", type=str)
    parser.add_argument("--start-date", help="Start date for filtering logs", type=str)
    parser.add_argument("--end-date", help="End date for filtering logs", type=str)
    parser.add_argument("--detect-anomalies", help="Run security anomaly detection", action="store_true")
    args = parser.parse_args()

    if args.export:
        cli_export_audit_logs(args.export, args.start_date, args.end_date)
    elif args.detect_anomalies:
        cli_detect_security_anomalies()
    else:
        logger.error("❌ Invalid CLI Arguments")

