import os
import json
import logging
import argparse
from flask import Blueprint, request, jsonify, send_file
from app.services.report_generator import ReportGenerator
from app.utils.logging import logger
from app.utils.custom_exceptions import (
    CustomException, EntityNotFoundError, ReportGenerationError
)
from app.utils.rbac import require_role, UserRole, log_access_attempt
from app.models.userModel import User

# Initialize Blueprint and Report Generator
report_bp = Blueprint('report', __name__)
report_generator = ReportGenerator()

def handle_report_generation(generation_method, entity_id, output_format='pdf', report_type=None):
    """
    Centralized report generation handler with error management.
    """
    try:
        current_user_id = None  # No JWT required
        current_user = User.objects.get(id=current_user_id) if current_user_id else None

        report = generation_method(entity_id=entity_id, output_format=output_format)

        log_access_attempt(current_user, f'{report_type}_report', allowed=True)

        return jsonify({
            'message': f'{report_type.capitalize()} report generated successfully',
            'report': report
        }), 200

    except EntityNotFoundError as e:
        log_access_attempt(current_user, f'{report_type}_report', allowed=False)
        return jsonify({'error': str(e)}), 404

    except ReportGenerationError as e:
        log_access_attempt(current_user, f'{report_type}_report', allowed=False)
        return jsonify({'error': str(e)}), 500

    except CustomException as e:
        return jsonify({'error': str(e)}), 400

    except Exception as e:
        logger.error(f"Unexpected error in {report_type} report generation: {e}")
        return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500


# ✅ Malware Analysis Report
@report_bp.route('/reports/malware', methods=['POST'])
@require_role([UserRole.ADMIN, UserRole.SENIOR_ANALYST, UserRole.ANALYST])  # Keeping role-based access, but removing JWT
def generate_malware_report():
    data = request.json
    return handle_report_generation(
        generation_method=report_generator.generate_malware_report,
        entity_id=data.get('malware_id'),
        output_format=data.get('output_format', 'pdf'),
        report_type='malware'
    )


# ✅ Malware DNA Sequence Report
@report_bp.route('/reports/dna', methods=['POST'])
@require_role([UserRole.ADMIN, UserRole.ANALYST])  # Keeping role-based access, but removing JWT
def generate_dna_report():
    data = request.json
    return handle_report_generation(
        generation_method=report_generator.generate_dna_report,
        entity_id=data.get('dna_sequence_id'),
        output_format=data.get('output_format', 'pdf'),
        report_type='dna'
    )


# ✅ Forensic Investigation Report
@report_bp.route('/reports/forensic', methods=['POST'])
@require_role([UserRole.ADMIN, UserRole.SENIOR_ANALYST])  # Keeping role-based access, but removing JWT
def generate_forensic_report():
    data = request.json
    return handle_report_generation(
        generation_method=report_generator.generate_forensic_report,
        entity_id=data.get('case_id'),
        output_format=data.get('output_format', 'pdf'),
        report_type='forensic'
    )


# ✅ Threat Intelligence Report
@report_bp.route('/reports/threat', methods=['POST'])
@require_role([UserRole.ADMIN, UserRole.SENIOR_ANALYST])  # Keeping role-based access, but removing JWT
def generate_threat_intelligence_report():
    data = request.json
    return handle_report_generation(
        generation_method=report_generator.generate_threat_intelligence_report,
        entity_id=data.get('threat_id'),
        output_format=data.get('output_format', 'pdf'),
        report_type='threat'
    )


# ✅ Retrieve List of Reports
@report_bp.route('/reports/list', methods=['GET'])
def list_reports():
    try:
        current_user_id = None  # No JWT required
        current_user = User.objects.get(id=current_user_id) if current_user_id else None

        report_type = request.args.get('type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        reports = report_generator.list_reports(
            user=current_user,
            report_type=report_type,
            start_date=start_date,
            end_date=end_date
        )

        return jsonify({'reports': reports, 'total_count': len(reports)}), 200

    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({'error': 'Failed to retrieve reports', 'details': str(e)}), 500


# ✅ Download Report
@report_bp.route('/reports/download/<report_id>', methods=['GET'])
def download_report(report_id):
    try:
        report_format = request.args.get('format', 'pdf')

        report_path = report_generator.get_report_path(
            report_id=report_id,
            format=report_format
        )

        if not report_path:
            return jsonify({'error': 'Report not found'}), 404

        return send_file(report_path, as_attachment=True, download_name=f'report_{report_id}.{report_format}')

    except Exception as e:
        logger.error(f"Report download error: {e}")
        return jsonify({'error': 'Failed to download report', 'details': str(e)}), 500


# ✅ Report Analytics Overview
@report_bp.route('/reports/analytics', methods=['GET'])
@require_role([UserRole.ADMIN])  # Keeping role-based access, but removing JWT
def fetch_report_analytics():
    try:
        current_user_id = None  # No JWT required
        current_user = User.objects.get(id=current_user_id) if current_user_id else None

        analytics_data = report_generator.fetch_report_analytics(user=current_user)

        return jsonify({
            'message': 'Analytics data retrieved successfully',
            'analytics': analytics_data
        }), 200

    except Exception as e:
        logger.error(f"Error fetching report analytics: {e}")
        return jsonify({'error': 'Failed to retrieve analytics', 'details': str(e)}), 500


# ---------------------------- CLI FUNCTIONALITY ---------------------------- #

def cli_generate_report(report_type, entity_id, output_format='pdf'):
    try:
        report_methods = {
            "malware": report_generator.generate_malware_report,
            "dna": report_generator.generate_dna_report,
            "forensic": report_generator.generate_forensic_report,
            "threat": report_generator.generate_threat_intelligence_report
        }

        if report_type not in report_methods:
            print(f"[❌] Invalid report type: {report_type}")
            return

        report = report_methods[report_type](entity_id=entity_id, output_format=output_format)
        print(f"[✔] {report_type.capitalize()} report generated successfully: {report}")

    except Exception as e:
        print(f"[❌] Report generation failed: {e}")


def cli_list_reports(report_type=None, start_date=None, end_date=None):
    try:
        reports = report_generator.list_reports(
            user=None,
            report_type=report_type,
            start_date=start_date,
            end_date=end_date
        )
        print(json.dumps(reports, indent=4))

    except Exception as e:
        print(f"[❌] Failed to retrieve reports: {e}")


def cli_download_report(report_id, output_format='pdf'):
    try:
        report_path = report_generator.get_report_path(report_id=report_id, format=output_format)

        if not report_path:
            print("[❌] Report not found.")
            return

        destination = f"./downloaded_report_{report_id}.{output_format}"
        os.system(f"cp {report_path} {destination}")

        print(f"[✔] Report downloaded: {destination}")

    except Exception as e:
        print(f"[❌] Report download failed: {e}")


# ---------------------------- CLI HANDLER ---------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Report Management CLI")
    parser.add_argument("--generate", nargs=2, metavar=("REPORT_TYPE", "ENTITY_ID"), help="Generate a report")
    parser.add_argument("--list", nargs="?", const=True, help="List all reports")
    parser.add_argument("--download", metavar="REPORT_ID", help="Download a report")

    args = parser.parse_args()

    if args.generate:
        cli_generate_report(args.generate[0], args.generate[1])
    elif args.list:
        cli_list_reports()
    elif args.download:
        cli_download_report(args.download)
    else:
        print("[❌] Invalid CLI command.")

