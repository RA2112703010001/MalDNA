import os
import json
import uuid
import argparse
import zipfile
import webbrowser
from datetime import datetime
from typing import Dict, Any, Optional, List

import numpy as np
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

from app.models.malwareModel import MalwareModel
from app.models.dnaModel import DNAModel
from app.models.threatModel import ThreatIntel, ThreatEvent

import logging
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import threading

# ---------------------------- LOGGER SETUP ---------------------------- #
LOG_FILE = 'logs/report_generator.log'
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Advanced Report Generator with logging, preview, zipping, and auto-open support.
    """

    def __init__(self, templates_dir: str = 'templates', output_dir: str = 'reports', bundle_dir: str = 'bundles'):
        self.templates_dir = templates_dir
        self.output_dir = output_dir
        self.bundle_dir = bundle_dir

        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.bundle_dir, exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=True
        )

    def generate_report(self, report_type: str, entity_id: str, output_format: str = 'html', auto_open: bool = False, preview: bool = False) -> Dict[str, str]:
        try:
            if report_type == 'malware':
                entity = MalwareModel.objects.get(id=entity_id)
                template_file = 'malwareReport.html'
            elif report_type == 'dna':
                entity = DNAModel.objects.get(id=entity_id)
                template_file = 'dnaReport.html'
            elif report_type == 'forensic':
                entity = ThreatEvent.objects.get(id=entity_id)
                template_file = 'forensicReport.html'
            elif report_type == 'threat':
                entity = ThreatIntel.objects.get(id=entity_id)
                template_file = 'threatReport.html'
            else:
                raise ValueError("Invalid report type specified.")

            context = self._prepare_report_context(entity, report_type)
            template = self.jinja_env.get_template(template_file)
            rendered_report = template.render(**context)

            report_id = str(uuid.uuid4())
            report_paths = self._save_report(report_id, rendered_report, output_format)
            bundle_path = self._create_zip_bundle(report_id, report_paths)

            if auto_open:
                webbrowser.open(f"file://{report_paths['html']}")

            if preview:
                self._launch_preview_server()

            logger.info(f"Successfully generated report ID: {report_id} for {report_type}")
            return {'report_id': report_id, 'paths': report_paths, 'bundle': bundle_path, 'metadata': context}

        except Exception as e:
            logger.error(f"Error generating {report_type} report: {e}")
            raise

    def list_reports(self, report_type: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, str]]:
        try:
            report_files = os.listdir(self.output_dir)
            filtered_reports = []

            for report in report_files:
                report_path = os.path.join(self.output_dir, report)
                if os.path.isfile(report_path):
                    report_data = {
                        'report_id': report.split('_')[0],
                        'report_name': report,
                        'generated_at': datetime.fromtimestamp(os.path.getctime(report_path)).isoformat(),
                        'format': report.split('.')[-1]
                    }

                    if report_type and report_type not in report:
                        continue
                    if start_date and datetime.fromisoformat(report_data['generated_at']) < datetime.fromisoformat(start_date):
                        continue
                    if end_date and datetime.fromisoformat(report_data['generated_at']) > datetime.fromisoformat(end_date):
                        continue

                    filtered_reports.append(report_data)

            return filtered_reports

        except Exception as e:
            logger.error(f"Error retrieving report list: {e}")
            return []

    def get_report_path(self, report_id: str, format: str) -> Optional[str]:
        try:
            report_filename = f"{report_id}_report.{format}"
            report_path = os.path.join(self.output_dir, report_filename)
            return report_path if os.path.exists(report_path) else None
        except Exception as e:
            logger.error(f"Error fetching report path: {e}")
            return None

    def _save_report(self, report_id: str, rendered_report: str, output_format: str) -> Dict[str, str]:
        report_paths = {}

        html_path = os.path.join(self.output_dir, f'{report_id}_report.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(rendered_report)
        report_paths['html'] = html_path

        if output_format == 'pdf':
            pdf_path = os.path.join(self.output_dir, f'{report_id}_report.pdf')
            HTML(string=rendered_report).write_pdf(
                pdf_path,
                stylesheets=[CSS(string='@page { size: A4; margin: 1cm; }')]
            )
            report_paths['pdf'] = pdf_path

        return report_paths

    def _create_zip_bundle(self, report_id: str, report_paths: Dict[str, str]) -> str:
        zip_path = os.path.join(self.bundle_dir, f"{report_id}_bundle.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for fmt, path in report_paths.items():
                zipf.write(path, arcname=os.path.basename(path))
        logger.info(f"Created ZIP bundle: {zip_path}")
        return zip_path

    def _prepare_report_context(self, entity: Any, report_type: str) -> Dict[str, Any]:
        try:
            context = {
                'report_type': report_type,
                'entity': entity.to_dict() if hasattr(entity, 'to_dict') else entity,
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            return context
        except Exception as e:
            logger.error(f"Error preparing report context: {e}")
            return {}

    def _launch_preview_server(self):
        os.chdir(self.output_dir)
        handler = SimpleHTTPRequestHandler
        server = TCPServer(("localhost", 8000), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        logger.info("Launched preview server at http://localhost:8000/")
        webbrowser.open("http://localhost:8000")

# --------------------------- CLI HANDLER --------------------------- #

def cli_generate(args):
    report_generator = ReportGenerator()
    result = report_generator.generate_report(
        report_type=args.type,
        entity_id=args.id,
        output_format=args.format,
        auto_open=args.open,
        preview=args.preview
    )
    print(json.dumps(result, indent=2))


def cli_list(args):
    report_generator = ReportGenerator()
    reports = report_generator.list_reports(args.type, args.start, args.end)
    print(json.dumps(reports, indent=2))


def cli_get(args):
    report_generator = ReportGenerator()
    path = report_generator.get_report_path(args.id, args.format)
    print(f"Report Path: {path}" if path else "Report not found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Report Generator CLI")
    subparsers = parser.add_subparsers(help="Commands")

    parser_generate = subparsers.add_parser("generate", help="Generate a report")
    parser_generate.add_argument("--type", required=True, help="Type of report (malware, dna, forensic, threat)")
    parser_generate.add_argument("--id", required=True, help="Entity ID")
    parser_generate.add_argument("--format", default="html", help="Output format (html, pdf)")
    parser_generate.add_argument("--open", action="store_true", help="Auto open report in browser")
    parser_generate.add_argument("--preview", action="store_true", help="Run live preview server")
    parser_generate.set_defaults(func=cli_generate)

    parser_list = subparsers.add_parser("list", help="List available reports")
    parser_list.add_argument("--type", help="Filter by report type")
    parser_list.add_argument("--start", help="Start date (YYYY-MM-DD)")
    parser_list.add_argument("--end", help="End date (YYYY-MM-DD)")
    parser_list.set_defaults(func=cli_list)

    parser_get = subparsers.add_parser("get", help="Get specific report path")
    parser_get.add_argument("--id", required=True, help="Report ID")
    parser_get.add_argument("--format", default="html", help="Format (html, pdf)")
    parser_get.set_defaults(func=cli_get)

    args = parser.parse_args()
    args.func(args)

