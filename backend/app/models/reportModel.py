import os
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

import markdown2
import pandas as pd
import plotly.graph_objs as go
import networkx as nx
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

from app.models.malwareModel import MalwareModel
from app.models.dnaModel import DNAModel
from app.models.threatModel import ThreatIntel, ThreatEvent
from app.models.lineageModel import LineageModel
from app.utils.blockchainutils import get_reputation, verify_on_blockchain
from app.utils.logging import logger


class ReportGenerator:
    """
    Comprehensive report generation service.
    Supports malware, DNA, forensic, threat, lineage, and blockchain audit reports.
    """

    def __init__(self, templates_dir: str = 'templates', output_dir: str = 'reports'):
        self.templates_dir = templates_dir
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.jinja_env = Environment(loader=FileSystemLoader(self.templates_dir), autoescape=True)

    def generate_report(self, report_type: str, entity_id: str, output_format: str = 'html') -> Dict[str, str]:
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
            elif report_type == 'lineage':
                entity = LineageModel.objects.get(id=entity_id)
                template_file = 'lineageReport.html'
            else:
                raise ValueError("Invalid report type specified.")

            context = self._prepare_report_context(entity, report_type)
            template = self.jinja_env.get_template(template_file)
            rendered_report = template.render(**context)

            report_id = str(uuid.uuid4())
            report_paths = self._save_report(report_id, rendered_report, output_format)

            return {'report_id': report_id, 'paths': report_paths, 'metadata': context}

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

    def _prepare_report_context(self, entity, report_type: str) -> Dict[str, Any]:
        context = {'generation_timestamp': datetime.now().isoformat(), 'analysis_id': str(uuid.uuid4())}

        if report_type == 'malware':
            blockchain_status = verify_on_blockchain(entity.dna_hash) if entity.dna_hash else "Not Verified"
            context.update({
                'malware_id': str(entity.id),
                'file_name': entity.file_name,
                'file_size': entity.file_size,
                'malware_family': entity.malware_family,
                'risk_level': self._calculate_risk_level(entity),
                'ai_classification': entity.deep_learning.classification if entity.deep_learning else 'N/A',
                'blockchain_verified': blockchain_status,
                'reputation_score': get_reputation(entity.dna_hash) if entity.dna_hash else 0,
                'features': entity.processed_features.to_mongo().to_dict() if entity.processed_features else {},
            })

        elif report_type == 'dna':
            context.update({
                'dna_sequence_id': str(entity.id),
                'sequence_length': len(entity.sequence),
                'complexity_score': self._calculate_sequence_complexity(entity),
                'origin_tool': entity.tool_used,
            })

        elif report_type == 'forensic':
            context.update({
                'case_id': str(entity.id),
                'case_status': entity.status,
                'investigator': entity.lead_investigator,
                'evidence_summary': entity.evidence_summary,
                'associated_malware': [m.file_name for m in MalwareModel.objects(id__in=entity.related_malware_ids)]
            })

        elif report_type == 'threat':
            context.update({
                'threat_id': str(entity.id),
                'threat_name': entity.threat_name,
                'attack_vector': entity.attack_vector,
                'global_distribution': entity.global_distribution,
                'indicators_of_compromise': entity.indicators,
            })

        elif report_type == 'lineage':
            context.update({
                'lineage_id': str(entity.id),
                'family_name': entity.family_name,
                'mutation_history': entity.get_mutation_chain(),
                'genetic_signature': entity.genetic_signature,
                'predicted_behavior': entity.predicted_behavior,
                'cross_platform': entity.cross_platform_behavior,
                'verified_on_blockchain': verify_on_blockchain(entity.genetic_signature),
            })

        return context

    def _calculate_risk_level(self, malware) -> str:
        risk_score = len(malware.network_connections or []) + malware.entropy
        if risk_score < 5:
            return 'low'
        elif risk_score < 10:
            return 'medium'
        else:
            return 'high'

    def _calculate_sequence_complexity(self, dna) -> float:
        sequence = dna.sequence
        unique_chars = len(set(sequence))
        complexity = round((unique_chars / len(sequence)) * 100, 2) if sequence else 0
        return complexity

    def __repr__(self):
        return f"<ReportGenerator templates_dir='{self.templates_dir}' output_dir='{self.output_dir}'>"

