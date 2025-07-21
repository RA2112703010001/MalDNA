import os
import json
import logging
import argparse
import tempfile
from typing import List, Dict, Any

# Visualization libraries
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.io as pio

# Internal dependencies
from app.models.visualizationModel import VisualizationData
from app.utils.securityUtils import sanitize_file_path
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration constants
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/tmp/malware_visualizations")
TEMP_DIR = tempfile.mkdtemp(prefix="maldna_viz_")


class VisualizationService:
    @classmethod
    def visualize_phylogenetic_tree(cls, dna_list: List[str]) -> Dict[str, Any]:
        """Generate interactive malware lineage phylogenetic tree."""
        try:
            tree = {
                "root": "common_ancestor",
                "branches": [{"node": dna} for dna in dna_list]
            }
            fig = go.Figure(go.Treemap(
                labels=[branch["node"] for branch in tree["branches"]],
                parents=["common_ancestor"] * len(tree["branches"])
            ))
            fig.update_layout(title="Malware Lineage Phylogenetic Tree")
            viz_json = json.loads(pio.to_json(fig))
            logger.info(f"Phylogenetic tree visualization created for {len(dna_list)} DNA sequences")
            return viz_json
        except Exception as e:
            logger.error(f"Phylogenetic tree visualization failed: {e}")
            raise

    @classmethod
    def generate_api_heatmap(cls, api_calls: List[str]) -> str:
        """Generate heatmap for API call frequency."""
        try:
            frequency = {call: api_calls.count(call) for call in set(api_calls)}
            heatmap_data = [[frequency[call] for call in api_calls]]
            plt.figure(figsize=(10, 6))
            sns.heatmap(heatmap_data, annot=True, cmap="YlGnBu", xticklabels=api_calls)
            plt.title("API Call Frequency Heatmap")
            output_path = os.path.join(cls._ensure_upload_directory(), "api_heatmap.png")
            plt.savefig(output_path)
            plt.close()
            logger.info(f"API call heatmap generated: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"API heatmap generation failed: {e}")
            raise

    @classmethod
    def generate_visual_report(cls, visualization_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive visual report."""
        try:
            report = {
                "phylogenetic_tree": cls.visualize_phylogenetic_tree(visualization_data.get("dna_list", [])),
                "api_heatmap": cls.generate_api_heatmap(visualization_data.get("api_calls", []))
            }
            visualization_record = VisualizationData(visualization_data=visualization_data, report=report)
            visualization_record.save()
            logger.info("Comprehensive visual report generated successfully")
            return report
        except Exception as e:
            logger.error(f"Visual report generation failed: {e}")
            raise

    @classmethod
    def generate_interactive_visualization(cls, data: Dict[str, Any], chart_type: str) -> Dict[str, Any]:
        """Generate an interactive visualization based on the provided data and chart type."""
        try:
            if not data:
                raise ValueError("No data provided for visualization")
            if chart_type not in ['bar', 'line', 'pie', 'heatmap']:
                raise ValueError(f"Unsupported chart type: {chart_type}")
            if chart_type == 'bar':
                fig = go.Figure(data=[go.Bar(x=list(data.keys()), y=list(data.values()))])
            elif chart_type == 'line':
                fig = go.Figure(data=[go.Scatter(x=list(data.keys()), y=list(data.values()), mode='lines+markers')])
            elif chart_type == 'pie':
                fig = go.Figure(data=[go.Pie(labels=list(data.keys()), values=list(data.values()))])
            elif chart_type == 'heatmap':
                heatmap_data = [[data.get(key, 0) for key in data.keys()]]
                fig = go.Figure(data=go.Heatmap(z=heatmap_data, x=list(data.keys()), y=["Frequency"]))
            fig.update_layout(title=f"{chart_type.capitalize()} Chart Visualization")
            viz_json = json.loads(pio.to_json(fig))
            logger.info(f"Interactive {chart_type} visualization generated successfully")
            return viz_json
        except Exception as e:
            logger.error(f"Interactive visualization generation failed: {e}")
            raise


# ---------------------------- CLI HANDLER ---------------------------- #

def cli_generate_phylogenetic_tree(args):
    """CLI wrapper for generating a phylogenetic tree."""
    service = VisualizationService()
    result = service.visualize_phylogenetic_tree(args.dna_list)
    print(json.dumps(result, indent=4))


def cli_generate_api_heatmap(args):
    """CLI wrapper for generating an API call heatmap."""
    service = VisualizationService()
    result = service.generate_api_heatmap(args.api_calls)
    print(f"Heatmap saved at: {result}")


def cli_generate_visual_report(args):
    """CLI wrapper for generating a full visual report."""
    service = VisualizationService()
    visualization_data = json.loads(args.visualization_data)
    result = service.generate_visual_report(visualization_data)
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualization Service CLI")
    subparsers = parser.add_subparsers(help="Visualization commands")

    # Generate Phylogenetic Tree
    parser_tree = subparsers.add_parser("phylo_tree", help="Generate malware lineage phylogenetic tree")
    parser_tree.add_argument("dna_list", nargs="+", help="List of malware DNA sequences")
    parser_tree.set_defaults(func=cli_generate_phylogenetic_tree)

    # Generate API Heatmap
    parser_heatmap = subparsers.add_parser("api_heatmap", help="Generate API call frequency heatmap")
    parser_heatmap.add_argument("api_calls", nargs="+", help="List of API calls")
    parser_heatmap.set_defaults(func=cli_generate_api_heatmap)

    # Generate Full Visual Report
    parser_report = subparsers.add_parser("visual_report", help="Generate a full visual report")
    parser_report.add_argument("visualization_data", type=str, help="JSON formatted visualization data")
    parser_report.set_defaults(func=cli_generate_visual_report)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

