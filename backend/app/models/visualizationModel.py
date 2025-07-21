import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any

# Graph Processing & Blockchain
import networkx as nx
from mongoengine import (
    Document, StringField, DictField, DateTimeField, ListField, BooleanField
)
from app.services.blockchainService import blockchain_service

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --------------------------------------------
# 📌 **Visualization Model: Malware Lineage**
# --------------------------------------------
class VisualizationModel(Document):
    """
    Stores CLI-generated malware lineage graphs and blockchain-verifiable evidence.
    """

    # 🔗 **Unique Identifiers**
    visualization_id = StringField(primary_key=True, default=lambda: str(os.urandom(16).hex()), unique=True)
    title = StringField(required=True)
    description = StringField()
    chart_type = StringField(choices=["lineage_graph", "heatmap", "bar_chart", "pie_chart", "time_series"])
    
    # 📊 **Graph Data & Metadata**
    graph_data = DictField(required=True)  # Stores nodes, edges, attributes
    metadata = DictField(default={})
    
    # 🕒 **Timestamps**
    created_at = DateTimeField(default=datetime.utcnow)
    
    # 🔒 **Blockchain Verification**
    blockchain_tx_id = StringField()
    blockchain_verified = BooleanField(default=False)

    # 📌 **Indexing & Optimization**
    meta = {
        "indexes": ["visualization_id", "title", "chart_type", "created_at"],
        "ordering": ["-created_at"],
        "strict": True
    }

    # --------------------------------------------
    # 🎯 **Blockchain Verification**
    # --------------------------------------------
    def store_on_blockchain(self):
        """
        Store visualization metadata on blockchain for verification.
        """
        try:
            blockchain_tx = blockchain_service.store_data_on_blockchain(json.dumps(self.to_dict()))
            self.blockchain_tx_id = blockchain_tx
            self.blockchain_verified = True
            self.save()

            logger.info(f"Visualization stored on blockchain with TX: {blockchain_tx}")
        except Exception as e:
            logger.error(f"Blockchain storage failed: {e}")
            raise

    # --------------------------------------------
    # 📌 **Export & Import**
    # --------------------------------------------
    def save_to_file(self, output_dir: str = "visualizations", file_format: str = "json") -> str:
        """
        Export visualization data to a file (JSON, GraphML).
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"visualization_{self.visualization_id}.{file_format}"
            file_path = os.path.join(output_dir, filename)

            if file_format == "json":
                with open(file_path, "w") as f:
                    json.dump(self.to_dict(), f, indent=4)
            elif file_format == "graphml":
                G = nx.node_link_graph(self.graph_data)  # Convert dict to graph
                nx.write_graphml(G, file_path)
            else:
                raise ValueError("Unsupported file format")

            logger.info(f"Visualization data exported to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save visualization: {e}")
            raise

    @classmethod
    def load_from_file(cls, file_path: str) -> Optional['VisualizationModel']:
        """
        Load visualization data from a JSON file.
        """
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            return cls(
                visualization_id=data["visualization_id"],
                title=data["title"],
                description=data["description"],
                chart_type=data["chart_type"],
                graph_data=data["graph_data"],
                metadata=data.get("metadata", {}),
                created_at=datetime.fromisoformat(data["created_at"]),
                blockchain_tx_id=data.get("blockchain_tx_id"),
                blockchain_verified=data.get("blockchain_verified", False)
            )
        except Exception as e:
            logger.error(f"Failed to load visualization: {e}")
            return None

    # --------------------------------------------
    # 📌 **Graph Processing**
    # --------------------------------------------
    def generate_graph(self) -> nx.Graph:
        """
        Convert stored JSON graph data into a NetworkX graph.
        """
        try:
            return nx.node_link_graph(self.graph_data)
        except Exception as e:
            logger.error(f"Failed to generate graph: {e}")
            raise

    def add_node(self, node_id: str, attributes: Dict[str, Any] = None):
        """
        Add a node to the visualization graph.
        """
        try:
            G = self.generate_graph()
            G.add_node(node_id, **(attributes or {}))
            self.graph_data = nx.node_link_data(G)
            self.save()
        except Exception as e:
            logger.error(f"Failed to add node: {e}")
            raise

    def add_edge(self, source: str, target: str, attributes: Dict[str, Any] = None):
        """
        Add an edge between nodes in the visualization graph.
        """
        try:
            G = self.generate_graph()
            G.add_edge(source, target, **(attributes or {}))
            self.graph_data = nx.node_link_data(G)
            self.save()
        except Exception as e:
            logger.error(f"Failed to add edge: {e}")
            raise

    # --------------------------------------------
    # 📌 **Utility Functions**
    # --------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the visualization model to a dictionary.
        """
        return {
            "visualization_id": self.visualization_id,
            "title": self.title,
            "description": self.description,
            "chart_type": self.chart_type,
            "graph_data": self.graph_data,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "blockchain_tx_id": self.blockchain_tx_id,
            "blockchain_verified": self.blockchain_verified
        }

# --------------------------------------------
# 🎯 **CLI Utility Functions**
# --------------------------------------------
def create_visualization(title: str, description: str, chart_type: str, graph_data: Dict[str, Any]) -> VisualizationModel:
    """
    Create and store a new malware lineage visualization.
    """
    try:
        visualization = VisualizationModel(
            title=title,
            description=description,
            chart_type=chart_type,
            graph_data=graph_data
        )
        visualization.save()
        return visualization
    except Exception as e:
        logger.error(f"Visualization creation failed: {e}")
        raise

def retrieve_visualization(visualization_id: str) -> Optional[VisualizationModel]:
    """
    Retrieve a visualization record from the database.
    """
    try:
        return VisualizationModel.objects(visualization_id=visualization_id).first()
    except Exception as e:
        logger.error(f"Failed to retrieve visualization: {e}")
        return None

