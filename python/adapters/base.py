from abc import ABC, abstractmethod
from typing import Dict, Any, List

class ScannerAdapter(ABC):
    """
    Abstract Base Class for IaC scanner adapters.
    Adapters are responsible for taking the raw output from a specific
    scanner (like Checkov or Trivy) and converting it into a standardized
    graph format that can be consumed by NetworkX and the orchestrator.
    """

    def __init__(self, raw_data: Dict[str, Any]):
        self.raw_data = raw_data

    @abstractmethod
    def parse(self) -> None:
        """
        Parses the raw data and populates internal structures for nodes and edges.
        """
        pass

    @abstractmethod
    def get_nodes(self) -> List[Dict[str, Any]]:
        """
        Returns a list of standardized nodes representing resources.
        Each node should at least contain an 'id' and 'type'.
        """
        pass

    @abstractmethod
    def get_edges(self) -> List[Dict[str, Any]]:
        """
        Returns a list of standardized edges representing connections.
        Each edge should at least contain 'source', 'target', and 'type'.
        """
        pass

    def get_graph_dict(self) -> Dict[str, Any]:
        """
        Returns the standardized graph dictionary.
        """
        return {
            "nodes": self.get_nodes(),
            "edges": self.get_edges()
        }
