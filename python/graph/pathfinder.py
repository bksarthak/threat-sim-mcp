import networkx as nx
from typing import List, Dict, Any, Optional

class Pathfinder:
    """
    Manages the NetworkX graph built from IaC parsed data and provides
    capabilities to simulate access paths and identify trust boundaries.
    """

    def __init__(self, graph_data: Dict[str, Any]):
        """
        Initializes the NetworkX graph from the standardized graph dictionary.
        """
        self.graph = nx.DiGraph()
        self._build_graph(graph_data)

    def _build_graph(self, graph_data: Dict[str, Any]) -> None:
        """
        Populates the NetworkX graph with nodes and edges.
        """
        for node in graph_data.get("nodes", []):
            node_id = node.get("id")
            if node_id:
                # Add node with all its attributes
                self.graph.add_node(node_id, **node)

        for edge in graph_data.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            if source and target:
                # Add edge with all its attributes
                self.graph.add_edge(source, target, **edge)

    def simulate_access_path(self, source_node: str, target_node: str) -> Dict[str, Any]:
        """
        Determines if a path exists between source_node and target_node.
        Returns a dictionary detailing the path if it exists, or indicating failure.
        """
        if source_node not in self.graph:
            return {"error": f"Source node '{source_node}' not found in graph."}
        if target_node not in self.graph:
            return {"error": f"Target node '{target_node}' not found in graph."}

        try:
            # Find the shortest path
            path = nx.shortest_path(self.graph, source=source_node, target=target_node)
            return {
                "path_exists": True,
                "path": path,
                "length": len(path) - 1
            }
        except nx.NetworkXNoPath:
            return {
                "path_exists": False,
                "path": [],
                "error": "No path exists between the specified nodes."
            }

    def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves all attributes for a specific node.
        """
        if node_id in self.graph:
            return dict(self.graph.nodes[node_id])
        return None

    def get_graph_summary(self) -> Dict[str, Any]:
        """
        Returns a summary of the graph topology.
        """
        return {
            "num_nodes": self.graph.number_of_nodes(),
            "num_edges": self.graph.number_of_edges()
        }
