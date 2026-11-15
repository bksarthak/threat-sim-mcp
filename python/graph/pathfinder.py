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

    def find_all_attack_paths(self, source_node: str, target_node: str, depth_limit: int = 10) -> Dict[str, Any]:
        """
        [Red Team] Discovers all simple paths up to a specified depth limit.
        This allows the Red agent to identify secondary pivot points if the shortest path is patched.
        """
        if source_node not in self.graph:
            return {"error": f"Source node '{source_node}' not found in graph."}
        if target_node not in self.graph:
            return {"error": f"Target node '{target_node}' not found in graph."}

        try:
            generator = nx.all_simple_paths(self.graph, source=source_node, target=target_node, cutoff=depth_limit)
            paths = list(generator)
            return {
                "paths_exist": len(paths) > 0,
                "paths": paths,
                "count": len(paths)
            }
        except Exception as e:
            return {
                "paths_exist": False,
                "paths": [],
                "error": str(e)
            }

    def simulate_access_path(self, source_node: str, target_node: str, cut_edge_from: Optional[str] = None, cut_edge_to: Optional[str] = None) -> Dict[str, Any]:
        """
        [Blue Team] Determines if a path exists. Optionally severs an edge before testing
        to mathematically prove if a specific IaC mitigation breaks the attack chain.
        """
        if source_node not in self.graph:
            return {"error": f"Source node '{source_node}' not found in graph."}
        if target_node not in self.graph:
            return {"error": f"Target node '{target_node}' not found in graph."}

        # Apply Ephemeral Mitigation
        if cut_edge_from and cut_edge_to:
            if self.graph.has_edge(cut_edge_from, cut_edge_to):
                self.graph.remove_edge(cut_edge_from, cut_edge_to)
            else:
                return {"error": f"Proposed mitigation edge {cut_edge_from}->{cut_edge_to} does not exist."}

        try:
            # Find the shortest path
            path = nx.shortest_path(self.graph, source=source_node, target=target_node)
            return {
                "path_exists": True,
                "path": path,
                "length": len(path) - 1,
                "mitigation_successful": False # If a path still exists, the cut failed to protect the target
            }
        except nx.NetworkXNoPath:
            return {
                "path_exists": False,
                "path": [],
                "mitigation_successful": (cut_edge_from is not None) # Proves the cut blocked the path
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
