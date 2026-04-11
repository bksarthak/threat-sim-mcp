import json
from typing import Dict, Any, List
from .base import ScannerAdapter

class CheckovAdapter(ScannerAdapter):
    """
    Adapter for parsing Checkov JSON output into a standardized graph.
    """

    def __init__(self, raw_data: Dict[str, Any]):
        super().__init__(raw_data)
        self.nodes = []
        self.edges = []
        # Checkov often outputs a list of results, or a dict with a 'results' key.
        # We need to handle the structure gracefully.
        self.results = self._extract_results(raw_data)

    def _extract_results(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            if "results" in data and "failed_checks" in data["results"]:
                # Handling standard checkov output structure
                return data.get("results", {}).get("passed_checks", []) + \
                       data.get("results", {}).get("failed_checks", []) + \
                       data.get("results", {}).get("skipped_checks", [])
            return [data] # Fallback
        return []

    def parse(self) -> None:
        """
        Parses Checkov results to extract resources as nodes.
        Note: Checkov natively evaluates single resources against policies.
        Graph generation (edges) might require deeper parsing of TF variables
        or relying on Checkov's experimental graph output if available.
        For MVP, we focus on extracting all unique resources as nodes.
        """
        seen_nodes = set()
        
        for check in self.results:
            resource_id = check.get("resource")
            if not resource_id:
                continue
            
            # resource_id is typically formatted as 'resource_type.resource_name'
            if resource_id not in seen_nodes:
                seen_nodes.add(resource_id)
                
                parts = resource_id.split(".")
                resource_type = parts[0] if len(parts) > 0 else "unknown"
                
                self.nodes.append({
                    "id": resource_id,
                    "type": resource_type,
                    "file_path": check.get("file_path", "unknown"),
                    "file_line_range": check.get("file_line_range", [])
                })
        
        # TODO: Implement edge extraction if Checkov graph features are enabled
        # or by parsing intrinsic links (like security_groups = [aws_security_group.sg.id])
        # For now, edges will be empty in the basic Checkov output.

    def get_nodes(self) -> List[Dict[str, Any]]:
        return self.nodes

    def get_edges(self) -> List[Dict[str, Any]]:
        return self.edges
