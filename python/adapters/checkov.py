import json
import os
import hcl2
from typing import Dict, Any, List
from .base import ScannerAdapter

class CheckovAdapter(ScannerAdapter):
    """
    Adapter for parsing Checkov JSON output into a standardized graph.
    Now leverages AST parsing (hcl2) to extract deterministic edges.
    """

    def __init__(self, raw_data: Dict[str, Any], target_dir: str = "."):
        super().__init__(raw_data, target_dir)
        self.nodes = []
        self.edges = []
        # Checkov often outputs a list of results, or a dict with a 'results' key.
        self.results = self._extract_results(raw_data)

    def _extract_results(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            if "results" in data and "failed_checks" in data["results"]:
                return data.get("results", {}).get("passed_checks", []) + \
                       data.get("results", {}).get("failed_checks", []) + \
                       data.get("results", {}).get("skipped_checks", [])
            return [data] # Fallback
        return []

    def parse(self) -> None:
        """
        Parses Checkov results to extract resources as nodes, 
        then builds edges by deeply parsing Terraform syntax via hcl2 AST.
        """
        seen_nodes = set()
        
        for check in self.results:
            resource_id = check.get("resource")
            if not resource_id:
                continue
            
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
        
        self._extract_edges()

    def _extract_edges(self) -> None:
        node_ids = {n["id"] for n in self.nodes}
        
        unique_files = set()
        for check in self.results:
            filepath = check.get("file_path")
            if filepath and filepath != "unknown":
                clean_path = filepath.lstrip("/")
                abs_path = os.path.abspath(os.path.join(self.target_dir, clean_path))
                
                # Path traversal mitigation
                if abs_path.startswith(os.path.abspath(self.target_dir)):
                    unique_files.add(abs_path)

        for abs_path in unique_files:
            if not os.path.exists(abs_path):
                continue
            try:
                with open(abs_path, 'r') as file:
                    tf_dict = hcl2.load(file)
                    
                    if "resource" in tf_dict:
                        for res in tf_dict["resource"]:
                            for res_type, res_blocks in res.items():
                                for res_name, res_attrs in res_blocks.items():
                                    current_id = f"{res_type}.{res_name}"
                                    if current_id in node_ids:
                                        self._find_edges_in_dict(current_id, res_attrs, node_ids)
            except Exception as e:
                # Tolerate parse errors for non-standard files or syntax issues
                pass

    def _find_edges_in_dict(self, current_id: str, data: Any, node_ids: set) -> None:
        if isinstance(data, dict):
            for k, v in data.items():
                self._find_edges_in_dict(current_id, v, node_ids)
        elif isinstance(data, list):
            for item in data:
                self._find_edges_in_dict(current_id, item, node_ids)
        elif isinstance(data, str):
            for nid in node_ids:
                if nid != current_id and nid in data:
                    edge = {"from_node": current_id, "to_node": nid, "type": "references"}
                    if edge not in self.edges:
                        self.edges.append(edge)

    def get_nodes(self) -> List[Dict[str, Any]]:
        return self.nodes

    def get_edges(self) -> List[Dict[str, Any]]:
        return self.edges
