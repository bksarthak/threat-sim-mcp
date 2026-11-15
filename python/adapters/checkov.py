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
        base_dir = os.path.abspath(self.target_dir)

        unique_files = set()
        for check in self.results:
            filepath = check.get("file_path")
            if filepath and filepath != "unknown":
                clean_path = filepath.lstrip("/")
                abs_path = os.path.abspath(os.path.join(base_dir, clean_path))

                # Path traversal mitigation using commonpath (prevents sibling-prefix bypass)
                try:
                    if os.path.commonpath([base_dir, abs_path]) == base_dir:
                        unique_files.add(abs_path)
                except ValueError:
                    continue

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
                                        self._enrich_attack_edges(current_id, res_type, res_attrs, node_ids)
            except Exception:
                # Tolerate parse errors for non-standard files or syntax issues
                pass

    def _add_edge(self, source: str, target: str, edge_type: str) -> None:
        if source == target:
            return
        edge = {"source": source, "target": target, "type": edge_type}
        if edge not in self.edges:
            self.edges.append(edge)

    def _find_edges_in_dict(self, current_id: str, data: Any, node_ids: set) -> None:
        if isinstance(data, dict):
            for _, v in data.items():
                self._find_edges_in_dict(current_id, v, node_ids)
        elif isinstance(data, list):
            for item in data:
                self._find_edges_in_dict(current_id, item, node_ids)
        elif isinstance(data, str):
            for nid in node_ids:
                if nid != current_id and nid in data:
                    self._add_edge(current_id, nid, "references")

    def _enrich_attack_edges(self, current_id: str, res_type: str, res_attrs: Dict[str, Any], node_ids: set) -> None:
        """
        Adds attacker-flow directional edges on top of raw Terraform references:
        - Security group ingress: referenced SG -> current SG (network_ingress)
        - Resource SG attachment: SG -> resource (network_exposure)
        - IAM role policy attachment: role -> policy (iam_policy_grant)
        - IAM wildcard/service policy: policy -> matching target resources (wildcard_access)
        """
        if not isinstance(res_attrs, dict):
            return

        if res_type == "aws_security_group":
            for ingress_rule in res_attrs.get("ingress", []):
                if isinstance(ingress_rule, dict):
                    for sg_ref in ingress_rule.get("security_groups", []):
                        if isinstance(sg_ref, str):
                            for nid in node_ids:
                                if nid.startswith("aws_security_group.") and nid in sg_ref:
                                    self._add_edge(nid, current_id, "network_ingress")

        for sg_key in ("security_groups", "vpc_security_group_ids"):
            for sg_ref in res_attrs.get(sg_key, []):
                if isinstance(sg_ref, str):
                    for nid in node_ids:
                        if nid.startswith("aws_security_group.") and nid in sg_ref:
                            self._add_edge(nid, current_id, "network_exposure")

        if res_type in ("aws_iam_role_policy", "aws_iam_role_policy_attachment"):
            role_ref = res_attrs.get("role", "")
            if isinstance(role_ref, str):
                for nid in node_ids:
                    if nid.startswith("aws_iam_role.") and nid in role_ref:
                        self._add_edge(nid, current_id, "iam_policy_grant")

        if res_type in ("aws_iam_role_policy", "aws_iam_policy"):
            policy_raw = res_attrs.get("policy")
            policy_str = json.dumps(policy_raw) if not isinstance(policy_raw, str) else policy_raw
            if policy_str and "Allow" in policy_str and ('"*"' in policy_str or "'*'" in policy_str or ":*" in policy_str):
                for nid in node_ids:
                    if nid.startswith(("aws_s3_bucket.", "aws_db_instance.", "aws_dynamodb_table.", "aws_secretsmanager_secret.")):
                        if "s3:" in policy_str or '"Action": "*"' in policy_str:
                            if nid.startswith("aws_s3_bucket."):
                                self._add_edge(current_id, nid, "wildcard_access")
                        else:
                            self._add_edge(current_id, nid, "wildcard_access")

    def get_nodes(self) -> List[Dict[str, Any]]:
        return self.nodes

    def get_edges(self) -> List[Dict[str, Any]]:
        return self.edges
