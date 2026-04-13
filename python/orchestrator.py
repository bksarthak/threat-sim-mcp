import argparse
import subprocess
import json
import sys
import os
from typing import Dict, Any, Optional

from adapters.checkov import CheckovAdapter
from graph.pathfinder import Pathfinder

def run_checkov(target_dir: str) -> Dict[str, Any]:
    """Runs Checkov on the target directory and returns the JSON output."""
    try:
        # We use -d for directory scanning in checkov
        result = subprocess.run(
            ["checkov", "-d", target_dir, "-o", "json"],
            capture_output=True,
            text=True,
            check=False # Checkov returns non-zero exit code if it finds issues
        )
        if not result.stdout.strip():
            if result.stderr:
                print(json.dumps({"error": f"Checkov stderr: {result.stderr}"}))
                sys.exit(1)
            return {}
        
        return json.loads(result.stdout)
    except FileNotFoundError:
        print(json.dumps({"error": "Checkov executable not found. Please ensure it is installed."}))
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Failed to parse Checkov output: {e}"}))
        sys.exit(1)

def generate_graph(target_dir: str, scanner: str) -> None:
    if scanner.lower() == "checkov":
        raw_data = run_checkov(target_dir)
        adapter = CheckovAdapter(raw_data, target_dir)
        adapter.parse()
        graph_dict = adapter.get_graph_dict()
        
        print(json.dumps(graph_dict))
    else:
        print(json.dumps({"error": f"Unsupported scanner: {scanner}"}))
        sys.exit(1)

def attack_paths(target_dir: str, scanner: str, source: str, target: str) -> None:
    if scanner.lower() == "checkov":
        raw_data = run_checkov(target_dir)
        adapter = CheckovAdapter(raw_data, target_dir)
        adapter.parse()
        graph_dict = adapter.get_graph_dict()
        
        pathfinder = Pathfinder(graph_dict)
        result = pathfinder.find_all_attack_paths(source, target)
        print(json.dumps(result))
    else:
        print(json.dumps({"error": f"Unsupported scanner: {scanner}"}))
        sys.exit(1)

def simulate_path(target_dir: str, scanner: str, source: str, target: str, cut_from: Optional[str] = None, cut_to: Optional[str] = None) -> None:
    if scanner.lower() == "checkov":
        raw_data = run_checkov(target_dir)
        adapter = CheckovAdapter(raw_data, target_dir)
        adapter.parse()
        graph_dict = adapter.get_graph_dict()
        
        pathfinder = Pathfinder(graph_dict)
        result = pathfinder.simulate_access_path(source, target, cut_from, cut_to)
        print(json.dumps(result))
    else:
        print(json.dumps({"error": f"Unsupported scanner: {scanner}"}))
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Threat-Sim Python Orchestrator")
    parser.add_argument("--action", required=True, choices=["generate", "simulate", "attack"], help="Action to perform")
    parser.add_argument("--dir", required=True, help="Target directory for IaC files")
    parser.add_argument("--scanner", default="checkov", help="Scanner to use (e.g., checkov)")
    
    parser.add_argument("--source", help="Source node ID for simulation")
    parser.add_argument("--target", help="Target node ID for simulation")
    parser.add_argument("--cut-from", help="Edge cut start node (Blue Team mitigation test)")
    parser.add_argument("--cut-to", help="Edge cut end node (Blue Team mitigation test)")
    
    args = parser.parse_args()

    if args.action == "generate":
        generate_graph(args.dir, args.scanner)
    elif args.action == "attack":
        if not args.source or not args.target:
            print(json.dumps({"error": "--source and --target are required for attack action"}))
            sys.exit(1)
        attack_paths(args.dir, args.scanner, args.source, args.target)
    elif args.action == "simulate":
        if not args.source or not args.target:
            print(json.dumps({"error": "--source and --target are required for simulate action"}))
            sys.exit(1)
        simulate_path(args.dir, args.scanner, args.source, args.target, args.cut_from, args.cut_to)

if __name__ == "__main__":
    main()
