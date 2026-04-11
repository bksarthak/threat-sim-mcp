import argparse
import subprocess
import json
import sys
import os
from typing import Dict, Any

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
        # Checkov might output multiple JSON blocks or extraneous text before JSON.
        # For simplicity in MVP, we assume standard JSON stdout.
        if not result.stdout.strip():
            # If no stdout, maybe all passed or empty dir, or check stderr
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
        adapter = CheckovAdapter(raw_data)
        adapter.parse()
        graph_dict = adapter.get_graph_dict()
        
        # Output the sanitized graph structure to stdout for Go middleware
        print(json.dumps(graph_dict))
    else:
        print(json.dumps({"error": f"Unsupported scanner: {scanner}"}))
        sys.exit(1)

def simulate_path(target_dir: str, scanner: str, source: str, target: str) -> None:
    # For MVP, we rebuild the graph to perform the simulation. 
    # In a production environment with large IaC, we'd persist the graph state.
    if scanner.lower() == "checkov":
        raw_data = run_checkov(target_dir)
        adapter = CheckovAdapter(raw_data)
        adapter.parse()
        graph_dict = adapter.get_graph_dict()
        
        pathfinder = Pathfinder(graph_dict)
        result = pathfinder.simulate_access_path(source, target)
        print(json.dumps(result))
    else:
        print(json.dumps({"error": f"Unsupported scanner: {scanner}"}))
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Threat-Sim Python Orchestrator")
    parser.add_argument("--action", required=True, choices=["generate", "simulate"], help="Action to perform")
    parser.add_argument("--dir", required=True, help="Target directory for IaC files")
    parser.add_argument("--scanner", default="checkov", help="Scanner to use (e.g., checkov)")
    
    # Arguments for simulate
    parser.add_argument("--source", help="Source node ID for simulation")
    parser.add_argument("--target", help="Target node ID for simulation")
    
    args = parser.parse_args()

    if args.action == "generate":
        generate_graph(args.dir, args.scanner)
    elif args.action == "simulate":
        if not args.source or not args.target:
            print(json.dumps({"error": "--source and --target are required for simulate action"}))
            sys.exit(1)
        simulate_path(args.dir, args.scanner, args.source, args.target)

if __name__ == "__main__":
    main()
