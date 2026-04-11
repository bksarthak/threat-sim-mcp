# Contributing to Threat-Sim (MCP)

First off, thank you for considering contributing to Threat-Sim! As an open-source security tool, community contributions are essential to keeping our threat models and parser adapters up to date.

## 🧠 Architectural Philosophy

Threat-Sim relies on deterministic parsers (like Checkov, Trivy, etc.) to do the heavy lifting of building an Infrastructure as Code network graph. The LLM is **only** used for probabilistic threat modeling and logic routing. 

When contributing, ensure we never ask the LLM to perform static text parsing that a mature CLI scanner can already do perfectly.

## 🛠 Adding a New Parser Adapter

We designed the Python orchestrator to be modular. To add support for a new IaC scanner (e.g., KICS, tfsec, or Trivy):

1. **Create the Adapter:**
   Create a new Python file in `python/adapters/` (e.g., `trivy_adapter.py`).
2. **Implement the Interface:**
   Your adapter must ingest the raw JSON from the scanner and yield a standardized `NetworkX` dictionary format representing Nodes and Edges.
3. **Update the Orchestrator:**
   In `python/orchestrator.py`, simply add your scanner string to the `generate_graph` action.
4. **Update the Go Allowlist:**
   In `cmd/mcp-server/main.go`, remember to add your new binary name to the `allowedScanners` map so the MCP server permits its execution.

## 🔒 Security Best Practices for PRs

- **No Remote Telemetry:** Threat-Sim is fully local. Do not introduce packages that phone home.
- **Dependency Hygiene:** Any new dependencies added to `requirements.txt` or `go.mod` must be strictly pinned and necessary.
- **Graph Redaction:** If your adapter introduces new attributes onto nodes (e.g., an IAM policy document), ensure the Go proxy's `sanitizer.go` is capable of sanitizing strings within those nested fields.

## 🧪 Running Tests Before Submitting

```bash
# Go Tests
go test ./pkg/...

# Python Tests
python3 -m unittest discover -s tests
```

Submit your PR against the `main` branch. We'll try to review it within 48 hours. Happy hunting!
