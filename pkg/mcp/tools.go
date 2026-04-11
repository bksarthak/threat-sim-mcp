package mcp

import (
	"encoding/json"
)

// Tool represents a registered MCP tool that can be invoked by Gemini.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema defines the expected parameters for a tool.
type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required"`
}

// Property defines a specific parameter attribute in the JSON schema.
type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// ToolCall represents an incoming invocation from the Gemini CLI.
type ToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// GenerateArchitectureGraphParams represents arguments for the generate_architecture_graph tool.
type GenerateArchitectureGraphParams struct {
	TargetDir string `json:"target_dir"`
	Scanner   string `json:"scanner"`
}

// SimulateAccessPathParams represents arguments for the simulate_access_path tool.
type SimulateAccessPathParams struct {
	SourceNode string `json:"source_node"`
	TargetNode string `json:"target_node"`
}

// LogThreatFindingParams represents arguments for the log_threat_finding tool.
type LogThreatFindingParams struct {
	StrideCategory     string `json:"stride_category"`
	NodeID             string `json:"node_id"`
	MitigationStrategy string `json:"mitigation_strategy"`
}

// GetRegisteredTools returns the slice of standard MCP tools available in Threat-Sim.
func GetRegisteredTools() []Tool {
	return []Tool{
		{
			Name:        "generate_architecture_graph",
			Description: "Parses the target directory using configured adapters and returns a sanitized graph schema.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target_dir": {
						Type:        "string",
						Description: "Relative path to the IaC files.",
					},
					"scanner": {
						Type:        "string",
						Description: "The tool to use (e.g., 'checkov', 'trivy').",
					},
				},
				Required: []string{"target_dir", "scanner"},
			},
		},
		{
			Name:        "simulate_access_path",
			Description: "Queries the local Python graph to determine if a network or IAM path exists between two nodes.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"source_node": {
						Type:        "string",
						Description: "The sanitized ID of the starting node.",
					},
					"target_node": {
						Type:        "string",
						Description: "The sanitized ID of the destination node.",
					},
				},
				Required: []string{"source_node", "target_node"},
			},
		},
		{
			Name:        "log_threat_finding",
			Description: "Writes a confirmed vulnerability to the local .threatmodel.json state file.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"stride_category": {
						Type:        "string",
						Description: "Spoofing, Tampering, Repudiation, etc.",
					},
					"node_id": {
						Type:        "string",
						Description: "The sanitized ID of the vulnerable node.",
					},
					"mitigation_strategy": {
						Type:        "string",
						Description: "Recommended IaC patch.",
					},
				},
				Required: []string{"stride_category", "node_id", "mitigation_strategy"},
			},
		},
	}
}
