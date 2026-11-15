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

// RedTeamAttackPathsParams represents arguments for the red_team_attack_paths tool.
type RedTeamAttackPathsParams struct {
	SourceNode string `json:"source_node"`
	TargetNode string `json:"target_node"`
}

// BlueTeamEvaluateMitigationParams represents arguments for the blue_team_evaluate_mitigation tool.
type BlueTeamEvaluateMitigationParams struct {
	SourceNode  string `json:"source_node"`
	TargetNode  string `json:"target_node"`
	CutEdgeFrom string `json:"cut_edge_from"`
	CutEdgeTo   string `json:"cut_edge_to"`
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
						Description: "The tool to use (currently 'checkov').",
					},
				},
				Required: []string{"target_dir", "scanner"},
			},
		},
		{
			Name:        "red_team_attack_paths",
			Description: "As the Red Team, queries the architecture to discover ALL potential lateral movement vectors up to depth 5 between two nodes.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"source_node": {
						Type:        "string",
						Description: "The sanitized ID of the starting node (attacker foothold).",
					},
					"target_node": {
						Type:        "string",
						Description: "The sanitized ID of the destination node (target asset).",
					},
				},
				Required: []string{"source_node", "target_node"},
			},
		},
		{
			Name:        "blue_team_evaluate_mitigation",
			Description: "As the Blue Team, simulates testing an IaC patch by severing an edge in the graph and verifying if the attacker can still reach the target.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"source_node": {
						Type:        "string",
						Description: "The starting node ID.",
					},
					"target_node": {
						Type:        "string",
						Description: "The destination node ID.",
					},
					"cut_edge_from": {
						Type:        "string",
						Description: "Node ID from which the severed edge originates.",
					},
					"cut_edge_to": {
						Type:        "string",
						Description: "Node ID to which the severed edge points.",
					},
				},
				Required: []string{"source_node", "target_node", "cut_edge_from", "cut_edge_to"},
			},
		},
		{
			Name:        "log_threat_finding",
			Description: "Writes a confirmed vulnerability to the local .threatmodel.json state file. Only invoke this after Blue Team verifies the mitigation works.",
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
