package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"threat-sim/pkg/mcp"
	"threat-sim/pkg/sanitizer"
)

// Global sanitizer instance
var globalSanitizer = sanitizer.New()

// Global session state
var globalTargetDir string = "."

// Security: Path traversal prevention
var pathTraversalPattern = regexp.MustCompile(`(^|[/\\])\.\.([/\\]|$)`)

// Security: Scanner allowlist — only explicitly approved scanners may execute
var allowedScanners = map[string]bool{
	"checkov": true,
	"trivy":   true,
}

func validateTargetDir(dir string) error {
	if filepath.IsAbs(dir) {
		return fmt.Errorf("absolute paths are not permitted")
	}
	if pathTraversalPattern.MatchString(dir) {
		return fmt.Errorf("path traversal sequences are not permitted")
	}
	return nil
}

func validateScanner(scanner string) error {
	if !allowedScanners[strings.ToLower(scanner)] {
		return fmt.Errorf("unsupported scanner specified")
	}
	return nil
}

// sanitizeUserInput strips control characters and enforces a max length
// to prevent arbitrary content injection from LLM-controlled parameters.
func sanitizeUserInput(input string, maxLen int) string {
	if len(input) > maxLen {
		input = input[:maxLen]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, input)
}

// extractSensitiveStrings pulls ALL string values from graph nodes,
// not just the 'id' field. This prevents file_path, bucket names,
// tags, and other attributes from leaking unredacted to the LLM.
func extractSensitiveStrings(graphDict map[string]interface{}) []string {
	seen := map[string]bool{}
	identifiers := []string{}

	if nodes, ok := graphDict["nodes"].([]interface{}); ok {
		for _, n := range nodes {
			if node, ok := n.(map[string]interface{}); ok {
				for _, v := range node {
					if str, ok := v.(string); ok && str != "" && len(str) > 2 && !seen[str] {
						seen[str] = true
						identifiers = append(identifiers, str)
					}
				}
			}
		}
	}

	// Sort longest-first to prevent substring collision during replacement
	sort.Slice(identifiers, func(i, j int) bool {
		return len(identifiers[i]) > len(identifiers[j])
	})

	return identifiers
}

// JSON-RPC standard structures
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func sendResponse(id interface{}, result interface{}, err *RPCError) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
		Error:   err,
	}
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}

func main() {
	// Setup logging to stderr since stdout is used for MCP protocol
	log.SetOutput(os.Stderr)
	log.Println("Starting Threat-Sim MCP Server (Red/Blue Swarm enabled)")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0), 10*1024*1024) // 10MB max to prevent silent truncation
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			sendResponse(nil, nil, &RPCError{Code: -32700, Message: "Parse error"})
			continue
		}

		handleRequest(req)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading standard input: %v", err)
	}
}

func handleRequest(req JSONRPCRequest) {
	switch req.Method {
	case "tools/list":
		sendResponse(req.ID, map[string]interface{}{
			"tools": mcp.GetRegisteredTools(),
		}, nil)
	case "tools/call":
		var params map[string]interface{}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			sendResponse(req.ID, nil, &RPCError{Code: -32602, Message: "Invalid params"})
			return
		}
		
		name, ok := params["name"].(string)
		if !ok {
			sendResponse(req.ID, nil, &RPCError{Code: -32602, Message: "Tool name missing"})
			return
		}
		
		argsRaw, _ := json.Marshal(params["arguments"])

		result, err := executeTool(name, argsRaw)
		if err != nil {
			sendResponse(req.ID, nil, &RPCError{Code: -32603, Message: err.Error()})
		} else {
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]string{
					{"type": "text", "text": result},
				},
			}, nil)
		}
	default:
		sendResponse(req.ID, nil, &RPCError{Code: -32601, Message: "Method not found"})
	}
}

func executeTool(name string, argsRaw []byte) (string, error) {
	switch name {
	case "generate_architecture_graph":
		var params mcp.GenerateArchitectureGraphParams
		if err := json.Unmarshal(argsRaw, &params); err != nil {
			return "", fmt.Errorf("invalid arguments: %v", err)
		}
		return handleGenerateGraph(params)

	case "red_team_attack_paths":
		var params mcp.RedTeamAttackPathsParams
		if err := json.Unmarshal(argsRaw, &params); err != nil {
			return "", fmt.Errorf("invalid arguments: %v", err)
		}
		return handleRedTeamAttack(params)

	case "blue_team_evaluate_mitigation":
		var params mcp.BlueTeamEvaluateMitigationParams
		if err := json.Unmarshal(argsRaw, &params); err != nil {
			return "", fmt.Errorf("invalid arguments: %v", err)
		}
		return handleBlueTeamMitigate(params)

	case "log_threat_finding":
		var params mcp.LogThreatFindingParams
		if err := json.Unmarshal(argsRaw, &params); err != nil {
			return "", fmt.Errorf("invalid arguments: %v", err)
		}
		return handleLogThreatFinding(params)

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func getOrchestratorPath() string {
	exePath, err := os.Executable()
	if err != nil {
		cwd, _ := os.Getwd()
		return filepath.Join(cwd, "python", "orchestrator.py")
	}
	return filepath.Join(filepath.Dir(exePath), "orchestrator")
}

func handleGenerateGraph(params mcp.GenerateArchitectureGraphParams) (string, error) {
	if err := validateTargetDir(params.TargetDir); err != nil {
		return "", err
	}
	if err := validateScanner(params.Scanner); err != nil {
		return "", err
	}

	globalTargetDir = params.TargetDir
	orchestrator := getOrchestratorPath()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if strings.HasSuffix(orchestrator, ".py") {
		cmd = exec.CommandContext(ctx, "python3", orchestrator, "--action", "generate", "--dir", params.TargetDir, "--scanner", params.Scanner)
	} else {
		cmd = exec.CommandContext(ctx, orchestrator, "--action", "generate", "--dir", params.TargetDir, "--scanner", params.Scanner)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("orchestrator generate error: %v, stderr: %s", err, stderr.String())
		return "", fmt.Errorf("graph generation failed: internal processing error")
	}

	rawOutput := strings.TrimSpace(stdout.String())

	var graphDict map[string]interface{}
	if err := json.Unmarshal([]byte(rawOutput), &graphDict); err == nil {
		identifiers := extractSensitiveStrings(graphDict)
		sanitizedOutput := globalSanitizer.SanitizePayload(rawOutput, identifiers)
		return sanitizedOutput, nil
	}

	return rawOutput, nil
}

func handleRedTeamAttack(params mcp.RedTeamAttackPathsParams) (string, error) {
	// Restore sanitized IDs back to real IDs before passing to python
	realSource := globalSanitizer.Restore(params.SourceNode)
	realTarget := globalSanitizer.Restore(params.TargetNode)

	// Use persisted target directory
	targetDir := globalTargetDir
	if targetDir == "" {
		targetDir = "."
	}

	orchestrator := getOrchestratorPath()

	// Security: Enforce subprocess timeout
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if strings.HasSuffix(orchestrator, ".py") {
		cmd = exec.CommandContext(ctx, "python3", orchestrator, "--action", "attack", "--dir", targetDir, "--source", realSource, "--target", realTarget)
	} else {
		cmd = exec.CommandContext(ctx, orchestrator, "--action", "attack", "--dir", targetDir, "--source", realSource, "--target", realTarget)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("RedTeam orchestrator attack error: %v, stderr: %s", err, stderr.String())
		return "", fmt.Errorf("red team attack simulation failed: internal processing error")
	}

	rawOutput := strings.TrimSpace(stdout.String())

	// Sanitize output back so Gemini only sees NODE_X
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(rawOutput), &result); err == nil {
		if pathsRaw, ok := result["paths"]; ok {
			if pathsList, ok := pathsRaw.([]interface{}); ok {
				sanitizedPaths := [][]string{}
				for _, p := range pathsList {
					if pathNodes, ok := p.([]interface{}); ok {
						sanitizedPath := []string{}
						for _, node := range pathNodes {
							if nodeStr, ok := node.(string); ok {
								sanitizedPath = append(sanitizedPath, globalSanitizer.Sanitize(nodeStr))
							}
						}
						sanitizedPaths = append(sanitizedPaths, sanitizedPath)
					}
				}
				result["paths"] = sanitizedPaths
			}
		}
		sanitizedJson, _ := json.Marshal(result)
		return string(sanitizedJson), nil
	}

	return rawOutput, nil
}

func handleBlueTeamMitigate(params mcp.BlueTeamEvaluateMitigationParams) (string, error) {
	// Restore sanitized IDs back to real IDs before passing to python
	realSource := globalSanitizer.Restore(params.SourceNode)
	realTarget := globalSanitizer.Restore(params.TargetNode)
	realCutFrom := globalSanitizer.Restore(params.CutEdgeFrom)
	realCutTo := globalSanitizer.Restore(params.CutEdgeTo)

	// Use persisted target directory
	targetDir := globalTargetDir
	if targetDir == "" {
		targetDir = "."
	}

	orchestrator := getOrchestratorPath()

	// Security: Enforce subprocess timeout
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if strings.HasSuffix(orchestrator, ".py") {
		cmd = exec.CommandContext(ctx, "python3", orchestrator, "--action", "simulate", "--dir", targetDir, "--source", realSource, "--target", realTarget, "--cut-from", realCutFrom, "--cut-to", realCutTo)
	} else {
		cmd = exec.CommandContext(ctx, orchestrator, "--action", "simulate", "--dir", targetDir, "--source", realSource, "--target", realTarget, "--cut-from", realCutFrom, "--cut-to", realCutTo)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("BlueTeam orchestrator simulate error: %v, stderr: %s", err, stderr.String())
		return "", fmt.Errorf("blue team mitigation simulation failed: internal processing error")
	}

	rawOutput := strings.TrimSpace(stdout.String())

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(rawOutput), &result); err == nil {
		// Re-sanitize any remaining patch returned
		if pathRaw, ok := result["path"]; ok {
			if pathList, ok := pathRaw.([]interface{}); ok {
				sanitizedPath := []string{}
				for _, node := range pathList {
					if nodeStr, ok := node.(string); ok {
						sanitizedPath = append(sanitizedPath, globalSanitizer.Sanitize(nodeStr))
					}
				}
				result["path"] = sanitizedPath
			}
		}
		sanitizedJson, _ := json.Marshal(result)
		return string(sanitizedJson), nil
	}

	return rawOutput, nil
}

func handleLogThreatFinding(params mcp.LogThreatFindingParams) (string, error) {
	realID := globalSanitizer.Restore(params.NodeID)

	entry := map[string]string{
		"category":   sanitizeUserInput(params.StrideCategory, 256),
		"node":       realID,
		"mitigation": sanitizeUserInput(params.MitigationStrategy, 2048),
	}

	b, _ := json.MarshalIndent(entry, "", "  ")

	f, err := os.OpenFile(".threatmodel.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open threatmodel file: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(append(b, '\n')); err != nil {
		return "", fmt.Errorf("failed to write finding: %v", err)
	}

	return fmt.Sprintf("✅ Successfully logged threat finding for node %s", params.NodeID), nil
}
