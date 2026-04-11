# Security Policy & Threat Model

Welcome to the **Threat-Sim MCP** project. As a security tool, protecting the host system from untrusted inputs and protecting proprietary configurations from being exposed to third-party APIs are our highest priorities.

This document outlines our operational threat model and the guardrails we have implemented in the codebase to mitigate them.

---

## 1. Threat Model Overview

Because Threat-Sim operates as a Model Context Protocol (MCP) server, it accepts parameters directly from an LLM (e.g., Gemini). In modern agentic workflows, **we must treat the LLM as an untrusted actor**. If the LLM is subjected to Prompt Injection (e.g., via malicious Infrastructure as Code (IaC) files it ingests), an attacker could coerce the LLM into making anomalous tool calls.

Our threat model assumes:
- The LLM's inputs (tool parameters, directories, IDs) are untrusted.
- External IaC files may contain adversarial payloads.
- Checkov/External Parsers are trusted binaries strictly installed by the host admin.

---

## 2. Implemented Security Guardrails

Our Go codebase (`cmd/mcp-server/main.go`) acts as the unbypassable policy enforcement point.

### A. Path Traversal & File Enumeration Jailing
**Threat:** The LLM requests checkov to scan `../../../../etc` or `/var/log` to read arbitrary host files.
**Mitigation:** `validateTargetDir` strictly rejects absolute paths (`filepath.IsAbs`) and validates against `regexp.MustCompile(\`(^|[/\\])\.\.([/\\]|$)\`)`. The parsed target directory is permanently jailed to subdirectories within the current working directory.

### B. Command Injection Immunitity
**Threat:** The LLM populates `target_dir` with shell operators: `.; rm -rf /`.
**Mitigation:** The Go backend executes the Python orchestrator and the Python orchestrator executes Checkov bypassing standard shell evaluation. We explicitly use Go's `os/exec` command argument arrays and Python's `subprocess.run(shell=False)`, stripping any ability to chain system commands.

### C. Resource Exhaustion (Denial of Service)
**Threat:** The LLM loops path simulation calls recursively or provides incredibly large graph requests.
**Mitigation:** All subprocess lifecycle executions (`exec.CommandContext`) are bound strictly to a `120*time.Second` context deadline. If the parser or pathfinder hangs, Go sends a SIGKILL and fails safely.

### D. Concurrency & Cross-Session Isolation
**Threat:** Multiple asynchronous MCP calls cause redaction state (e.g., `NODE_1 -> prod-db`) to leak or corrupt across threads.
**Mitigation:** The `/pkg/sanitizer` state mapping maps securely using `sync.RWMutex` bidirectional dictionaries for thread-safe mutation and reads.

### E. File System Permissions
**Threat:** De-sanitized output reports (`.threatmodel.json`) are readable by other unprivileged users on a shared continuous integration (CI) host.
**Mitigation:** Reports are strictly generated with OS-level `0600` (Owner Read/Write Only) privilege masks.

---

## 3. Supported & Allowed Scanners

We utilize an explicit allowlist constraint array (`allowedScanners` map). The LLM cannot coercively execute alternative binaries installed on the host. Currently supported:
- `checkov`
- `trivy`

---

## 4. Reporting a Vulnerability

If you've found a vulnerability in how the Go proxy parses commands, or how the sanitizer handles obfuscation, please **DO NOT open a public issue.** 

Instead, drop an email to the security team (or repository owner) directly. We treat bypasses as Critical P0 vulnerabilities and will patch them within 24 hours.
