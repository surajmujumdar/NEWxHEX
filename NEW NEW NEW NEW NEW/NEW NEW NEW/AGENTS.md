# HexStrike AI Model System Directives

## Workspace Context
This workspace contains **HexStrike AI v6.0**, an AI-powered cybersecurity automation framework connecting Large Language Models (LLMs) with 150+ cybersecurity tools and 12+ autonomous AI agents via the Model Context Protocol (MCP) and REST API.

## Core Modules
- **`hexstrike_server.py`**: The central Flask REST API server and intelligence engine. Handles tool execution, command caching, error recovery, visual telemetry, and multi-agent coordination.
- **`hexstrike_mcp.py`**: The FastMCP client interface providing tool declarations and RPC execution over MCP standard input/output or network protocol.
- **`hexstrike-ai-mcp.json` / `mcp_config.json`**: Client configurations for Claude Desktop, Cursor, VS Code Copilot, Antigravity, and MCP clients.
- **`requirements.txt`**: Python dependencies required to run the server and MCP bridge.

## Operational Guidelines
1. **Ethical & Authorized Scope**: All automated security tools, scripts, and scanning workflows must be run only against authorized targets, research labs, CTF environments, or authorized pentest scopes.
2. **Execution Flow**:
   - Step 1: Ensure `hexstrike_server.py` is running on `http://127.0.0.1:3000`.
   - Step 2: The MCP agent or client interacts with `hexstrike_mcp.py` or directly calls REST endpoints (`/api/tools/*`, `/api/intelligence/*`, `/api/agents/*`).
   - Step 3: Always inspect telemetry, recovery strategies, and tool output.
3. **Multi-Agent Coordination**:
   - For bug bounties and external recon, use the Bug Bounty Manager workflow (`subfinder` -> `httpx` -> `katana` -> `nuclei`).
   - For web apps, chain crawling, parameter extraction (`arjun`), and focused vulnerability fuzzing (`dalfox`, `sqlmap`, `ffuf`).
   - For cloud audits, leverage `prowler` and `scout-suite` with structured JSON reports.
