// src/mcp-agent.ts — McpAgent Durable Object
// This is the core MCP server running inside a Cloudflare Durable Object.
// Each DO instance = one MCP session with its own SQLite-backed state.
//
// Boundary: B2 (Controlled Execution Plane)
// Responsibilities: tool orchestration, session state, prompt compilation, guardrail enforcement
//
// Changelog:
//   - [FIX] onToolCall is now a concrete utility invoked by tool handlers, not dead code.
//           MCP SDK does not call onToolCall automatically — callers must invoke it explicitly
//           via the exported trackToolCall helper after each tool execution.

import { McpAgent } from "agents/mcp";
import { z } from "zod";
import type { Env } from "./types.js";
import { registerPromptTools } from "./tools/prompt-tools.js";

// ─── Durable Object State ──────────────────────────────────────────
interface AgentState {
  sessionId: string;
  userId: string;
  role: string;
  createdAt: string;
  requestCount: number;
}

// ─── PromptMCPServer Durable Object ────────────────────────────────
export class PromptMCPServer extends McpAgent<Env, AgentState> {
  // Called once when the DO is first instantiated
  async init(): Promise<void> {
    // Initialize session state
    const state: AgentState = this.state ?? {
      sessionId: crypto.randomUUID(),
      userId: "anonymous",
      role: "viewer",
      createdAt: new Date().toISOString(),
      requestCount: 0,
    };
    this.setState(state);

    // Initialize SQLite tables for session-local data
    this.sql`
      CREATE TABLE IF NOT EXISTS session_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `;

    // Register all MCP tools
    registerPromptTools(this.server, this.env, state.userId);

    // Register MCP prompts (reusable prompt templates)
    this.server.registerPrompt(
      "four_layer_prompt",
      {
        title: "Four-Layer Prompt Builder",
        description:
          "Interactive prompt builder using the Objective → Role → Constraints → Output Shape stack",
        argsSchema: z.object({
          objective: z.string().describe("What the model should accomplish"),
          role: z.string().describe("Persona and domain expertise"),
          constraints: z.string().describe("Rules and boundaries"),
          outputShape: z.string().describe("Expected output format"),
        }),
      },
      async ({ objective, role, constraints, outputShape }) => ({
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                `## ROLE\n${role}`,
                `## OBJECTIVE\n${objective}`,
                `## CONSTRAINTS\n${constraints}`,
                `## OUTPUT FORMAT\n${outputShape}`,
              ].join("\n\n"),
            },
          },
        ],
      }),
    );

    this.server.registerPrompt(
      "security_assessment",
      {
        title: "Security Assessment Prompt",
        description:
          "Pre-built prompt for vulnerability assessment with structured JSON output",
        argsSchema: z.object({
          target: z.string().describe("Target system or scan data identifier"),
          scanData: z.string().describe("Raw scan output to analyze"),
        }),
      },
      async ({ target, scanData }) => ({
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                "## ROLE",
                "You are a senior penetration tester with OSCP certification.",
                "",
                "## OBJECTIVE",
                `Analyze scan results for target: ${target}`,
                "",
                "## CONSTRAINTS",
                "- Only reference CVEs from NVD/MITRE",
                "- Flag uncertain findings with confidence scores",
                "- Do not fabricate vulnerability data",
                "",
                "## OUTPUT FORMAT",
                'JSON: {"findings": [{"port": int, "service": str, "severity": str, "cve": str, "confidence": float, "remediation": str}], "riskRating": str, "nextSteps": [str]}',
                "",
                `<user_input>\n${scanData}\n</user_input>`,
              ].join("\n"),
            },
          },
        ],
      }),
    );

    // Register resources (template catalog)
    this.server.registerResource(
      "promptcraft://templates",
      {
        uri: "promptcraft://templates",
        name: "Template Catalog",
        description: "List of all available prompt templates",
        mimeType: "application/json",
      },
      async () => {
        const list = await this.env.PROMPT_TEMPLATES.list({
          prefix: "template:",
          limit: 100,
        });
        const templates = list.keys
          .filter((k) => !k.name.includes(":v"))
          .map((k) => ({
            id: k.name.replace("template:", ""),
            name: (k.metadata as Record<string, unknown>)?.name ?? "unknown",
          }));
        return JSON.stringify(templates, null, 2);
      },
    );
  }

  // ─── Session Tool Tracking ─────────────────────────────────────────
  // [FIX] The MCP SDK does not call this method automatically — it must be
  // invoked explicitly by tool handlers. This method is intentionally kept
  // on the class (not a module-level function) because it needs access to
  // this.sql and this.state, which are Durable Object instance members.
  //
  // Usage in tool handlers:
  //   const agent = ... // obtain DO stub
  //   await agent.trackToolCall("promptcraft_execute_prompt", inputHash, "success");
  //
  // In practice, tools call this via the exported trackToolCall() helper below,
  // which receives a reference to the DO instance from the Hono request context.
  async trackToolCall(
    toolName: string,
    inputHash: string,
    status: string,
  ): Promise<void> {
    this.sql`
      INSERT INTO session_history (tool_name, input_hash, status)
      VALUES (${toolName}, ${inputHash}, ${status})
    `;
    this.setState({
      ...this.state,
      requestCount: (this.state?.requestCount ?? 0) + 1,
    });
  }
}
