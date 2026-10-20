import {
  applyEmbeddedAttemptToolsAllow,
  HEARTBEAT_RESPONSE_TOOL_NAME,
  normalizeHeartbeatToolResponse,
  type AnyAgentTool,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import type { CodexPluginConfig } from "./config.js";
import {
  projectCodexDynamicTools,
  type CodexToolDescriptor,
  type ProjectedCodexDynamicTool,
} from "./dynamic-tool-catalog.js";
import { filterCodexDynamicTools } from "./dynamic-tool-profile.js";
import { flattenCodexDynamicToolFunctions, type CodexDynamicToolSpec } from "./protocol.js";

type InactiveCodexHeartbeatResponseDescriptor = Pick<
  ProjectedCodexDynamicTool<CodexToolDescriptor>,
  "name" | "description" | "inputSchema"
>;

export function resolveInactiveCodexHeartbeatResponseDescriptor(params: {
  registeredTools: readonly CodexToolDescriptor[];
  registeredSpecs?: readonly CodexDynamicToolSpec[];
}): InactiveCodexHeartbeatResponseDescriptor | undefined {
  const descriptor = params.registeredSpecs
    ? flattenCodexDynamicToolFunctions(params.registeredSpecs).find(
        (tool) => tool.name === HEARTBEAT_RESPONSE_TOOL_NAME,
      )
    : projectCodexDynamicTools(
        params.registeredTools.filter((tool) => tool.name === HEARTBEAT_RESPONSE_TOOL_NAME),
      ).tools[0];
  return descriptor
    ? {
        name: descriptor.name,
        description: descriptor.description,
        inputSchema: descriptor.inputSchema,
      }
    : undefined;
}

export function selectInactiveCodexHeartbeatResponseTool(params: {
  descriptor: InactiveCodexHeartbeatResponseDescriptor;
  disableTools?: boolean;
  toolsAllow?: string[];
  pluginConfig: Pick<CodexPluginConfig, "codexDynamicToolsExclude">;
}): AnyAgentTool | undefined {
  if (params.disableTools) {
    return undefined;
  }
  const descriptor = params.descriptor;
  if (descriptor.name !== HEARTBEAT_RESPONSE_TOOL_NAME) {
    throw new Error(`Expected ${HEARTBEAT_RESPONSE_TOOL_NAME}, received ${descriptor.name}`);
  }
  const tool: AnyAgentTool = {
    name: descriptor.name,
    label: descriptor.name,
    description: descriptor.description,
    // Preserve the accepted declaration so exact matching keeps this inert executor
    // available without granting notification authority outside a heartbeat turn.
    parameters: descriptor.inputSchema,
    execute: async (_toolCallId, args) => {
      const response = normalizeHeartbeatToolResponse(args);
      if (!response) {
        throw new Error(
          "Invalid heartbeat response. Provide outcome, notify, and non-empty summary.",
        );
      }
      if (response.notify) {
        throw new Error("heartbeat_respond cannot send notifications outside a heartbeat turn");
      }
      return {
        content: [
          {
            type: "text" as const,
            text: "No heartbeat is active for this turn. Continue the current task and respond normally.",
          },
        ],
        details: { status: "ignored", reason: "non-heartbeat-turn" },
      };
    },
  };

  const allowed = applyEmbeddedAttemptToolsAllow([tool], params.toolsAllow);
  return filterCodexDynamicTools(allowed, params.pluginConfig)[0];
}
