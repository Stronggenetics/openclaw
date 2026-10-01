// Policy layers for one gateway tool surface, including trusted completion turns.
import { resolveConversationCapabilityProfile } from "../agents/conversation-capability-profile.js";
import { resolveConversationToolPolicies } from "../agents/conversation-tool-policy-pipeline.js";
import {
  hasVerifiedRequesterCompletionHandoff,
  type resolveRequesterToolPolicies,
} from "../agents/requester-tool-policy.js";
import type { SourceReplyDeliveryMode } from "../auto-reply/get-reply-options.types.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { McpLoopbackRequestContext } from "./mcp-grant-store.js";

type ConversationPolicies = ReturnType<typeof resolveConversationToolPolicies>;
type ConfiguredPolicies = {
  profilePolicyWithAlsoAllow: ConversationPolicies["profilePolicy"];
  providerProfilePolicyWithAlsoAllow: ConversationPolicies["providerProfilePolicy"];
  globalPolicy: ConversationPolicies["globalPolicy"];
  globalProviderPolicy: ConversationPolicies["globalProviderPolicy"];
  agentPolicy: ConversationPolicies["agentPolicy"];
  agentProviderPolicy: ConversationPolicies["agentProviderPolicy"];
};

/** A completion grant is only as current as the requester lineage that minted it. */
export function staleCompletionGrantError(): Error {
  return new Error("CLI completion tool grant no longer matches its requester policy");
}

type CompletionGrantLineageParams = {
  cfg: OpenClawConfig;
  context: Pick<
    McpLoopbackRequestContext,
    | "sessionKey"
    | "runtimePolicySessionKey"
    | "sessionId"
    | "modelProvider"
    | "modelId"
    | "inputProvenance"
    | "trustedInternalHandoff"
  >;
};

/**
 * Whether a completion grant's requester lineage still verifies. Grants without a
 * handoff carry no lineage and are always current. The child entry can be removed or
 * re-parented while a tool call awaits preparation, hooks or approvals, so the tool
 * list, the dispatch authorization and the tool's source-effect guard all ask this.
 */
export function isCompletionGrantLineageCurrent(params: CompletionGrantLineageParams): boolean {
  const { context } = params;
  return (
    !context.trustedInternalHandoff ||
    hasVerifiedRequesterCompletionHandoff({
      config: params.cfg,
      sessionKey: context.runtimePolicySessionKey?.trim() || context.sessionKey,
      sessionId: context.sessionId,
      modelProvider: context.modelProvider,
      modelId: context.modelId,
      inputProvenance: context.inputProvenance,
      trustedInternalHandoff: context.trustedInternalHandoff,
    })
  );
}

/** Rejects a tool list, built or cached, whose completion grant outlived its lineage. */
export function assertCompletionGrantLineage(params: CompletionGrantLineageParams): void {
  if (!isCompletionGrantLineageCurrent(params)) {
    throw staleCompletionGrantError();
  }
}

/**
 * Picks the policy layers for a gateway tool surface. A trusted completion whose reply
 * is bound to its source keeps the requester's persisted cap and gains only `message`;
 * explicit denies still win at every layer.
 */
export function selectGatewayToolPolicies(params: {
  current: ConfiguredPolicies;
  requesterPolicies: ReturnType<typeof resolveRequesterToolPolicies>;
  sandboxPolicy: ConversationPolicies["sandboxPolicy"];
  grant: Pick<
    McpLoopbackRequestContext,
    "sessionId" | "modelProvider" | "modelId" | "inputProvenance" | "trustedInternalHandoff"
  > & { sourceReplyOnly?: boolean };
  config: OpenClawConfig;
  sessionKey: string;
  agentId: string | undefined;
  sourceReplyDeliveryMode: SourceReplyDeliveryMode | undefined;
}): Omit<ConversationPolicies, "runtimeToolPolicy"> {
  const { current, requesterPolicies, sandboxPolicy, grant } = params;
  if (
    requesterPolicies.requesterPolicySource === "completion-handoff" &&
    grant.sourceReplyOnly === true &&
    params.sourceReplyDeliveryMode === "message_tool_only"
  ) {
    // A completion-handoff resolution has no sender or group layer to carry over: the
    // child's persisted envelope already holds the spawning sender's restrictions and
    // arrives as the inherited policy. Only `message` extends restrictive allowlists,
    // mirroring the attempt's source-bound delivery grant.
    return resolveConversationToolPolicies({
      capabilityProfile: resolveConversationCapabilityProfile({
        config: params.config,
        sessionKey: params.sessionKey,
        sessionId: grant.sessionId,
        agentId: params.agentId,
        modelProvider: grant.modelProvider,
        modelId: grant.modelId,
        sandboxToolPolicy: sandboxPolicy,
        inputProvenance: grant.inputProvenance,
        trustedInternalHandoff: grant.trustedInternalHandoff,
      }),
      additionalProfileAllow: ["message"],
      additionalPolicyAllow: ["message"],
      additionalInheritedAllow: ["message"],
    });
  }
  return {
    profilePolicy: current.profilePolicyWithAlsoAllow,
    providerProfilePolicy: current.providerProfilePolicyWithAlsoAllow,
    globalPolicy: current.globalPolicy,
    globalProviderPolicy: current.globalProviderPolicy,
    agentPolicy: current.agentPolicy,
    agentProviderPolicy: current.agentProviderPolicy,
    groupPolicy: requesterPolicies.groupPolicy,
    senderPolicy: requesterPolicies.senderPolicy,
    sandboxPolicy,
    subagentPolicy: requesterPolicies.subagentPolicy,
    inheritedToolPolicy: requesterPolicies.inheritedToolPolicy,
  };
}
