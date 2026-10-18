import fs from "node:fs/promises";
import path from "node:path";
import { withTempDir } from "openclaw/plugin-sdk/test-env";
import { describe, expect, it, vi } from "vitest";
import { resolveCodexAppServerLocalHomeDir } from "./auth-start-options.js";
import {
  ensureCodexAppServerClientRuntime,
  protectCodexAppServerLiveThread,
} from "./client-runtime.js";
import { resolveRuntimeForTest } from "./config.test-support.js";
import {
  loadCodexAttemptNativeToolCatalog,
  parseCodexNativeToolCatalog,
} from "./native-tool-catalog.js";
import {
  buildCodexAppServerConnectionFingerprint,
  buildCodexAppServerRuntimeFingerprint,
} from "./plugin-app-cache-key.js";
import {
  getOrCreateSharedClientEntry,
  getSharedCodexAppServerClientState,
} from "./shared-client-lifecycle.js";
import { createClientHarness } from "./test-support.js";
import { codexDynamicToolsFingerprint } from "./thread-fingerprints.js";
import { CODEX_APP_SERVER_VERSION } from "./version.js";

const threadId = "native-thread";
const tool = {
  type: "function" as const,
  name: "example",
  description: "Synthetic tool",
  inputSchema: { type: "object" },
};

it.each([
  {
    transport: "websocket",
    url: "wss://native.example.test",
    authToken: "synthetic-test-token",
  },
  { transport: "stdio", remoteWorkspaceRoot: "/remote/workspace" },
])("leaves protected remote bindings on normal reuse: %j", async (connection) => {
  const agentDir = "/tmp/native-catalog-agent";
  const appServer = resolveRuntimeForTest({ pluginConfig: { appServer: connection } });
  const harness = createClientHarness();
  const identity = vi.spyOn(harness.client, "getRuntimeIdentity").mockReturnValue({
    serverVersion: CODEX_APP_SERVER_VERSION,
    codexHome: resolveCodexAppServerLocalHomeDir(appServer.start, agentDir),
  });
  ensureCodexAppServerClientRuntime(harness.client, { agentDir });
  const unprotect = protectCodexAppServerLiveThread(harness.client, threadId);
  const shared = getSharedCodexAppServerClientState();
  const entry = getOrCreateSharedClientEntry(
    shared,
    `remote-catalog:${harness.client.getInstanceId()}`,
  );
  entry.client = harness.client;
  shared.liveClients.add(harness.client);
  shared.entriesByClient.set(harness.client, entry);
  const acquireClient = vi.fn(async () => harness.client);
  try {
    await expect(
      loadCodexAttemptNativeToolCatalog({
        binding: {
          threadId,
          cwd: "/workspace",
          clientId: harness.client.getInstanceId(),
          dynamicToolsFingerprint: codexDynamicToolsFingerprint([tool]),
          appServerRuntimeFingerprint: buildCodexAppServerRuntimeFingerprint({
            appServer,
            appServerVersion: harness.client.getServerVersion(),
            runtimeIdentity: harness.client.getRuntimeIdentity(),
          }),
        },
        appServer,
        agentDir,
        assertCurrent: () => {},
        signal: new AbortController().signal,
        acquireClient,
        releaseClient: vi.fn(),
      }),
    ).resolves.toBeUndefined();
    expect(acquireClient).not.toHaveBeenCalled();
    expect(harness.writes).toHaveLength(0);
    expect(entry.activeLeases).toBe(0);
    expect(harness.client.getCloseError()).toBeUndefined();
  } finally {
    unprotect();
    shared.clients.delete(entry.key);
    shared.liveClients.delete(harness.client);
    shared.entriesByClient.delete(harness.client);
    identity.mockRestore();
    await harness.client.closeAndWait();
  }
});

it("loads a protected managed catalog only with its original runtime fingerprint", async () => {
  await withTempDir("codex-managed-catalog-", async (agentDir) => {
    const appServer = resolveRuntimeForTest();
    const harness = createClientHarness();
    const codexHome = resolveCodexAppServerLocalHomeDir(appServer.start, agentDir);
    const identity = vi.spyOn(harness.client, "getRuntimeIdentity").mockReturnValue({
      serverVersion: CODEX_APP_SERVER_VERSION,
      codexHome,
    });
    ensureCodexAppServerClientRuntime(harness.client, { agentDir });
    const unprotect = protectCodexAppServerLiveThread(harness.client, threadId);
    const shared = getSharedCodexAppServerClientState();
    const entry = getOrCreateSharedClientEntry(
      shared,
      `managed-catalog:${harness.client.getInstanceId()}`,
    );
    entry.client = harness.client;
    shared.liveClients.add(harness.client);
    shared.entriesByClient.set(harness.client, entry);
    const acquireClient = vi.fn(async () => harness.client);
    try {
      const rolloutPath = path.join(codexHome, "sessions", `rollout-${threadId}.jsonl`);
      await fs.mkdir(path.dirname(rolloutPath), { recursive: true });
      await fs.writeFile(
        rolloutPath,
        JSON.stringify({
          type: "session_meta",
          payload: { id: threadId, dynamic_tools: [tool] },
        }) + "\n",
      );
      const runtime = {
        appServer,
        appServerVersion: harness.client.getServerVersion(),
        runtimeIdentity: harness.client.getRuntimeIdentity(),
      };
      const binding = {
        threadId,
        cwd: agentDir,
        rolloutPath,
        clientId: harness.client.getInstanceId(),
        dynamicToolsFingerprint: codexDynamicToolsFingerprint([tool]),
        appServerRuntimeFingerprint: buildCodexAppServerRuntimeFingerprint(runtime),
      };
      const params = {
        binding,
        appServer,
        agentDir,
        assertCurrent: () => {},
        signal: new AbortController().signal,
        acquireClient,
        releaseClient: vi.fn(),
      };
      await expect(loadCodexAttemptNativeToolCatalog(params)).resolves.toEqual([tool]);
      for (const fingerprint of [
        buildCodexAppServerConnectionFingerprint(appServer, agentDir),
        buildCodexAppServerRuntimeFingerprint({ ...runtime, appServerVersion: "0.0.0" }),
      ]) {
        await expect(
          loadCodexAttemptNativeToolCatalog({
            ...params,
            binding: { ...binding, appServerRuntimeFingerprint: fingerprint },
          }),
        ).rejects.toThrow("original verified local binding");
      }
      expect(acquireClient).not.toHaveBeenCalled();
      expect(harness.writes).toHaveLength(0);
      expect(entry.activeLeases).toBe(0);
      expect(harness.client.getCloseError()).toBeUndefined();
    } finally {
      unprotect();
      shared.clients.delete(entry.key);
      shared.liveClients.delete(harness.client);
      shared.entriesByClient.delete(harness.client);
      identity.mockRestore();
      await harness.client.closeAndWait();
    }
  });
});

describe("parseCodexNativeToolCatalog", () => {
  it.each([{}, { dynamic_tools: null }, { dynamic_tools: [] }])(
    "restores the native empty representation %j without accepting a missing nonempty catalog",
    (catalog) => {
      const metadata = { id: threadId, ...catalog };
      expect(
        parseCodexNativeToolCatalog(metadata, threadId, codexDynamicToolsFingerprint([])),
      ).toEqual([]);
      expect(() =>
        parseCodexNativeToolCatalog(metadata, threadId, codexDynamicToolsFingerprint([tool])),
      ).toThrow("native tool catalog is missing, corrupt, or changed");
    },
  );

  it.each([
    null,
    {},
    { id: "other" },
    ...[{}, [null]].map((dynamic_tools) => ({ id: threadId, dynamic_tools })),
  ])("rejects invalid metadata %j", (metadata) => {
    expect(() => parseCodexNativeToolCatalog(metadata, threadId)).toThrow(
      "native tool catalog is missing, corrupt, or changed",
    );
  });

  it("retains nonempty declarations and the pinned false-defer omission", () => {
    expect(
      parseCodexNativeToolCatalog(
        { id: threadId, dynamic_tools: [{ ...tool, deferLoading: false }] },
        threadId,
        codexDynamicToolsFingerprint([tool]),
      ),
    ).toEqual([tool]);
  });
});
