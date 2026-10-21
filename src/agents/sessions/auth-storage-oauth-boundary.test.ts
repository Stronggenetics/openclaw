import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveRequestUrl } from "../../plugin-sdk/request-url.js";
import { loadOpenClawPlugins, clearPluginRegistryLoadCache } from "../../plugins/loader.js";
import { resetPluginRuntimeStateForTest } from "../../plugins/runtime.js";
import { createDeferredCore } from "../../shared/deferred.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { isOAuthRefreshFence } from "../auth-profiles/oauth-refresh-marker.js";
import { resolveApiKeyForProfile } from "../auth-profiles/oauth.js";
import { loadPersistedAuthProfileStore } from "../auth-profiles/persisted.js";
import { writePersistedAuthProfileStoreRaw } from "../auth-profiles/sqlite.js";
import type { OAuthCredential } from "../auth-profiles/types.js";
import * as sdkRefresh from "./auth-storage-oauth-refresh.js";
import { AuthStorage } from "./auth-storage.js";

const original: OAuthCredential = {
  type: "oauth",
  provider: "xai",
  accountId: "synthetic-account",
  access: "synthetic-old-access",
  refresh: "synthetic-old-refresh",
  expires: 1,
};
const endpoint = "https://auth.x.ai/oauth2/token";
const rotated = {
  access_token: "synthetic-new-access",
  refresh_token: "synthetic-new-refresh",
  expires_in: 3600,
};

async function storage(agentDir: string, pluginId = "xai") {
  const registry = loadOpenClawPlugins({
    config: { plugins: { allow: [pluginId], entries: { [pluginId]: { enabled: true } } } },
    cache: false,
    onlyPluginIds: [pluginId],
  });
  expect(
    registry.plugins.find((plugin) => plugin.id === pluginId)?.status,
    JSON.stringify(registry.diagnostics),
  ).toBe("loaded");
  return await AuthStorage.forAgentAsync(agentDir);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearPluginRegistryLoadCache();
  resetPluginRuntimeStateForTest();
});

describe("bundled OAuth adapter through SQLite SDK owner", () => {
  it("restores a discovery-only failure and permits a later intentional refresh", async () => {
    await withOpenClawTestState(
      { layout: "state-only", prefix: "oauth-boundary-discovery-" },
      async (state) => {
        await state.writeConfig({
          plugins: { allow: ["xai"], entries: { xai: { enabled: true } } },
        });
        const dir = state.agentDir();
        writePersistedAuthProfileStoreRaw(
          { version: 1, profiles: { "xai:default": original } },
          dir,
        );
        const requests: Array<{ url: string; body: string }> = [];
        vi.stubGlobal(
          "fetch",
          vi.fn<typeof fetch>(async (url, init) => {
            requests.push({
              url: resolveRequestUrl(url),
              body: await new Response(init?.body).text(),
            });
            if (requests.length === 1) {
              return Response.json({ error: "temporarily_unavailable" }, { status: 503 });
            }
            if (resolveRequestUrl(url).includes("openid-configuration")) {
              return Response.json({ token_endpoint: endpoint });
            }
            return Response.json(rotated);
          }),
        );
        await expect(
          (await storage(dir)).getApiKey("xai", { includeFallback: false }),
        ).resolves.toBeUndefined();
        expect(loadPersistedAuthProfileStore(dir)?.profiles["xai:default"]).toEqual(original);
        expect(requests).toHaveLength(1);
        await expect(
          (await storage(dir)).getApiKey("xai", { includeFallback: false }),
        ).resolves.toBe(rotated.access_token);
        expect(requests.filter((request) => request.url === endpoint)).toEqual([
          {
            url: endpoint,
            body: "grant_type=refresh_token&client_id=b1a00492-073a-47ea-816f-4c329264a828&refresh_token=synthetic-old-refresh",
          },
        ]);
        expect(loadPersistedAuthProfileStore(dir)?.profiles["xai:default"]).toMatchObject({
          access: rotated.access_token,
          refresh: rotated.refresh_token,
        });
      },
    );
  });

  it.each(["socket-close", "html-503", "malformed-success"] as const)(
    "does not replay a possibly consumed token after %s",
    async (outcome) => {
      await withOpenClawTestState(
        { layout: "state-only", prefix: "oauth-boundary-consumed-" },
        async (state) => {
          await state.writeConfig({
            plugins: { allow: ["xai"], entries: { xai: { enabled: true } } },
          });
          const dir = state.agentDir();
          writePersistedAuthProfileStoreRaw(
            { version: 1, profiles: { "xai:default": { ...original, tokenEndpoint: endpoint } } },
            dir,
          );
          let consumed = 0;
          vi.stubGlobal(
            "fetch",
            vi.fn<typeof fetch>(async (_url, init) => {
              expect(
                new URLSearchParams(await new Response(init?.body).text()).get("refresh_token"),
              ).toBe(original.refresh);
              consumed += 1;
              if (outcome === "socket-close") {
                throw Object.assign(new Error("socket closed after consuming grant"), {
                  code: "ECONNRESET",
                });
              }
              if (outcome === "html-503") {
                return new Response("<html>temporary upstream error</html>", {
                  status: 503,
                  headers: { "content-type": "text/html" },
                });
              }
              return new Response('{"access_token":', { status: 200 });
            }),
          );
          await expect(
            (await storage(dir)).getApiKey("xai", { includeFallback: false }),
          ).resolves.toBeUndefined();
          const persisted = loadPersistedAuthProfileStore(dir)?.profiles["xai:default"];
          expect(isOAuthRefreshFence(persisted?.type === "oauth" ? persisted : undefined)).toBe(
            true,
          );
          await expect(
            (await storage(dir)).getApiKey("xai", { includeFallback: false }),
          ).resolves.toBeUndefined();
          expect(consumed).toBe(1);
        },
      );
    },
  );
});

for (const owner of ["native manager", "SDK AuthStorage"] as const) {
  it.each(["coalesced waiters", "newer login"] as const)(
    owner + " preserves the real HTTP claim with %s",
    async (mode) =>
      withOpenClawTestState(
        { layout: "state-only", prefix: "oauth-real-owner-" },
        async (state) => {
          const cfg = { plugins: { allow: ["xai"], entries: { xai: { enabled: true } } } };
          await state.writeConfig(cfg);
          const dir = state.agentDir();
          const initial = { ...original, tokenEndpoint: endpoint };
          writePersistedAuthProfileStoreRaw(
            { version: 1, profiles: { "xai:default": initial } },
            dir,
          );
          const sdk = await storage(dir);
          const secondSdk = await storage(dir);
          const entered = createDeferredCore();
          const release = createDeferredCore();
          let requests = 0;
          vi.stubGlobal(
            "fetch",
            vi.fn<typeof fetch>(async (url, init) => {
              expect(resolveRequestUrl(url)).toBe(endpoint);
              expect(
                new URLSearchParams(await new Response(init?.body).text()).get("refresh_token"),
              ).toBe(original.refresh);
              requests++;
              entered.resolve();
              await release.promise;
              return Response.json(rotated);
            }),
          );
          const resolve = async (target = sdk) =>
            owner === "SDK AuthStorage"
              ? target.getApiKey("xai", { includeFallback: false })
              : (
                  await resolveApiKeyForProfile({
                    cfg,
                    store: loadPersistedAuthProfileStore(dir)!,
                    profileId: "xai:default",
                    agentDir: dir,
                    allowProfileFallback: false,
                  })
                )?.apiKey;
          const first = resolve();
          await entered.promise;
          const newer = {
            ...initial,
            access: "synthetic-new-login",
            refresh: "synthetic-new-login-refresh",
            expires: Date.now() + 600000,
          };
          let second: Promise<string | undefined> | undefined;
          try {
            if (mode === "newer login") {
              writePersistedAuthProfileStoreRaw(
                { version: 1, profiles: { "xai:default": newer } },
                dir,
              );
            } else {
              const admitted = createDeferredCore();
              if (owner === "SDK AuthStorage") {
                // Observe the real serialized entry, without replacing its backend or refresh.
                const refresh = sdkRefresh.refreshAuthStorageOAuthCredential;
                vi.spyOn(sdkRefresh, "refreshAuthStorageOAuthCredential").mockImplementation(
                  (params) => {
                    const work = refresh(params);
                    admitted.resolve();
                    return work;
                  },
                );
              } else {
                const { KeyedAsyncQueue } = await import("../../plugin-sdk/keyed-async-queue.js");
                // oxlint-disable-next-line typescript/unbound-method -- Preserve the native queue receiver.
                const enqueue = KeyedAsyncQueue.prototype.enqueue;
                vi.spyOn(KeyedAsyncQueue.prototype, "enqueue").mockImplementation(function (
                  this: InstanceType<typeof KeyedAsyncQueue>,
                  key,
                  task,
                  hooks,
                ) {
                  return enqueue.call(this, key, task, {
                    ...hooks,
                    onEnqueue() {
                      hooks?.onEnqueue?.();
                      admitted.resolve();
                    },
                  });
                });
              }
              second = resolve(secondSdk);
              await admitted.promise;
              expect(requests).toBe(1);
            }
          } finally {
            release.resolve();
          }
          const expected = mode === "newer login" ? newer.access : rotated.access_token;
          await expect(first).resolves.toBe(expected);
          if (second) {
            await expect(second).resolves.toBe(expected);
          }
          expect(loadPersistedAuthProfileStore(dir)?.profiles["xai:default"]).toMatchObject(
            mode === "newer login"
              ? newer
              : { access: rotated.access_token, refresh: rotated.refresh_token },
          );
          await expect(resolve()).resolves.toBe(expected);
          expect(requests).toBe(1);
        },
      ),
  );
}

it("a native caller detaches without cancelling real HTTP rotation or durable settlement", async () => {
  await withOpenClawTestState(
    { layout: "state-only", prefix: "oauth-real-detach-" },
    async (state) => {
      const cfg = { plugins: { allow: ["xai"], entries: { xai: { enabled: true } } } };
      await state.writeConfig(cfg);
      const dir = state.agentDir();
      writePersistedAuthProfileStoreRaw(
        { version: 1, profiles: { "xai:default": { ...original, tokenEndpoint: endpoint } } },
        dir,
      );
      await storage(dir);
      const entered = createDeferredCore();
      const release = createDeferredCore();
      let requests = 0;
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>(async (_url, init) => {
          expect(
            new URLSearchParams(await new Response(init?.body).text()).get("refresh_token"),
          ).toBe(original.refresh);
          requests++;
          entered.resolve();
          await release.promise;
          expect(init?.signal?.aborted).not.toBe(true);
          return Response.json(rotated);
        }),
      );
      const abort = new AbortController();
      const resolve = async (signal?: AbortSignal) =>
        (
          await resolveApiKeyForProfile({
            cfg,
            store: loadPersistedAuthProfileStore(dir)!,
            profileId: "xai:default",
            agentDir: dir,
            allowProfileFallback: false,
            signal,
          })
        )?.apiKey;
      const first = resolve(abort.signal).then(
        () => "published",
        () => "detached",
      );
      await entered.promise;
      abort.abort();
      try {
        expect(await first).toBe("detached");
      } finally {
        release.resolve();
      }
      await expect(resolve()).resolves.toBe(rotated.access_token);
      expect(loadPersistedAuthProfileStore(dir)?.profiles["xai:default"]).toMatchObject({
        access: rotated.access_token,
        refresh: rotated.refresh_token,
      });
      expect(requests).toBe(1);
    },
  );
});

for (const owner of ["native manager", "SDK AuthStorage"] as const) {
  it(owner + " persists the real Copilot projection without a refresh-token POST", async () => {
    await withOpenClawTestState(
      { layout: "state-only", prefix: "oauth-copilot-owner-" },
      async (state) => {
        const cfg = {
          plugins: { allow: ["github-copilot"], entries: { "github-copilot": { enabled: true } } },
        };
        await state.writeConfig(cfg);
        const dir = state.agentDir();
        const credential = { ...original, provider: "github-copilot" };
        writePersistedAuthProfileStoreRaw(
          { version: 1, profiles: { "github-copilot:default": credential } },
          dir,
        );
        const sdk = await storage(dir, "github-copilot");
        const network = vi.fn<typeof fetch>(async () => {
          throw new Error("projection must not send a refresh grant");
        });
        vi.stubGlobal("fetch", network);
        const result =
          owner === "SDK AuthStorage"
            ? await sdk.getApiKey("github-copilot", { includeFallback: false })
            : (
                await resolveApiKeyForProfile({
                  cfg,
                  store: loadPersistedAuthProfileStore(dir)!,
                  profileId: "github-copilot:default",
                  agentDir: dir,
                  allowProfileFallback: false,
                })
              )?.apiKey;
        expect(result).toBe(credential.refresh);
        expect(loadPersistedAuthProfileStore(dir)?.profiles["github-copilot:default"]).toEqual({
          ...credential,
          access: credential.refresh,
          expires: 8_640_000_000_000_000,
        });
        expect(network).not.toHaveBeenCalled();
      },
    );
  });

  it.each([
    {
      plugin: "minimax",
      provider: "minimax-portal",
      profileId: "minimax-portal:minimax-cli",
      authFlow: "external-cli",
    },
    {
      plugin: "google",
      provider: "google-gemini-cli",
      profileId: "google-gemini-cli:default",
      authFlow: undefined,
    },
  ])(
    owner + " does not invent a native refresh for $provider",
    async ({ plugin, provider, profileId, authFlow }) => {
      await withOpenClawTestState(
        { layout: "state-only", prefix: "oauth-unsupported-owner-" },
        async (state) => {
          const cfg = { plugins: { allow: [plugin], entries: { [plugin]: { enabled: true } } } };
          await state.writeConfig(cfg);
          const dir = state.agentDir();
          const credential = { ...original, provider, ...(authFlow ? { authFlow } : {}) };
          writePersistedAuthProfileStoreRaw(
            { version: 1, profiles: { [profileId]: credential } },
            dir,
          );
          const sdk = await storage(dir, plugin);
          const network = vi.fn<typeof fetch>(async () => {
            throw new Error("unsupported owner must not send a refresh grant");
          });
          vi.stubGlobal("fetch", network);
          const result =
            owner === "SDK AuthStorage"
              ? await sdk.getApiKey(provider, { includeFallback: false })
              : (
                  await resolveApiKeyForProfile({
                    cfg,
                    store: loadPersistedAuthProfileStore(dir)!,
                    profileId,
                    agentDir: dir,
                    allowProfileFallback: false,
                  })
                )?.apiKey;
          expect(result).toBeUndefined();
          expect(loadPersistedAuthProfileStore(dir)?.profiles[profileId]).toEqual(credential);
          expect(network).not.toHaveBeenCalled();
        },
      );
    },
  );
}
