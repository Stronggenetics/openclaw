import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import { resolveRequestUrl } from "../../plugin-sdk/request-url.js";
import {
  cleanupPluginLoaderFixturesForTest,
  loadOpenClawPlugins,
  resetPluginLoaderTestStateForTest,
  writePlugin,
} from "../../plugins/loader.test-fixtures.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { isOAuthRefreshFence } from "../auth-profiles/oauth-refresh-marker.js";
import { resolveApiKeyForProfile } from "../auth-profiles/oauth.js";
import { loadPersistedAuthProfileStore } from "../auth-profiles/persisted.js";
import { writePersistedAuthProfileStoreRaw } from "../auth-profiles/sqlite.js";
import type { OAuthCredential } from "../auth-profiles/types.js";
import { getAuthStorageOAuthProviderRegistry } from "./auth-storage-oauth-registry.js";
import { AuthStorage } from "./auth-storage.js";

const provider = "fixture-oauth";
const profileId = provider + ":default";
const original: OAuthCredential = {
  type: "oauth",
  provider,
  access: "synthetic-old-access",
  refresh: "synthetic-old-refresh",
  expires: 1,
};
const endpoint = "https://oauth.example.test/token";
// The fixture is admitted as a third-party plugin and imports only the public SDK.
// The real runtime, HTTP parser, and SQLite refresh owner remain in the path.
const body = [
  'const { createOAuthRefreshError, createOAuthRefreshResponseError } = require("openclaw/plugin-sdk/provider-oauth-runtime");',
  'module.exports = { id: "fixture-oauth", register(api) {',
  'api.registerProvider({ id: "fixture-oauth", label: "Fixture OAuth", auth: [], async refreshOAuth(cred) {',
  'const discovery = await fetch("https://oauth.example.test/discovery");',
  'if (!discovery.ok) throw createOAuthRefreshError("discovery unavailable", { version: 1, phase: "before-dispatch", outcome: "not-attempted", recovery: { kind: "later", evidence: "dispatch-not-started" } });',
  'const response = await fetch((await discovery.json()).token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: cred.refresh }) });',
  "const data = await response.json();",
  'if (data.legacy) throw Object.assign(new Error("legacy retry hint"), { oauthRefreshFailure: { retryable: true } });',
  'if (data.unknownVersion) throw Object.assign(new Error("future outcome"), { oauthRefreshOutcome: { version: 999, phase: "before-dispatch", outcome: "not-attempted", recovery: { kind: "later", evidence: "dispatch-not-started" } }});',
  'if (!response.ok || data.error) throw new Error("adapter wrapper", { cause: createOAuthRefreshResponseError("fixture rejected", response.status, data) });',
  'if (typeof data.access_token !== "string" || typeof data.refresh_token !== "string") throw new Error("invalid response");',
  "return { ...cred, access: data.access_token, refresh: data.refresh_token, expires: Date.now() + 600000 };",
  "}}); }};",
].join("\n");

afterEach(() => {
  vi.unstubAllGlobals();
  resetPluginLoaderTestStateForTest();
});
afterAll(cleanupPluginLoaderFixturesForTest);

for (const owner of ["native plugin", "registered SDK provider"] as const) {
  describe(owner + " public outcome compatibility", () => {
    it.each(["success", "discovery", "rejected", "unknown", "legacy", "unknown-version"] as const)(
      "%s preserves real HTTP and durable settlement",
      async (mode) =>
        withOpenClawTestState({ layout: "state-only", prefix: "custom-oauth-" }, async (state) => {
          const plugin = writePlugin({ id: provider, body });
          const cfg: OpenClawConfig = {
            plugins: {
              allow: [provider],
              load: { paths: [plugin.file] },
              slots: { memory: "none" },
              entries: { [provider]: { enabled: true } },
            },
          };
          await state.writeConfig(cfg);
          const registry = loadOpenClawPlugins({
            config: cfg,
            cache: false,
            onlyPluginIds: [provider],
          });
          expect(
            registry.plugins.find((p) => p.id === provider)?.status,
            JSON.stringify(registry.diagnostics),
          ).toBe("loaded");
          const adapter = registry.providers.find((p) => p.provider.id === provider)?.provider
            .refreshOAuth;
          if (!adapter) {
            throw new Error("Fixture adapter was not registered");
          }
          const dir = state.agentDir();
          writePersistedAuthProfileStoreRaw(
            { version: 1, profiles: { [profileId]: original } },
            dir,
          );
          let discoveries = 0;
          let exchanges = 0;
          vi.stubGlobal(
            "fetch",
            vi.fn<typeof fetch>(async (url, init) => {
              if (resolveRequestUrl(url).endsWith("/discovery")) {
                discoveries++;
                return mode === "discovery" && discoveries === 1
                  ? new Response(null, { status: 503 })
                  : Response.json({ token_endpoint: endpoint });
              }
              expect(resolveRequestUrl(url)).toBe(endpoint);
              expect(init?.method).toBe("POST");
              expect(
                Object.fromEntries(new URLSearchParams(await new Response(init?.body).text())),
              ).toEqual({
                grant_type: "refresh_token",
                refresh_token: original.refresh,
              });
              exchanges++;
              if (mode === "unknown") {
                throw new Error("socket closed after consuming grant");
              }
              if (mode === "rejected") {
                return Response.json({ error: { code: "invalid_grant" } });
              }
              if (mode === "legacy") {
                return Response.json({ legacy: true });
              }
              if (mode === "unknown-version") {
                return Response.json({ unknownVersion: true });
              }
              return Response.json({
                access_token: "synthetic-new-access",
                refresh_token: "synthetic-new-refresh",
              });
            }),
          );
          const sdk = await AuthStorage.forAgentAsync(dir, cfg);
          getAuthStorageOAuthProviderRegistry(sdk).register({
            id: provider,
            name: "Fixture OAuth",
            login: async () => {
              throw new Error("unused login");
            },
            refreshToken: (cred) => adapter({ ...cred, type: "oauth", provider }, cfg),
            getApiKey: (cred) => cred.access,
          });
          const resolve = async () =>
            owner === "registered SDK provider"
              ? sdk.getApiKey(provider, { includeFallback: false })
              : (
                  await resolveApiKeyForProfile({
                    cfg,
                    store: loadPersistedAuthProfileStore(dir)!,
                    profileId,
                    agentDir: dir,
                    allowProfileFallback: false,
                  })
                )?.apiKey;
          if (mode === "success") {
            await expect(resolve()).resolves.toBe("synthetic-new-access");
          } else {
            if (owner === "native plugin") {
              await expect(resolve()).rejects.toThrow("OAuth token refresh failed");
            } else {
              await expect(resolve()).resolves.toBeUndefined();
            }
            if (mode === "discovery") {
              expect(loadPersistedAuthProfileStore(dir)?.profiles[profileId]).toEqual(original);
              expect(exchanges).toBe(0);
              await expect(resolve()).resolves.toBe("synthetic-new-access");
            } else {
              const value = loadPersistedAuthProfileStore(dir)?.profiles[profileId];
              expect(isOAuthRefreshFence(value?.type === "oauth" ? value : undefined)).toBe(true);
              await expect(resolve()).resolves.toBeUndefined();
            }
          }
          if (mode === "success" || mode === "discovery") {
            expect(loadPersistedAuthProfileStore(dir)?.profiles[profileId]).toMatchObject({
              access: "synthetic-new-access",
              refresh: "synthetic-new-refresh",
            });
            await expect(resolve()).resolves.toBe("synthetic-new-access");
          }
          expect(exchanges).toBe(1);
          expect(discoveries).toBe(mode === "discovery" ? 2 : 1);
        }),
    );
  });
}
