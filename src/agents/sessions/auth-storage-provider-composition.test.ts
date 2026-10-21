import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import { resolveRequestUrl } from "../../plugin-sdk/request-url.js";
import { clearPluginRegistryLoadCache, loadOpenClawPlugins } from "../../plugins/loader.js";
import { resetPluginRuntimeStateForTest } from "../../plugins/runtime.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { isOAuthRefreshFence } from "../auth-profiles/oauth-refresh-marker.js";
import { resolveApiKeyForProfile } from "../auth-profiles/oauth.js";
import { loadPersistedAuthProfileStore } from "../auth-profiles/persisted.js";
import { writePersistedAuthProfileStoreRaw } from "../auth-profiles/sqlite.js";
import type { OAuthCredential } from "../auth-profiles/types.js";
import { AuthStorage } from "./auth-storage.js";

// Shared unit setup stubs this facade; this integration exercises the real builtin adapters.
vi.unmock("../../llm/oauth.js");

const oldRefresh = "synthetic-old-refresh";
const nextRefresh = "synthetic-next-refresh";
const nextAccess = "synthetic-next-access";
const issuer = "https://auth.openai.com";
const clientId = "oaiapp_synthetic_registered";
const jwt = (claims: object) =>
  [
    "eyJhbGciOiJub25lIn0",
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "synthetic",
  ].join(".");
const codexAccess = jwt({
  "https://api.openai.com/auth": { chatgpt_account_id: "synthetic-account" },
});
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = {
  ...keys.publicKey.export({ format: "jwk" }),
  kid: "synthetic-signing-key",
  alg: "RS256",
};
let idToken: string;
beforeAll(() => {
  const now = Math.floor(Date.now() / 1000);
  const input = [
    Buffer.from(JSON.stringify({ alg: "RS256", kid: "synthetic-signing-key" })).toString(
      "base64url",
    ),
    Buffer.from(
      JSON.stringify({
        sub: "synthetic-subject",
        iss: issuer,
        aud: clientId,
        iat: now,
        exp: now + 3600,
      }),
    ).toString("base64url"),
  ].join(".");
  idToken =
    input + "." + sign("RSA-SHA256", Buffer.from(input), keys.privateKey).toString("base64url");
});

type Route = {
  name: string;
  provider: string;
  plugin?: string;
  endpoint: string;
  json?: boolean;
  fields: Record<string, string>;
  extra?: () => Partial<OAuthCredential>;
  response?: () => object;
  access?: string;
  env?: Record<string, string>;
};
const standard = { access_token: nextAccess, refresh_token: nextRefresh, expires_in: 3600 };
const routes: Route[] = [
  {
    name: "Anthropic builtin",
    provider: "anthropic",
    endpoint: "https://platform.claude.com/v1/oauth/token",
    json: true,
    fields: { client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e" },
  },
  {
    name: "OpenAI standard plugin",
    provider: "openai",
    plugin: "openai",
    endpoint: issuer + "/oauth/token",
    access: codexAccess,
    fields: { client_id: "app_EMoamEEZ73f0CkXaXp7hrann" },
    extra: () => ({ accountId: "synthetic-account" }),
    response: () => ({ ...standard, access_token: codexAccess }),
  },
  {
    name: "OpenAI builtin facade",
    provider: "openai",
    endpoint: issuer + "/oauth/token",
    access: codexAccess,
    fields: { client_id: "app_EMoamEEZ73f0CkXaXp7hrann" },
    extra: () => ({ accountId: "synthetic-account" }),
    response: () => ({ ...standard, access_token: codexAccess }),
  },
  ...["chatgpt-token-sharing", "chatgpt-identity"].map((flow): Route => ({
    name: "OpenAI " + flow,
    provider: "openai",
    plugin: "openai",
    endpoint: issuer + "/api/accounts/oauth/token",
    fields: { client_id: clientId, resource: "https://api.openai.com/v1" },
    extra: () => ({
      authFlow: flow,
      issuer,
      clientId,
      tokenEndpoint: issuer + "/api/accounts/oauth/token",
      idToken,
      accountId: createHash("sha256")
        .update(issuer + "\0" + clientId + "\0synthetic-subject")
        .digest("hex"),
      grantedScope:
        flow === "chatgpt-token-sharing" ? "resource.invoke chatgpt.tokens.use.direct" : "openid",
    }),
    response: () => ({ ...standard, id_token: idToken, token_type: "Bearer" }),
  })),
  {
    name: "Chutes stored public client",
    provider: "chutes",
    plugin: "chutes",
    endpoint: "https://api.chutes.ai/idp/token",
    fields: { client_id: "synthetic-client" },
    extra: () => ({ clientId: "synthetic-client" }),
  },
  {
    name: "Chutes confidential client",
    provider: "chutes",
    plugin: "chutes",
    endpoint: "https://api.chutes.ai/idp/token",
    fields: { client_id: "synthetic-client", client_secret: "synthetic-client-secret" },
    extra: () => ({ clientId: "synthetic-client" }),
    env: { CHUTES_CLIENT_SECRET: "synthetic-client-secret" },
  },
  ...["global", "cn"].map((region): Route => ({
    name: "MiniMax " + region,
    provider: "minimax-portal",
    plugin: "minimax",
    endpoint:
      "https://account." + (region === "cn" ? "minimaxi.com" : "minimax.io") + "/oauth2/token",
    fields: { client_id: "78257093-7e40-4613-99e0-527b14b39113" },
    extra: () => ({
      tokenEndpoint:
        "https://account." + (region === "cn" ? "minimaxi.com" : "minimax.io") + "/oauth2/token",
    }),
    response: () => ({
      status: "success",
      access_token: nextAccess,
      refresh_token: nextRefresh,
      expired_in: 3600,
    }),
  })),
  {
    name: "Radius",
    provider: "radius",
    plugin: "radius",
    endpoint: "https://radius.pi.dev/v1/oauth/token",
    fields: { client_id: "pi-gateway" },
    response: () => ({ ...standard, scope: "gateway offline_access" }),
  },
  {
    name: "xAI cached endpoint",
    provider: "xai",
    plugin: "xai",
    endpoint: "https://auth.x.ai/oauth2/token",
    fields: { client_id: "b1a00492-073a-47ea-816f-4c329264a828" },
    extra: () => ({ tokenEndpoint: "https://auth.x.ai/oauth2/token" }),
  },
];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  clearPluginRegistryLoadCache();
  resetPluginRuntimeStateForTest();
});

for (const owner of ["model manager", "SDK AuthStorage"] as const) {
  describe(owner + " real bundled refresh composition", () => {
    it.each(routes)("$name serializes, parses and durably publishes rotation", async (route) => {
      await run(route, "success");
    });
    it.each(routes.filter((route) => route.provider !== "anthropic"))(
      "$name preserves an explicitly omitted unchanged refresh token",
      async (route) => {
        await run(route, "omitted-refresh");
      },
    );
    it.each(routes)(
      "$name fences a malformed returned rotation rather than retaining the old token",
      async (route) => {
        await run(route, "invalid-refresh");
      },
    );
    it.each(routes.filter((route) => route.name.includes("chatgpt-")))(
      "$name never restores a consumed grant after identity verification fails",
      async (route) => {
        await run(route, "identity-failure");
      },
    );
    it.each(routes)(
      "$name quarantines a consumed grant despite a transient-looking lost response",
      async (route) => {
        await run(route, "socket");
      },
    );
    it.each(routes)(
      "$name preserves structured rejection on HTTP 200 without replay",
      async (route) => {
        await run(route, "rejected");
      },
    );
  });

  async function run(
    route: Route,
    mode:
      | "success"
      | "omitted-refresh"
      | "invalid-refresh"
      | "identity-failure"
      | "socket"
      | "rejected",
  ) {
    await withOpenClawTestState(
      { layout: "state-only", prefix: "oauth-real-adapter-" },
      async (state) => {
        vi.stubEnv("CHUTES_CLIENT_SECRET", "");
        for (const [name, value] of Object.entries(route.env ?? {})) {
          vi.stubEnv(name, value);
        }
        const cfg: OpenClawConfig = {
          plugins: {
            allow: route.plugin ? [route.plugin] : [],
            entries: route.plugin ? { [route.plugin]: { enabled: true } } : {},
          },
        };
        await state.writeConfig(cfg);
        if (route.plugin) {
          const registry = loadOpenClawPlugins({
            config: cfg,
            cache: false,
            onlyPluginIds: [route.plugin],
          });
          expect(
            registry.plugins.find((plugin) => plugin.id === route.plugin)?.status,
            JSON.stringify(registry.diagnostics),
          ).toBe("loaded");
        }
        const dir = state.agentDir();
        const profileId = route.provider + ":default";
        const credential: OAuthCredential = {
          type: "oauth",
          provider: route.provider,
          access: "synthetic-old-access",
          refresh: oldRefresh,
          expires: 1,
          ...route.extra?.(),
        };
        writePersistedAuthProfileStoreRaw(
          { version: 1, profiles: { [profileId]: credential } },
          dir,
        );
        let grantsConsumed = 0;
        vi.stubGlobal(
          "fetch",
          vi.fn<typeof fetch>(async (url, init) => {
            if (resolveRequestUrl(url) === issuer + "/.well-known/jwks.json") {
              if (mode === "identity-failure") {
                return Response.json({ keys: [] });
              }
              return Response.json({ keys: [jwk] });
            }
            expect(resolveRequestUrl(url)).toBe(route.endpoint);
            expect(init?.method).toBe("POST");
            const headers = new Headers(init?.headers);
            expect(headers.get("content-type")).toContain(
              route.json ? "application/json" : "application/x-www-form-urlencoded",
            );
            const body: unknown = route.json
              ? JSON.parse(await new Response(init?.body).text())
              : Object.fromEntries(new URLSearchParams(await new Response(init?.body).text()));
            expect(body).toEqual({
              grant_type: "refresh_token",
              refresh_token: oldRefresh,
              ...route.fields,
            });
            grantsConsumed += 1;
            if (mode === "socket") {
              throw Object.assign(new Error("connection reset after consuming synthetic grant"), {
                code: "ECONNRESET",
              });
            }
            if (mode === "rejected") {
              return Response.json({
                error: { code: "invalid_grant" },
                error_description: "synthetic rejection",
              });
            }
            const response: Record<string, unknown> = { ...(route.response?.() ?? standard) };
            if (mode === "omitted-refresh") {
              delete response.refresh_token;
            }
            if (mode === "invalid-refresh") {
              response.refresh_token = null;
            }
            return Response.json(response);
          }),
        );
        const resolve = async () => {
          if (owner === "SDK AuthStorage") {
            const storage = await AuthStorage.forAgentAsync(dir, cfg);
            const value = await storage.getApiKey(route.provider, { includeFallback: false });
            if (grantsConsumed === 0) {
              expect(
                storage
                  .drainErrors()
                  .map((error) => error.stack)
                  .join("\n"),
              ).toBe("");
            }
            return value;
          }
          return (
            await resolveApiKeyForProfile({
              cfg,
              store: loadPersistedAuthProfileStore(dir)!,
              profileId,
              agentDir: dir,
              allowProfileFallback: false,
            })
          )?.apiKey;
        };
        if (mode === "success" || mode === "omitted-refresh") {
          await expect(resolve()).resolves.toBe(route.access ?? nextAccess);
          expect(loadPersistedAuthProfileStore(dir)?.profiles[profileId]).toMatchObject({
            type: "oauth",
            access: route.access ?? nextAccess,
            refresh: mode === "omitted-refresh" ? oldRefresh : nextRefresh,
          });
          await expect(resolve()).resolves.toBe(route.access ?? nextAccess);
        } else {
          if (owner === "SDK AuthStorage") {
            await expect(resolve()).resolves.toBeUndefined();
          } else {
            await expect(resolve()).rejects.toThrow("OAuth token refresh failed");
          }
          const persisted = loadPersistedAuthProfileStore(dir)?.profiles[profileId];
          expect(isOAuthRefreshFence(persisted?.type === "oauth" ? persisted : undefined)).toBe(
            true,
          );
          // A new call observes the terminal durable generation, not another provider attempt.
          await expect(resolve()).resolves.toBeUndefined();
        }
        expect(grantsConsumed).toBe(1);
      },
    );
  }
}
