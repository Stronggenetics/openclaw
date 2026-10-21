import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createDeferred } from "openclaw/plugin-sdk/extension-shared";
import { resetPluginStateStoreForTests } from "openclaw/plugin-sdk/plugin-state-test-runtime";
import { resolveRequestUrl } from "openclaw/plugin-sdk/request-url";
import { closeOpenClawStateDatabaseAsync } from "openclaw/plugin-sdk/sqlite-runtime-testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadMSTeamsDelegatedTokens, saveMSTeamsDelegatedTokens } from "./delegated-state.js";
import { setMSTeamsRuntime } from "./runtime.js";
import { msteamsRuntimeStub } from "./test-support/runtime.js";
import { resolveDelegatedAccessToken } from "./token.js";

const params = {
  accountId: "synthetic",
  tenantId: "tenant",
  clientId: "client",
  clientSecret: "synthetic-secret",
};
const original = {
  accessToken: "synthetic-old-access",
  refreshToken: "synthetic-old-refresh",
  expiresAt: 1,
  scopes: ["User.Read", "offline_access"],
};
const response = {
  access_token: "synthetic-next-access",
  refresh_token: "synthetic-next-refresh",
  expires_in: 3600,
  scope: "User.Read offline_access",
};
let stateDir: string;
beforeEach(async () => {
  await closeOpenClawStateDatabaseAsync();
  resetPluginStateStoreForTests();
  stateDir = mkdtempSync(path.join(os.tmpdir(), "teams-refresh-boundary-"));
  vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
  setMSTeamsRuntime(msteamsRuntimeStub);
  await saveMSTeamsDelegatedTokens(original, params.accountId);
});
afterEach(async () => {
  vi.unstubAllGlobals();
  await closeOpenClawStateDatabaseAsync();
  resetPluginStateStoreForTests();
  vi.unstubAllEnvs();
  rmSync(stateDir, { recursive: true, force: true });
});

async function assertRequest(url: RequestInfo | URL, init?: RequestInit) {
  expect(resolveRequestUrl(url)).toBe("https://login.microsoftonline.com/tenant/oauth2/v2.0/token");
  expect(init?.method).toBe("POST");
  expect(new URLSearchParams(await new Response(init?.body).text())).toEqual(
    new URLSearchParams({
      client_id: params.clientId,
      client_secret: params.clientSecret,
      grant_type: "refresh_token",
      scope: "User.Read offline_access",
      refresh_token: original.refreshToken,
    }),
  );
}

describe("Teams actual delegated HTTP parser and SQLite owner", () => {
  it("coalesces callers and publishes the replacement before returning access", async () => {
    const entered = createDeferred<void>();
    const release = createDeferred<void>();
    const network = vi.fn<typeof fetch>(async (url, init) => {
      await assertRequest(url, init);
      entered.resolve();
      await release.promise;
      return Response.json(response);
    });
    vi.stubGlobal("fetch", network);
    const first = resolveDelegatedAccessToken(params);
    await entered.promise;
    const second = resolveDelegatedAccessToken(params);
    release.resolve();
    await expect(Promise.all([first, second])).resolves.toEqual([
      response.access_token,
      response.access_token,
    ]);
    expect(network).toHaveBeenCalledOnce();
    await closeOpenClawStateDatabaseAsync();
    resetPluginStateStoreForTests();
    expect(await loadMSTeamsDelegatedTokens(params.accountId)).toMatchObject({
      accessToken: response.access_token,
      refreshToken: response.refresh_token,
    });
  });

  it.each(["socket-after-consumption", "structured-rejection"] as const)(
    "does not replay %s",
    async (mode) => {
      let consumed = 0;
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>(async (url, init) => {
          await assertRequest(url, init);
          consumed += 1;
          if (mode === "socket-after-consumption") {
            throw Object.assign(new Error("synthetic lost response"), { code: "ECONNRESET" });
          }
          return Response.json({ error: { code: "invalid_grant" } });
        }),
      );
      await expect(resolveDelegatedAccessToken(params)).resolves.toBeUndefined();
      await expect(resolveDelegatedAccessToken(params)).resolves.toBeUndefined();
      expect(consumed).toBe(1);
      expect(await loadMSTeamsDelegatedTokens(params.accountId)).toBeUndefined();
    },
  );

  it("does not overwrite a newer login while the old exchange settles", async () => {
    const entered = createDeferred<void>();
    const release = createDeferred<void>();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (url, init) => {
        await assertRequest(url, init);
        entered.resolve();
        await release.promise;
        return Response.json(response);
      }),
    );
    const result = resolveDelegatedAccessToken(params);
    await entered.promise;
    const newer = {
      ...original,
      accessToken: "synthetic-login-access",
      refreshToken: "synthetic-login-refresh",
      expiresAt: Date.now() + 3600000,
    };
    await saveMSTeamsDelegatedTokens(newer, params.accountId);
    release.resolve();
    await expect(result).resolves.toBeUndefined();
    expect(await loadMSTeamsDelegatedTokens(params.accountId)).toEqual(newer);
  });
});
