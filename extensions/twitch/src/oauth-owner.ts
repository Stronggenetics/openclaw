import { createHash, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { callTwitchApiRaw } from "@twurple/api-call";
import {
  accessTokenIsExpired,
  getTokenInfo,
  StaticAuthProvider,
  type AccessToken,
  type AuthProvider,
} from "@twurple/auth";
import { normalizeAccountId } from "openclaw/plugin-sdk/account-resolution";
import { readProviderJsonObjectResponse } from "openclaw/plugin-sdk/provider-http";
import {
  createOAuthRefreshError,
  createOAuthRefreshResponseError,
  isRecoverableOAuthRefreshFailure,
  readOAuthRefreshErrorReason,
} from "openclaw/plugin-sdk/provider-oauth-runtime";
import { getAccountConfig } from "./config.js";
import { getTwitchRuntime } from "./runtime.js";
import { resolveTwitchToken } from "./token.js";
import type { TwitchAccountConfig } from "./types.js";
import { normalizeToken } from "./utils/twitch.js";

// Twurple documents this merge seam for the host's native fetch options.
declare module "@twurple/api-call" {
  interface TwitchApiCallFetchOptions {
    signal?: AbortSignal;
    redirect?: RequestRedirect;
  }
}

type Grant = AccessToken & { userId?: string };
type State = { lineage: string } & ({ token: Grant } | { claim: string });
const tasks = new WeakMap<object, Map<string, Promise<Grant>>>();

function lineageOf(account: TwitchAccountConfig, token: string): string {
  return createHash("sha256")
    .update(
      JSON.stringify([
        account.username.toLowerCase(),
        account.clientId,
        account.clientSecret,
        token,
        account.refreshToken,
        account.expiresIn,
        account.obtainmentTimestamp,
      ]),
    )
    .digest("hex");
}

async function exchange(account: TwitchAccountConfig, refreshToken: string): Promise<AccessToken> {
  // Keep Twurple's public endpoint/query serializer, but inspect the raw response:
  // its higher-level helper discards OAuth errors on HTTP 200 and quotes secret URLs.
  let response: Response;
  try {
    response = await callTwitchApiRaw(
      {
        type: "auth",
        url: "token",
        method: "POST",
        query: {
          client_id: account.clientId,
          client_secret: account.clientSecret!,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        },
      },
      undefined,
      undefined,
      undefined,
      { signal: AbortSignal.timeout(30_000), redirect: "error" },
    );
  } catch {
    throw createOAuthRefreshError("Twitch OAuth refresh transport failed", {
      version: 1,
      phase: "token-response",
      outcome: "unknown",
    });
  }
  let payload: Record<string, unknown>;
  try {
    payload = await readProviderJsonObjectResponse(response, "Twitch OAuth refresh", {
      maxBytes: 256 * 1024,
    });
  } catch {
    throw createOAuthRefreshError("Twitch OAuth refresh returned an unreadable response", {
      version: 1,
      phase: "after-token-response",
      outcome: "unknown",
      status: response.status,
    });
  }
  if (!response.ok || readOAuthRefreshErrorReason(payload)) {
    throw createOAuthRefreshResponseError("Twitch OAuth refresh", response.status, payload);
  }
  if (
    typeof payload.access_token !== "string" ||
    !payload.access_token.trim() ||
    typeof payload.refresh_token !== "string" ||
    !payload.refresh_token.trim() ||
    typeof payload.expires_in !== "number" ||
    !Number.isFinite(payload.expires_in) ||
    payload.expires_in < 0 ||
    !Array.isArray(payload.scope) ||
    !payload.scope.every((scope): scope is string => typeof scope === "string") ||
    typeof payload.token_type !== "string" ||
    payload.token_type.toLowerCase() !== "bearer"
  ) {
    throw createOAuthRefreshError("Twitch OAuth refresh returned invalid tokens", {
      version: 1,
      phase: "after-token-response",
      outcome: "unknown",
      status: response.status,
    });
  }
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresIn: payload.expires_in,
    scope: payload.scope,
    obtainmentTimestamp: Date.now(),
  };
}

/** One durable channel-account owner, including the initial and IRC-requested refresh. */
export async function createManagedTwitchAuthProvider(
  account: TwitchAccountConfig,
  token: string,
  accountId?: string,
): Promise<AuthProvider> {
  const clientId = account.clientId;
  if (!clientId) {
    throw new Error("Twitch OAuth requires a client ID");
  }
  const runtime = getTwitchRuntime();
  const id = normalizeAccountId(accountId);
  const lineage = lineageOf(account, token);
  const assertCurrent = () => {
    if (getTwitchRuntime() !== runtime) {
      throw new Error("Twitch OAuth runtime changed");
    }
    const cfg = runtime.config.current({ clone: true });
    const current = getAccountConfig(cfg, id);
    if (cfg.channels?.twitch?.enabled === false || current?.enabled === false) {
      throw new Error("Twitch account is disabled; enable it before using its OAuth grant");
    }
    const currentToken = normalizeToken(resolveTwitchToken(cfg, { accountId: id }).token);
    if (!current || lineageOf(current, currentToken) !== lineage) {
      throw new Error("Twitch OAuth account changed; retry with its current configuration");
    }
  };
  assertCurrent();
  const namespace = "oauth-" + id;
  const key = runtime.state.resolveStateDir() + ":" + id + ":" + lineage;
  const resolve = async (force = false): Promise<Grant> => {
    assertCurrent();
    let active = tasks.get(runtime);
    if (!active) {
      active = new Map();
      tasks.set(runtime, active);
    }
    const pending = active.get(key);
    if (pending) {
      return await pending;
    }
    const task = (async () => {
      const store = runtime.state.openKeyedStoreV2<State>(
        { namespace, maxEntries: 1, overflowPolicy: "reject-new" },
        { assertCurrent },
      );
      let observed = await store.observe("current");
      if (observed.value?.lineage !== lineage) {
        const initialized = await store.compareAndApply("current", observed.comparison, {
          operation: "update",
          action: "set",
          value: {
            lineage,
            token: {
              accessToken: token,
              refreshToken: account.refreshToken ?? null,
              expiresIn: account.expiresIn ?? null,
              obtainmentTimestamp: account.obtainmentTimestamp ?? Date.now(),
              scope: [],
            },
          },
        });
        observed =
          initialized.status === "conflict" ? initialized.current : await store.observe("current");
      }
      assertCurrent();
      if (!observed.value || observed.value.lineage !== lineage || !("token" in observed.value)) {
        throw new Error(
          "Twitch OAuth refresh is pending or its outcome is uncertain; reauthorize the configured grant",
        );
      }
      const original = observed.value.token;
      if (!force && !accessTokenIsExpired(original)) {
        return original;
      }
      if (!original.refreshToken) {
        throw new Error("Twitch OAuth refresh requires a refresh token");
      }
      const claim: State = { lineage, claim: randomUUID() };
      const claimed = await store.compareAndApply("current", observed.comparison, {
        operation: "update",
        action: "set",
        value: claim,
      });
      if (claimed.status !== "applied") {
        throw new Error("Twitch OAuth grant changed before refresh; retry with its current owner");
      }
      const settle = async (replacement: Grant) => {
        const current = await store.observe("current");
        if (!isDeepStrictEqual(current.value, claim)) {
          throw new Error("Twitch OAuth refresh owner changed before settlement");
        }
        const result = await store.compareAndApply("current", current.comparison, {
          operation: "update",
          action: "set",
          value: { lineage, token: replacement },
        });
        if (result.status !== "applied") {
          throw new Error("Twitch OAuth refresh owner changed before settlement");
        }
        assertCurrent();
      };
      assertCurrent();
      let refreshed: AccessToken;
      try {
        refreshed = await exchange(account, original.refreshToken);
      } catch (error) {
        if (isRecoverableOAuthRefreshFailure(error)) {
          await settle(original);
        }
        throw error;
      }
      const info = await getTokenInfo(refreshed.accessToken, clientId);
      if (
        !info.userId ||
        info.userName?.toLowerCase() !== account.username.toLowerCase() ||
        (original.userId && info.userId !== original.userId)
      ) {
        throw new Error("Twitch OAuth refresh returned a different account");
      }
      const replacement = { ...refreshed, userId: info.userId };
      // Identity validation and storage are post-success: neither may restore old tokens.
      await settle(replacement);
      return replacement;
    })();
    active.set(key, task);
    try {
      return await task;
    } finally {
      if (active.get(key) === task) {
        active.delete(key);
      }
    }
  };
  let grant = await resolve();
  let staticProvider = new StaticAuthProvider(clientId, grant);
  const prepare = async (force = false) => {
    const current = await resolve(force);
    if (current.accessToken !== grant.accessToken) {
      staticProvider = new StaticAuthProvider(clientId, current);
    }
    grant = current;
    assertCurrent();
    return staticProvider;
  };
  return {
    clientId,
    hasClientSecret: true,
    getCurrentScopesForUser: () => staticProvider.getCurrentScopesForUser(),
    async getAccessTokenForUser(user, ...scopeSets) {
      const auth = await prepare();
      const result = await auth.getAccessTokenForUser(user, ...scopeSets);
      assertCurrent();
      return result;
    },
    async getAccessTokenForIntent(intent, ...scopeSets) {
      if (intent !== "chat") {
        return null;
      }
      const auth = await prepare();
      const result = await auth.getAccessTokenForIntent(intent, ...scopeSets);
      assertCurrent();
      return result;
    },
    async getAnyAccessToken() {
      const result = await (await prepare()).getAnyAccessToken();
      assertCurrent();
      return result;
    },
    async refreshAccessTokenForIntent(intent) {
      if (intent !== "chat") {
        throw new Error("Unknown Twitch OAuth intent");
      }
      const result = await (await prepare(true)).getAccessTokenForIntent(intent);
      assertCurrent();
      return result;
    },
    async refreshAccessTokenForUser(user) {
      const result = await (await prepare(true)).getAccessTokenForUser(user);
      assertCurrent();
      return result;
    },
  };
}
