import express from "express";
import cookieParser from "cookie-parser";
import { randomUUID, createHash, randomBytes } from "crypto";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import rateLimit from "express-rate-limit";
import * as db from "./db.js";
import { trackTool, trackRegister, shutdownAnalytics } from "./analytics.js";

// MCP SDK
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { Response as ExpressResponse } from "express";

const SUPABASE_URL             = process.env.SUPABASE_URL!;
const SUPABASE_ANON_KEY        = process.env.SUPABASE_ANON_KEY!;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const SUPABASE_JWT_SECRET      = process.env.SUPABASE_JWT_SECRET!;
const HIVE_BASE_URL    = process.env.HIVE_BASE_URL    ?? "https://hive.brainrotcreations.com";
const WEBSITE_BASE_URL = process.env.WEBSITE_BASE_URL ?? "https://brainrotcreations.com";

// ─── Logger ───────────────────────────────────────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  green:   "\x1b[32m",
  yellow:  "\x1b[33m",
  red:     "\x1b[31m",
  cyan:    "\x1b[36m",
  bold:    "\x1b[1m",
  magenta: "\x1b[35m",
};

function ts() {
  return C.dim + new Date().toISOString().replace("T", " ").slice(0, 23) + C.reset;
}

function log(level: "INFO" | "WARN" | "ERROR", msg: string, detail?: unknown) {
  const badge =
    level === "ERROR" ? `${C.red}✖ error${C.reset}` :
    level === "WARN"  ? `${C.yellow}⚠ warn ${C.reset}` :
                        `${C.green}● info ${C.reset}`;
  const extra = detail !== undefined
    ? `\n         ${C.dim}${detail instanceof Error ? detail.stack ?? detail.message : String(detail)}${C.reset}`
    : "";
  console.log(`${ts()} ${badge}  ${msg}${extra}`);
}

// ─── Supabase singleton ───────────────────────────────────────────────────────

let _adminClient: SupabaseClient | null = null;
function adminSupabase(): SupabaseClient {
  if (!_adminClient) _adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  return _adminClient;
}

// ─── OAuth persistent state (Supabase-backed) ────────────────────────────────
// Replaces in-memory Maps — survives serverless restarts on Vercel.

interface PendingAuth {
  codeChallenge: string;
  redirectUri: string;
  clientId: string;
}

interface PendingCode {
  accessToken: string;
  refreshToken: string;
  codeChallenge: string;
  clientId: string;
}

const OAUTH_TTL_MS = 10 * 60 * 1000;

async function setOAuthState(key: string, type: "auth" | "code", data: unknown) {
  const expires_at = new Date(Date.now() + OAUTH_TTL_MS).toISOString();
  const { error } = await adminSupabase()
    .schema("hive").from("oauth_state")
    .upsert({ key, type, data, expires_at });
  if (error) throw error;
}

async function getOAuthState<T>(key: string, type: "auth" | "code"): Promise<T | null> {
  const { data } = await adminSupabase()
    .schema("hive").from("oauth_state")
    .select("data")
    .eq("key", key)
    .eq("type", type)
    .gt("expires_at", new Date().toISOString())
    .single();
  return (data?.data as T) ?? null;
}

async function deleteOAuthState(key: string) {
  await adminSupabase().schema("hive").from("oauth_state").delete().eq("key", key);
}

// Fire-and-forget — lazily purges expired OAuth rows on each flow
function purgeExpiredOAuthState() {
  void adminSupabase()
    .schema("hive").from("oauth_state")
    .delete().lt("expires_at", new Date().toISOString());
}

// ─── OAuth clients store (Supabase-backed) ────────────────────────────────────

const clientsStore: OAuthRegisteredClientsStore = {
  async getClient(clientId: string) {
    const { data } = await adminSupabase()
      .schema("hive").from("oauth_clients")
      .select("data").eq("client_id", clientId).single();
    return data?.data as OAuthClientInformationFull | undefined;
  },
  async registerClient(client) {
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: randomUUID(),
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    await adminSupabase()
      .schema("hive").from("oauth_clients")
      .insert({ client_id: full.client_id, data: full });
    return full;
  },
};

// ─── OAuth provider ───────────────────────────────────────────────────────────

const oauthProvider: OAuthServerProvider = {
  get clientsStore() {
    return clientsStore;
  },

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: ExpressResponse,
  ) {
    const mcpState = randomUUID();
    purgeExpiredOAuthState();

    let redirectUri = params.redirectUri;
    if (params.state) {
      redirectUri = addParam(redirectUri, "_mcp_orig_state", params.state);
    }

    await setOAuthState(mcpState, "auth", {
      codeChallenge: params.codeChallenge,
      redirectUri,
      clientId: client.client_id,
    });

    res.redirect(`${WEBSITE_BASE_URL}/mcp-auth?mcp_state=${mcpState}`);
  },

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ) {
    const pending = await getOAuthState<PendingCode>(authorizationCode, "code");
    if (!pending) throw new Error("Unknown authorization code");
    return pending.codeChallenge;
  },

  async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<OAuthTokens> {
    const pending = await getOAuthState<PendingCode>(authorizationCode, "code");
    if (!pending) throw new Error("Unknown or expired authorization code");
    await deleteOAuthState(authorizationCode);

    return {
      access_token: pending.accessToken,
      token_type: "bearer",
      refresh_token: pending.refreshToken,
    };
  },

  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
  ): Promise<OAuthTokens> {
    const { data, error } = await adminSupabase().auth.refreshSession({
      refresh_token: refreshToken,
    });
    if (error || !data.session) throw new Error("Failed to refresh token");
    return {
      access_token: data.session.access_token,
      token_type: "bearer",
      refresh_token: data.session.refresh_token,
    };
  },

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const [headerB64, payloadB64, sigB64] = token.split(".");
      if (!headerB64 || !payloadB64 || !sigB64) throw new Error("Malformed JWT");

      const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());

      if (header.alg === "HS256") {
        const { createHmac } = await import("crypto");
        const sig = createHmac("sha256", SUPABASE_JWT_SECRET)
          .update(`${headerB64}.${payloadB64}`)
          .digest("base64url");
        if (sig !== sigB64) throw new Error("Invalid HS256 signature");
      }

      const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
      if (!payload.sub) throw new Error("No sub in token");
      if (payload.exp && payload.exp < Date.now() / 1000) throw new Error("Token expired");

      return {
        token,
        clientId: payload.sub as string,
        scopes: [],
        expiresAt: payload.exp as number,
        extra: { userId: payload.sub as string },
      };
    } catch (e) {
      log("WARN", "Token verification failed", e);
      throw e;
    }
  },
};

// ─── PKCE helpers ─────────────────────────────────────────────────────────────

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function pkceVerifier(): string { return b64url(randomBytes(32)); }
function pkceChallenge(v: string): string { return b64url(createHash("sha256").update(v).digest()); }

// ─── Rate limiters ────────────────────────────────────────────────────────────
// Note: in-memory limiters work per-instance. On Vercel serverless, warm
// instances are often reused so this provides meaningful protection. For
// strict multi-instance limiting, swap the store for Upstash Redis.

const publicLimit = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: "Too many requests" },
});

const authLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: "Too many requests" },
});

// ─── Express app ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(cookieParser());
app.set("trust proxy", 1); // accurate client IP behind Vercel's proxy

// ─── Request logger ───────────────────────────────────────────────────────────

const METHOD_COLOR: Record<string, string> = {
  GET:    C.green,
  POST:   C.cyan,
  PUT:    C.yellow,
  PATCH:  C.yellow,
  DELETE: C.red,
};

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const ms = Date.now() - start;
    const method = req.method;
    const mc = METHOD_COLOR[method] ?? C.dim;
    const sc = res.statusCode >= 500 ? C.red : res.statusCode >= 400 ? C.yellow : C.green;
    if (req.path === "/health") return;
    console.log(
      `${ts()} ${C.dim}│${C.reset}  ${mc}${method.padEnd(6)}${C.reset} ${req.path}  ${sc}${res.statusCode}${C.reset}  ${C.dim}${ms}ms${C.reset}`
    );
  });
  next();
});

// ─── Local dev OAuth routes ───────────────────────────────────────────────────
// Used when WEBSITE_BASE_URL === HIVE_BASE_URL (i.e. running fully locally).

app.get("/mcp-auth", authLimit, async (req, res) => {
  const { mcp_state } = req.query as Record<string, string>;
  const pending = mcp_state ? await getOAuthState<PendingAuth>(mcp_state, "auth") : null;
  if (!pending) return void res.status(400).send("Invalid or expired mcp_state");

  const verifier = pkceVerifier();
  const challenge = pkceChallenge(verifier);

  const authUrl = new URL(`${SUPABASE_URL}/auth/v1/authorize`);
  authUrl.searchParams.set("provider", "google");
  authUrl.searchParams.set("redirect_to", `${HIVE_BASE_URL}/oauth/callback`);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const cookieOpts = { httpOnly: true, secure: true, maxAge: OAUTH_TTL_MS, sameSite: "lax" as const };
  res.cookie("mcp_state", mcp_state, cookieOpts);
  res.cookie("pkce_verifier", verifier, cookieOpts);
  res.redirect(authUrl.toString());
});

app.get("/oauth/callback", authLimit, async (req, res) => {
  const { code } = req.query as Record<string, string>;
  const mcp_state = req.cookies?.mcp_state as string | undefined;
  const verifier  = req.cookies?.pkce_verifier as string | undefined;

  if (!code || !mcp_state || !verifier) {
    return void res.status(400).send("Missing code, mcp_state, or pkce_verifier cookie");
  }

  res.clearCookie("mcp_state");
  res.clearCookie("pkce_verifier");

  const pending = await getOAuthState<PendingAuth>(mcp_state, "auth");
  if (!pending) return void res.status(400).send("Unknown or expired OAuth state");

  const tokenRes = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=pkce`, {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: SUPABASE_ANON_KEY },
    body: JSON.stringify({ auth_code: code, code_verifier: verifier }),
  });

  if (!tokenRes.ok) {
    const msg = await tokenRes.text();
    return void res.status(400).send(`Auth failed: ${msg}`);
  }

  const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string };

  await deleteOAuthState(mcp_state);

  const hiveCode = randomUUID();
  await setOAuthState(hiveCode, "code", {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    codeChallenge: pending.codeChallenge,
    clientId: pending.clientId,
  });

  const redirectUrl = new URL(pending.redirectUri);
  redirectUrl.searchParams.set("code", hiveCode);
  const origState = redirectUrl.searchParams.get("_mcp_orig_state");
  if (origState) {
    redirectUrl.searchParams.delete("_mcp_orig_state");
    redirectUrl.searchParams.set("state", origState);
  }
  res.redirect(redirectUrl.toString());
});

// ─── MCP auth bridge (website → here → Claude Code) ──────────────────────────

const ALLOWED_ORIGINS = [
  WEBSITE_BASE_URL,
  WEBSITE_BASE_URL.replace("://", "://www."),   // allow www variant
  WEBSITE_BASE_URL.replace("://www.", "://"),    // allow non-www variant
].filter((v, i, a) => a.indexOf(v) === i);      // dedupe

function setCorsHeaders(req: express.Request, res: express.Response) {
  const origin = req.headers.origin ?? "";
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
}

app.options("/mcp-auth-bridge", (req, res) => {
  setCorsHeaders(req, res);
  res.header("Access-Control-Allow-Headers", "Content-Type");
  res.header("Access-Control-Allow-Methods", "POST");
  res.sendStatus(200);
});

app.post("/mcp-auth-bridge", authLimit, async (req, res) => {
  setCorsHeaders(req, res);

  const { mcp_state, access_token, refresh_token } = req.body as Record<string, string>;
  if (!mcp_state || !access_token || !refresh_token) {
    return void res.status(400).json({ error: "Missing required fields" });
  }

  const pending = await getOAuthState<PendingAuth>(mcp_state, "auth");
  if (!pending) return void res.status(400).json({ error: "Unknown or expired mcp_state" });

  const { data, error } = await adminSupabase().auth.getUser(access_token);
  if (error || !data.user) return void res.status(401).json({ error: "Invalid token" });

  await deleteOAuthState(mcp_state);

  const hiveCode = randomUUID();
  await setOAuthState(hiveCode, "code", {
    accessToken: access_token,
    refreshToken: refresh_token,
    codeChallenge: pending.codeChallenge,
    clientId: pending.clientId,
  });

  const redirectUrl = new URL(pending.redirectUri);
  redirectUrl.searchParams.set("code", hiveCode);
  const origState = redirectUrl.searchParams.get("_mcp_orig_state");
  if (origState) {
    redirectUrl.searchParams.delete("_mcp_orig_state");
    redirectUrl.searchParams.set("state", origState);
  }

  res.json({ redirect_to: redirectUrl.toString() });
});

// ─── MCP auth router (/.well-known/*, /authorize, /token, /register) ──────────

app.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl: new URL(HIVE_BASE_URL),
  }),
);

// ─── MCP HTTP endpoint ────────────────────────────────────────────────────────

function createMcpServer(userId: string) {
  const server = new McpServer({ name: "hive", version: "0.1.0" });

  server.registerTool(
    "hive_register",
    {
      description:
        "Register as a Hive agent. Required before contributing or voting. Safe to call multiple times.",
      inputSchema: {},
    },
    async () => {
      const installId = await ensureAgent(userId);
      trackRegister(userId);
      return text(`Agent registered. Your agent ID: ${installId.slice(0, 8)}`);
    },
  );

  server.registerTool(
    "hive_pull",
    {
      description:
        "Check Hive for known methods to perform an action on a website. Call BEFORE using browser tools. Returns blocks ranked by collective confidence — try them top-down.",
      inputSchema: {
        domain:     z.string().describe('e.g. "reddit.com"'),
        action_key: z.string().describe('e.g. "click_reply"'),
        limit:      z.number().optional().describe("Max blocks to return, default 5"),
      },
    },
    async ({ domain, action_key, limit }) => {
      const blocks = await db.pullChain(domain, action_key, limit ?? 5);
      trackTool(userId, "hive_pull", { domain, action_key, block_count: blocks.length, result: blocks.length ? "found" : "empty" });
      if (!blocks.length) {
        return text(
          `No known methods for "${action_key}" on ${domain}.\n` +
          `Use your browser tool, then call hive_contribute with what works.`,
        );
      }
      const formatted = blocks
        .map((b, i) => {
          const score   = typeof b.score === "number" ? b.score.toFixed(1) : "0";
          const demoted = b.demoted ? " [stale]" : "";
          return (
            `#${i + 1}  id:${b.id.slice(0, 8)}${demoted}\n` +
            `  type:  ${b.method.type}\n` +
            `  value: ${b.method.value}\n` +
            (b.method.context ? `  ctx:   ${b.method.context}\n` : "") +
            `  score: ${score}  (↑${b.upvote_count} ↓${b.downvote_count})`
          );
        })
        .join("\n\n");
      return text(`${blocks.length} known method(s) for "${action_key}" on ${domain}:\n\n${formatted}`);
    },
  );

  server.registerTool(
    "hive_contribute",
    {
      description:
        "Contribute a discovered browser method to Hive. Call after successfully performing an action NOT in hive_pull results.",
      inputSchema: {
        domain:     z.string(),
        action_key: z.string(),
        method: z.object({
          type:    z.enum(["css", "xpath", "aria", "visual"]),
          value:   z.string(),
          context: z.string().optional(),
        }),
        parent: z.string().optional().describe("Block ID that failed before this was discovered"),
      },
    },
    async ({ domain, action_key, method, parent }) => {
      const installId = await ensureAgent(userId);
      const id = blockId(domain, action_key, method);
      const { isNew } = await db.contributeBlock({ id, domain, action_key, method, install_id: installId, parent });
      trackTool(userId, "hive_contribute", { domain, action_key, result: isNew ? "contributed" : "already_exists" });
      return text(
        isNew
          ? `Contributed [${id.slice(0, 8)}] for "${action_key}" on ${domain}.`
          : `Block already exists. Vote on it instead.`,
      );
    },
  );

  server.registerTool(
    "hive_vote",
    {
      description: 'Vote on a block from hive_pull. "up" if it worked, "down" if it failed. Always vote after trying.',
      inputSchema: {
        block_id:  z.string(),
        direction: z.enum(["up", "down"]),
      },
    },
    async ({ block_id, direction }) => {
      const installId = await ensureAgent(userId);
      const score = await db.vote(block_id, installId, direction);
      trackTool(userId, "hive_vote", { direction, result: "voted" });
      const label = direction === "up" ? "Upvoted" : "Downvoted";
      return text(`${label} [${block_id.slice(0, 8)}]. Score: ${typeof score === "number" ? score.toFixed(1) : "updating"}`);
    },
  );

  server.registerTool(
    "hive_status",
    {
      description: "See what Hive knows about a domain.",
      inputSchema: {
        domain:     z.string(),
        action_key: z.string().optional(),
      },
    },
    async ({ domain, action_key }) => {
      const chains = await db.status(domain, action_key);
      trackTool(userId, "hive_status", { domain, action_key, block_count: chains.length });
      if (!chains.length) return text(`No Hive knowledge for ${domain} yet.`);
      const formatted = chains
        .map((c) => {
          const score    = typeof c.score === "number" ? (c.score as number).toFixed(1) : "?";
          const verified = c.last_upvoted_at
            ? new Date(c.last_upvoted_at as string).toLocaleDateString()
            : "never";
          return `  ${c.action_key}  score=${score}  last_verified=${verified}`;
        })
        .join("\n");
      return text(`Hive coverage for ${domain}:\n\n${formatted}`);
    },
  );

  return server;
}

const bearerAuth = requireBearerAuth({ verifier: oauthProvider });

app.post("/mcp", bearerAuth, async (req, res) => {
  try {
    const userId = (req.auth?.extra?.userId ?? req.auth?.clientId) as string;
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = createMcpServer(userId);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    log("ERROR", "POST /mcp unhandled", e);
    if (!res.headersSent) res.status(500).json({ error: String(e) });
  }
});

app.get("/mcp", (_req, res) => {
  res.status(405).json({ error: "Use POST for MCP requests" });
});

// ─── Auth middleware (REST routes) ────────────────────────────────────────────

async function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return err(res, 401, "Missing authorization token.");

  const { data, error } = await adminSupabase().auth.getUser(token);
  if (error || !data.user) return err(res, 401, "Invalid or expired token.");

  res.locals.user_id = data.user.id;
  next();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function blockId(domain: string, actionKey: string, method: object): string {
  return createHash("sha256")
    .update(domain + actionKey + JSON.stringify(method))
    .digest("hex");
}

function ok(res: express.Response, data: unknown) {
  res.json({ ok: true, ...(typeof data === "object" ? data : { data }) });
}

function err(res: express.Response, status: number, message: string) {
  res.status(status).json({ ok: false, error: message });
}

function text(content: string) {
  return { content: [{ type: "text" as const, text: content }] };
}

function addParam(url: string, key: string, value: string): string {
  const u = new URL(url);
  u.searchParams.set(key, value);
  return u.toString();
}

async function ensureAgent(userId: string): Promise<string> {
  const installId = createHash("sha256")
    .update(`hive:agent:${userId}`)
    .digest("hex")
    .slice(0, 32);
  const formattedId = [
    installId.slice(0, 8),
    installId.slice(8, 12),
    installId.slice(12, 16),
    installId.slice(16, 20),
    installId.slice(20),
  ].join("-");
  // hive.register is idempotent — returns existing install_id if already registered
  return db.registerAgent(formattedId, userId);
}

// ─── REST routes ──────────────────────────────────────────────────────────────

app.post("/register", requireAuth, async (req, res) => {
  const parsed = z.object({ install_id: z.string().uuid() }).safeParse(req.body);
  if (!parsed.success) return err(res, 400, "install_id (UUID) required");

  const { install_id } = parsed.data;
  const user_id: string = res.locals.user_id;

  try {
    const existing = await db.getAgent(user_id);
    if (existing) return ok(res, { install_id: existing.install_id, already_registered: true });
    await db.registerAgent(install_id, user_id);
    ok(res, { install_id, already_registered: false });
  } catch (e) {
    const msg = String(e);
    if (msg.includes("unique") || msg.includes("duplicate")) {
      err(res, 409, "This install ID is already registered to a different account.");
    } else {
      err(res, 500, msg);
    }
  }
});

app.get("/pull", publicLimit, async (req, res) => {
  const parsed = z
    .object({
      domain:     z.string(),
      action_key: z.string(),
      limit:      z.coerce.number().optional().default(5),
    })
    .safeParse(req.query);

  if (!parsed.success) return err(res, 400, "domain and action_key required");

  try {
    const blocks = await db.pullChain(parsed.data.domain, parsed.data.action_key, parsed.data.limit);
    ok(res, { blocks });
  } catch (e) {
    err(res, 500, String(e));
  }
});

app.post("/contribute", requireAuth, async (req, res) => {
  const parsed = z
    .object({
      domain:     z.string(),
      action_key: z.string(),
      method: z.object({
        type:    z.enum(["css", "xpath", "aria", "visual"]),
        value:   z.string(),
        context: z.string().optional(),
      }),
      install_id: z.string().uuid(),
      parent:     z.string().optional(),
    })
    .safeParse(req.body);

  if (!parsed.success) return err(res, 400, parsed.error.message);

  const { domain, action_key, method, install_id, parent } = parsed.data;
  const user_id: string = res.locals.user_id;

  try {
    const agent = await db.getAgent(user_id);
    if (!agent) return err(res, 403, "Agent not registered.");
    if (agent.install_id !== install_id) return err(res, 403, "install_id mismatch.");

    const id = blockId(domain, action_key, method);
    const { isNew } = await db.contributeBlock({ id, domain, action_key, method, install_id, parent });
    ok(res, { block_id: id, is_new: isNew });
  } catch (e) {
    err(res, 500, String(e));
  }
});

app.post("/vote", requireAuth, async (req, res) => {
  const parsed = z
    .object({
      block_id:   z.string(),
      direction:  z.enum(["up", "down"]),
      install_id: z.string().uuid(),
    })
    .safeParse(req.body);

  if (!parsed.success) return err(res, 400, parsed.error.message);

  const { block_id, direction, install_id } = parsed.data;
  const user_id: string = res.locals.user_id;

  try {
    const agent = await db.getAgent(user_id);
    if (!agent) return err(res, 403, "Agent not registered.");
    if (agent.install_id !== install_id) return err(res, 403, "install_id mismatch.");

    const score = await db.vote(block_id, install_id, direction);
    ok(res, { score });
  } catch (e) {
    err(res, 500, String(e));
  }
});

app.get("/status", publicLimit, async (req, res) => {
  const parsed = z
    .object({
      domain:     z.string(),
      action_key: z.string().optional(),
    })
    .safeParse(req.query);

  if (!parsed.success) return err(res, 400, "domain required");

  try {
    const chains = await db.status(parsed.data.domain, parsed.data.action_key);
    ok(res, { chains });
  } catch (e) {
    err(res, 500, String(e));
  }
});

app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/",       (_req, res) => res.json({ ok: true }));

// ─── Start (local dev only — Vercel uses the default export) ──────────────────

if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT ?? 3000;
  app.listen(PORT, () => {
    console.log();
    console.log(`  ${C.bold}${C.magenta}Hive API${C.reset}  ${C.dim}v0.1.0${C.reset}`);
    console.log();
    console.log(`  ${C.green}➜${C.reset}  ${C.bold}Local:${C.reset}   ${C.cyan}${HIVE_BASE_URL}${C.reset}`);
    console.log(`  ${C.green}➜${C.reset}  ${C.bold}MCP:${C.reset}     ${C.cyan}${HIVE_BASE_URL}/mcp${C.reset}`);
    console.log(`  ${C.dim}➜  Website: ${WEBSITE_BASE_URL}${C.reset}`);
    console.log();
  });
}

export default app;
