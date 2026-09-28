import { createHash, randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import express from "express";
import pino from "pino";
import request from "supertest";
import { eq } from "drizzle-orm";
import { expect, it } from "vitest";
import {
  activityLog,
  agentApiKeys,
  agentKeyEnrollmentCodes,
  agents,
  authUsers,
  companies,
  companyMemberships,
  documentRevisions,
  documents,
  issueDocuments,
  issues,
} from "@paperclipai/db";
import type { DeploymentMode } from "@paperclipai/shared";
import { actorMiddleware } from "../middleware/auth.js";
import { boardMutationGuard } from "../middleware/board-mutation-guard.js";
import { errorHandler } from "../middleware/index.js";
import { issueDocumentReadKeyGuard } from "../middleware/issue-document-read-guard.js";
import { createHttpLogger } from "../middleware/logger.js";
import { HTTP_LOG_REDACT_PATHS } from "../middleware/http-log-redaction.js";
import { agentKeyDelegationRoutes } from "../routes/agent-key-delegation.js";
import { agentRoutes } from "../routes/agents.js";
import { companyRoutes } from "../routes/companies.js";
import { issueRoutes } from "../routes/issues.js";
import { secretRoutes } from "../routes/secrets.js";
import { describeEmbeddedPostgres, useEmbeddedPostgres } from "./helpers/route-test-harness.js";

const BOARD_USER = "local-board";
const DAY_MS = 24 * 60 * 60 * 1000;

describeEmbeddedPostgres("issue_document_read keys, rotation, delegated issuer and enrollment (ONY-200 K1–K5)", () => {
  const ctx = useEmbeddedPostgres("paperclip-agent-key-delegation-");
  const logLines: string[] = [];
  const secretValues: string[] = [];

  function buildApp(deploymentMode: DeploymentMode) {
    const db = ctx.db;
    const httpLogger = createHttpLogger(pino(
      { level: "debug", redact: [...HTTP_LOG_REDACT_PATHS] },
      new Writable({
        write(chunk, _encoding, callback) {
          logLines.push(String(chunk));
          callback();
        },
      }),
    ));
    const app = express();
    app.use(express.json());
    app.use(httpLogger);
    // Same order as app.ts: actor resolution, then the fail-closed guard, then routes.
    app.use(actorMiddleware(db, { deploymentMode }));
    app.use(issueDocumentReadKeyGuard(db));
    const api = express.Router();
    api.use(boardMutationGuard());
    api.use("/companies", companyRoutes(db, {} as never));
    api.use(agentKeyDelegationRoutes(db));
    api.use(agentRoutes(db));
    api.use(issueRoutes(db, {} as never));
    api.use(secretRoutes(db));
    app.use("/api", api);
    app.use(errorHandler);
    return app;
  }

  /** Board requests carry no bearer (local_trusted); agent requests carry their key. */
  const app = () => buildApp("local_trusted");
  /** Authenticated mode: a request without a bearer is anonymous. */
  const publicApp = () => buildApp("authenticated");

  function remember<T extends string>(value: T) {
    secretValues.push(value);
    return value;
  }

  async function seed() {
    const db = ctx.db;
    const prefix = `K${randomUUID().replace(/-/g, "").slice(0, 5).toUpperCase()}`;
    const company = await db.insert(companies).values({ name: `Key Co ${prefix}`, issuePrefix: prefix })
      .returning().then((rows) => rows[0]!);
    await db.insert(authUsers).values({
      id: BOARD_USER,
      name: "Board",
      email: "board@example.com",
      createdAt: new Date(),
      updatedAt: new Date(),
    }).onConflictDoNothing();
    await db.insert(companyMemberships).values({
      companyId: company.id,
      principalType: "user",
      principalId: BOARD_USER,
      status: "active",
      membershipRole: "owner",
    });
    const [vera, reader, other] = await db.insert(agents).values(
      (["Vera", "sandbox-deny-sync-reader", "Other"] as const).map((name) => ({
        companyId: company.id,
        name,
        role: "engineer",
        status: name === "sandbox-deny-sync-reader" ? ("paused" as const) : ("active" as const),
        adapterType: "process",
        adapterConfig: {},
        runtimeConfig: {},
      })),
    ).returning();
    const [issue, otherIssue] = await db.insert(issues).values([199, 200].map((n) => ({
      companyId: company.id,
      identifier: `${prefix}-${n}`,
      title: `Issue ${n}`,
      status: "todo" as const,
      priority: "medium" as const,
    }))).returning();

    async function createDoc(issueId: string, key: string, body: string) {
      const doc = await db.insert(documents).values({
        companyId: company.id,
        title: key,
        latestBody: body,
        createdByAgentId: vera!.id,
        updatedByAgentId: vera!.id,
      }).returning().then((rows) => rows[0]!);
      await db.insert(documentRevisions).values({
        companyId: company.id,
        documentId: doc.id,
        revisionNumber: 1,
        body,
        createdByAgentId: vera!.id,
      });
      await db.insert(issueDocuments).values({ companyId: company.id, issueId, documentId: doc.id, key });
      return doc;
    }
    await createDoc(issue!.id, "sandbox-deny", "deny: example.invalid");
    await createDoc(issue!.id, "plan", "private plan");
    await createDoc(otherIssue!.id, "sandbox-deny", "other issue denies");

    return { company, vera: vera!, reader: reader!, other: other!, issue: issue!, otherIssue: otherIssue! };
  }

  type Seed = Awaited<ReturnType<typeof seed>>;

  async function mintStandardKey(agentId: string) {
    const res = await request(app()).post(`/api/agents/${agentId}/keys`).send({ name: "standard" });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return remember(res.body.token as string);
  }

  async function mintReadKey(s: Seed, opts: { issueId?: string; documentKey?: string; ttlMs?: number } = {}) {
    const res = await request(app()).post(`/api/agents/${s.reader.id}/keys`).send({
      name: "reader",
      scope: {
        kind: "issue_document_read",
        issueId: opts.issueId ?? s.issue.id,
        documentKey: opts.documentKey ?? "sandbox-deny",
      },
      expiresAt: new Date(Date.now() + (opts.ttlMs ?? 30 * DAY_MS - 60_000)).toISOString(),
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return { id: res.body.id as string, token: remember(res.body.token as string) };
  }

  async function createRule(s: Seed, maxTtlDays = 30) {
    const res = await request(app()).post(`/api/companies/${s.company.id}/agent-key-issuer-rules`).send({
      issuerAgentId: s.vera.id,
      holderAgentId: s.reader.id,
      kind: "issue_document_read",
      issueId: s.issue.id,
      documentKey: "sandbox-deny",
      maxTtlDays,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return res.body as { id: string };
  }

  const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
  const docPath = (issueRef: string, key = "sandbox-deny") => `/api/issues/${issueRef}/documents/${key}`;

  async function activities(companyId: string) {
    return ctx.db.select().from(activityLog).where(eq(activityLog.companyId, companyId));
  }

  async function assertNoSecretLeaks(companyId: string) {
    const serializedActivity = JSON.stringify(await activities(companyId));
    const serializedLogs = logLines.join("\n");
    for (const value of secretValues) {
      expect(serializedActivity.includes(value), "secret value found in activity log").toBe(false);
      expect(serializedLogs.includes(value), "secret value found in HTTP logs").toBe(false);
    }
  }

  it("K1: reads only the scoped document, its revisions and /agents/me with keyScope", async () => {
    const s = await seed();
    const key = await mintReadKey(s);

    const doc = await request(app()).get(docPath(s.issue.id)).set(bearer(key.token));
    expect(doc.status, JSON.stringify(doc.body)).toBe(200);
    expect(doc.body.body ?? doc.body.latestBody).toContain("deny: example.invalid");
    const byIdentifier = await request(app()).get(docPath(s.issue.identifier!)).set(bearer(key.token));
    expect(byIdentifier.status).toBe(200);
    const revisions = await request(app()).get(`${docPath(s.issue.id)}/revisions`).set(bearer(key.token));
    expect(revisions.status, JSON.stringify(revisions.body)).toBe(200);

    const me = await request(app()).get("/api/agents/me").set(bearer(key.token));
    expect(me.status).toBe(200);
    expect(me.body.id).toBe(s.reader.id);
    expect(me.body.keyScope).toMatchObject({
      kind: "issue_document_read",
      issueId: s.issue.id,
      documentKey: "sandbox-deny",
    });
    expect(Date.parse(me.body.keyScope.expiresAt)).toBeGreaterThan(Date.now());
    expect(me.body.adapterConfig).toBeUndefined();
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);

  it("K1: every write, other issue, other document and non-document route returns 403", async () => {
    const s = await seed();
    const key = await mintReadKey(s);
    const auth = bearer(key.token);
    const cases: Array<[string, string, Record<string, unknown>?]> = [
      ["POST", `/api/issues/${s.issue.id}/comments`, { body: "hello" }],
      ["PUT", docPath(s.issue.id), { format: "markdown", body: "deny: *" }],
      ["PATCH", `/api/issues/${s.issue.id}`, { title: "x" }],
      ["DELETE", docPath(s.issue.id)],
      ["POST", `${docPath(s.issue.id)}/lock`, {}],
      ["GET", docPath(s.otherIssue.id)],
      ["GET", docPath(s.otherIssue.identifier!)],
      ["GET", docPath(s.issue.id, "plan")],
      ["GET", `${docPath(s.issue.id)}/annotations`],
      ["GET", `${docPath(s.issue.id)}?includeAnnotations=true`],
      ["GET", `/api/issues/${s.issue.id}`],
      ["GET", `/api/issues/${s.issue.id}/comments`],
      ["GET", `/api/issues/${s.issue.id}/documents`],
      ["GET", `/api/agents/${s.reader.id}`],
      ["GET", `/api/agents/${s.vera.id}`],
      ["GET", "/api/agents/me/inbox-lite"],
      ["POST", `/api/agents/${s.reader.id}/keys`, { name: "escalate" }],
      ["GET", `/api/companies/${s.company.id}`],
      ["GET", `/api/companies/${s.company.id}/agents`],
      ["GET", `/api/companies/${s.company.id}/issues`],
      ["GET", `/api/companies/${s.company.id}/secrets`],
      ["POST", `/api/companies/${s.company.id}/secrets`, { name: "x", value: "y" }],
      ["GET", `/api/companies/${s.company.id}/agent-key-issuer-rules`],
    ];
    for (const [method, path, body] of cases) {
      let req = request(app())[method.toLowerCase() as "get"](path).set(auth);
      if (body) req = req.send(body);
      const res = await req;
      expect(res.status, `${method} ${path} -> ${res.status} ${JSON.stringify(res.body)}`).toBe(403);
    }
    // Nothing was written through the key.
    const stillOriginal = await request(app()).get(docPath(s.issue.id)).set(auth);
    expect(stillOriginal.body.body ?? stillOriginal.body.latestBody).toContain("deny: example.invalid");
  }, 60_000);

  it("K1: expiresAt is mandatory and capped at 30 days; expired keys and terminated holders get 401", async () => {
    const s = await seed();
    const scope = { kind: "issue_document_read", issueId: s.issue.id, documentKey: "sandbox-deny" };
    const missing = await request(app()).post(`/api/agents/${s.reader.id}/keys`).send({ name: "r", scope });
    expect(missing.status).toBe(400);
    const tooLong = await request(app()).post(`/api/agents/${s.reader.id}/keys`).send({
      name: "r",
      scope,
      expiresAt: new Date(Date.now() + 31 * DAY_MS).toISOString(),
    });
    expect(tooLong.status).toBe(422);
    const past = await request(app()).post(`/api/agents/${s.reader.id}/keys`).send({
      name: "r",
      scope,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    expect(past.status).toBe(422);

    const key = await mintReadKey(s);
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(key.token))).status).toBe(200);
    await ctx.db.update(agentApiKeys).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(agentApiKeys.id, key.id));
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(key.token))).status).toBe(401);
    expect((await request(app()).get("/api/agents/me").set(bearer(key.token))).status).toBe(401);

    // A stored read-only scope without an expiry fails closed instead of acting as a standard key.
    const noExpiry = await mintReadKey(s);
    await ctx.db.update(agentApiKeys).set({ expiresAt: null }).where(eq(agentApiKeys.id, noExpiry.id));
    expect((await request(app()).get("/api/agents/me").set(bearer(noExpiry.token))).status).toBe(401);

    // Rollback safety: the stored hash carries the `idr:` prefix, so a server build that
    // only looks up the bare SHA-256 can never match (and never widen) this key...
    const prefixed = await mintReadKey(s);
    const bareHash = createHash("sha256").update(prefixed.token).digest("hex");
    const storedRow = await ctx.db.select().from(agentApiKeys).where(eq(agentApiKeys.id, prefixed.id)).then((rows) => rows[0]!);
    expect(storedRow.keyHash).toBe(`idr:${bareHash}`);
    expect(await ctx.db.select().from(agentApiKeys).where(eq(agentApiKeys.keyHash, bareHash))).toHaveLength(0);
    // ...and a read-only scope stored without the prefix fails closed.
    await ctx.db.update(agentApiKeys).set({ keyHash: bareHash }).where(eq(agentApiKeys.id, prefixed.id));
    expect((await request(app()).get("/api/agents/me").set(bearer(prefixed.token))).status).toBe(401);

    const live = await mintReadKey(s);
    await ctx.db.update(agents).set({ status: "terminated" }).where(eq(agents.id, s.reader.id));
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(live.token))).status).toBe(401);
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);

  it("K2: rotation copies scope from the calling key, caps expiry by the rule, and retires the old key", async () => {
    const s = await seed();
    const rule = await createRule(s, 7);
    const old = await mintReadKey(s);

    const veraKey = await mintStandardKey(s.vera.id);
    expect((await request(app()).post("/api/agents/me/keys/rotate").set(bearer(veraKey))).status).toBe(403);

    const rotated = await request(app())
      .post("/api/agents/me/keys/rotate")
      .set(bearer(old.token))
      .send({
        scope: { kind: "issue_document_read", issueId: s.otherIssue.id, documentKey: "plan" },
        expiresAt: new Date(Date.now() + 365 * DAY_MS).toISOString(),
        name: "escalated",
      });
    expect(rotated.status, JSON.stringify(rotated.body)).toBe(201);
    const next = { id: rotated.body.id as string, token: remember(rotated.body.token as string) };
    expect(rotated.body.scope).toEqual({ kind: "issue_document_read", issueId: s.issue.id, documentKey: "sandbox-deny" });
    expect(rotated.body.name).toBe("reader");
    expect(Date.parse(rotated.body.expiresAt)).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
    expect(Date.parse(rotated.body.previousKeyExpiresAt)).toBeLessThanOrEqual(Date.now() + 10 * 60 * 1000);

    // Old key still works during the grace period and cannot fork a second successor.
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(old.token))).status).toBe(200);
    expect((await request(app()).post("/api/agents/me/keys/rotate").set(bearer(old.token))).status).toBe(409);

    // Even a denied request authenticates the successor and retires the old key.
    expect((await request(app()).get(docPath(s.otherIssue.id, "plan")).set(bearer(next.token))).status).toBe(403);
    expect((await request(app()).get("/api/agents/me").set(bearer(next.token))).status).toBe(200);
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(old.token))).status).toBe(401);

    const rows = await activities(s.company.id);
    const rotatedEntry = rows.find((row) => row.action === "agent_key.rotated");
    expect(rotatedEntry?.details).toMatchObject({
      ruleId: rule.id,
      holderAgentId: s.reader.id,
      previousKeyId: old.id,
      keyId: next.id,
      scope: { kind: "issue_document_read", issueId: s.issue.id, documentKey: "sandbox-deny" },
    });
    expect(rows.some((row) => row.action === "agent_key.rotation_completed" && row.entityId === old.id)).toBe(true);
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);

  it("K3: only the board manages issuer rules; only the issuer manages the holder's in-scope keys", async () => {
    const s = await seed();
    const veraKey = await mintStandardKey(s.vera.id);
    const otherKey = await mintStandardKey(s.other.id);
    const ruleBody = {
      issuerAgentId: s.vera.id,
      holderAgentId: s.reader.id,
      kind: "issue_document_read",
      issueId: s.issue.id,
      documentKey: "sandbox-deny",
      maxTtlDays: 30,
    };
    const tooLong = await request(app()).post(`/api/companies/${s.company.id}/agent-key-issuer-rules`)
      .send({ ...ruleBody, maxTtlDays: 31 });
    expect(tooLong.status).toBe(400);
    const agentCreates = await request(app()).post(`/api/companies/${s.company.id}/agent-key-issuer-rules`)
      .set(bearer(veraKey)).send(ruleBody);
    expect(agentCreates.status).toBe(403);
    const rule = await createRule(s);
    expect((await request(app()).patch(`/api/agent-key-issuer-rules/${rule.id}`).set(bearer(veraKey))
      .send({ maxTtlDays: 30, issuerAgentId: s.other.id })).status).toBe(403);
    expect((await request(app()).delete(`/api/agent-key-issuer-rules/${rule.id}`).set(bearer(veraKey))).status).toBe(403);

    const mine = await request(app()).get("/api/agents/me/key-issuer-rules").set(bearer(veraKey));
    expect(mine.status).toBe(200);
    expect(mine.body.map((r: { id: string }) => r.id)).toEqual([rule.id]);

    const inScope = await mintReadKey(s);
    const otherDocKey = await mintReadKey(s, { documentKey: "plan" });
    const otherIssueKey = await mintReadKey(s, { issueId: s.otherIssue.id });
    const otherHolderKeyRow = await ctx.db.select().from(agentApiKeys).where(eq(agentApiKeys.agentId, s.other.id))
      .then((rows) => rows[0]!);

    // Non-issuer agents: 403 on every issuer operation.
    for (const [method, path] of [
      ["GET", `/api/agent-key-issuer-rules/${rule.id}/keys`],
      ["POST", `/api/agent-key-issuer-rules/${rule.id}/keys/${inScope.id}/revoke`],
      ["POST", `/api/agent-key-issuer-rules/${rule.id}/enrollment-codes`],
    ] as const) {
      const res = await request(app())[method === "GET" ? "get" : "post"](path).set(bearer(otherKey)).send({});
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    // The holder's own read-only key is stopped by the guard.
    expect((await request(app()).get(`/api/agent-key-issuer-rules/${rule.id}/keys`).set(bearer(inScope.token))).status).toBe(403);

    // The issuer cannot use board-only key routes.
    expect((await request(app()).post(`/api/agents/${s.reader.id}/keys`).set(bearer(veraKey)).send({ name: "x" })).status).toBe(403);
    expect((await request(app()).delete(`/api/agents/${s.reader.id}/keys/${inScope.id}`).set(bearer(veraKey))).status).toBe(403);

    // Listing returns metadata only, and only in-scope keys.
    const listed = await request(app()).get(`/api/agent-key-issuer-rules/${rule.id}/keys`).set(bearer(veraKey));
    expect(listed.status).toBe(200);
    expect(listed.body.map((k: { id: string }) => k.id)).toEqual([inScope.id]);
    expect(JSON.stringify(listed.body)).not.toMatch(/keyHash|key_hash|token/);

    // Issuer cannot revoke keys of another holder, document or issue.
    for (const keyId of [otherHolderKeyRow.id, otherDocKey.id, otherIssueKey.id]) {
      const res = await request(app()).post(`/api/agent-key-issuer-rules/${rule.id}/keys/${keyId}/revoke`).set(bearer(veraKey));
      expect(res.status, keyId).toBe(403);
    }
    expect((await request(app()).get(docPath(s.issue.id, "plan")).set(bearer(otherDocKey.token))).status).toBe(200);

    // In-scope revoke takes effect immediately.
    const revoked = await request(app()).post(`/api/agent-key-issuer-rules/${rule.id}/keys/${inScope.id}/revoke`).set(bearer(veraKey));
    expect(revoked.status, JSON.stringify(revoked.body)).toBe(200);
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(inScope.token))).status).toBe(401);
    const revokeEntry = (await activities(s.company.id)).find((row) => row.action === "agent_key.revoked");
    expect(revokeEntry).toMatchObject({ actorType: "agent", actorId: s.vera.id, entityId: inScope.id });
    expect(revokeEntry?.details).toMatchObject({ ruleId: rule.id, holderAgentId: s.reader.id, keyId: inScope.id });
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);

  it("K3/K4: the issuer cannot target another holder, kind, issue, document or longer TTL", async () => {
    const s = await seed();
    const veraKey = await mintStandardKey(s.vera.id);
    const rule = await createRule(s, 7);
    const path = `/api/agent-key-issuer-rules/${rule.id}/enrollment-codes`;
    for (const body of [
      { holderAgentId: s.other.id },
      { holderAgentId: s.vera.id },
      { kind: "standard" },
      { kind: "task_bridge" },
      { issueId: s.otherIssue.id },
      { documentKey: "plan" },
      { ttlDays: 8 },
    ]) {
      const res = await request(app()).post(path).set(bearer(veraKey)).send(body);
      expect(res.status, JSON.stringify(body)).toBe(403);
    }
    expect((await request(app()).post(path).set(bearer(veraKey)).send({ ttlDays: 31 })).status).toBe(400);
    expect(await ctx.db.select().from(agentKeyEnrollmentCodes).where(eq(agentKeyEnrollmentCodes.ruleId, rule.id)))
      .toHaveLength(0);
  }, 60_000);

  it("K4: codes are hashed, single-use, expire, and exchange only for a rule-matching read key", async () => {
    const s = await seed();
    const veraKey = await mintStandardKey(s.vera.id);
    const rule = await createRule(s, 14);

    const created = await request(app()).post(`/api/agent-key-issuer-rules/${rule.id}/enrollment-codes`)
      .set(bearer(veraKey)).send({ holderAgentId: s.reader.id, kind: "issue_document_read", ttlDays: 7 });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const code = remember(created.body.enrollmentCode as string);
    expect(Date.parse(created.body.expiresAt)).toBeLessThanOrEqual(Date.now() + 30 * 60 * 1000);

    const stored = await ctx.db.select().from(agentKeyEnrollmentCodes).where(eq(agentKeyEnrollmentCodes.id, created.body.id));
    expect(stored[0]!.codeHash).toBe(createHash("sha256").update(code).digest("hex"));
    expect(JSON.stringify(stored)).not.toContain(code);

    const exchanged = await request(publicApp()).post("/api/agent-key-enrollments/exchange")
      .send({ enrollmentCode: code, name: "sandbox-deny-sync" });
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(201);
    const token = remember(exchanged.body.token as string);
    expect(exchanged.body.agentId).toBe(s.reader.id);
    expect(exchanged.body.scope).toEqual({ kind: "issue_document_read", issueId: s.issue.id, documentKey: "sandbox-deny" });
    expect(Date.parse(exchanged.body.expiresAt)).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(token))).status).toBe(200);
    expect((await request(app()).post(`/api/issues/${s.issue.id}/comments`).set(bearer(token)).send({ body: "x" })).status).toBe(403);

    const reused = await request(publicApp()).post("/api/agent-key-enrollments/exchange").send({ enrollmentCode: code });
    expect(reused.status).toBe(401);

    const second = await request(app()).post(`/api/agent-key-issuer-rules/${rule.id}/enrollment-codes`)
      .set(bearer(veraKey)).send({});
    const expiredCode = remember(second.body.enrollmentCode as string);
    await ctx.db.update(agentKeyEnrollmentCodes).set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(agentKeyEnrollmentCodes.id, second.body.id));
    expect((await request(publicApp()).post("/api/agent-key-enrollments/exchange").send({ enrollmentCode: expiredCode })).status)
      .toBe(401);
    const unknown = remember(`pcenr_${randomUUID()}${randomUUID()}`);
    expect((await request(publicApp()).post("/api/agent-key-enrollments/exchange").send({ enrollmentCode: unknown })).status)
      .toBe(401);

    const rows = await activities(s.company.id);
    expect(rows.find((row) => row.action === "agent_key.enrollment_code_created")?.details).toMatchObject({
      ruleId: rule.id,
      issuerAgentId: s.vera.id,
      holderAgentId: s.reader.id,
      keyTtlDays: 7,
    });
    expect(rows.find((row) => row.action === "agent_key.enrollment_code_exchanged")?.details).toMatchObject({
      ruleId: rule.id,
      holderAgentId: s.reader.id,
      keyId: exchanged.body.id,
      scope: { kind: "issue_document_read", issueId: s.issue.id, documentKey: "sandbox-deny" },
    });
    const rejections = rows.filter((row) => row.action === "agent_key.enrollment_code_rejected")
      .map((row) => (row.details as { reason: string }).reason)
      .sort();
    expect(rejections).toEqual(["already_used", "expired"]);
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);

  it("K3/K4: replacing the issuer voids its codes; revoking a successor retires its predecessor", async () => {
    const s = await seed();
    const veraKey = await mintStandardKey(s.vera.id);
    const rule = await createRule(s);

    const pending = await request(app()).post(`/api/agent-key-issuer-rules/${rule.id}/enrollment-codes`)
      .set(bearer(veraKey)).send({});
    expect(pending.status).toBe(201);
    const pendingCode = remember(pending.body.enrollmentCode as string);
    const patched = await request(app()).patch(`/api/agent-key-issuer-rules/${rule.id}`).send({ issuerAgentId: s.other.id });
    expect(patched.status, JSON.stringify(patched.body)).toBe(200);
    expect((await request(publicApp()).post("/api/agent-key-enrollments/exchange").send({ enrollmentCode: pendingCode })).status)
      .toBe(401);
    // The former issuer lost its authority over the rule.
    expect((await request(app()).get(`/api/agent-key-issuer-rules/${rule.id}/keys`).set(bearer(veraKey))).status).toBe(403);

    const otherKey = await mintStandardKey(s.other.id);
    const old = await mintReadKey(s);
    const rotated = await request(app()).post("/api/agents/me/keys/rotate").set(bearer(old.token));
    expect(rotated.status).toBe(201);
    remember(rotated.body.token as string);
    const revoke = await request(app())
      .post(`/api/agent-key-issuer-rules/${rule.id}/keys/${rotated.body.id}/revoke`)
      .set(bearer(otherKey));
    expect(revoke.status, JSON.stringify(revoke.body)).toBe(200);
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(old.token))).status).toBe(401);
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);

  it("K5: mint and board revoke entries carry holder, keyId, scope and expiry but never values", async () => {
    const s = await seed();
    const key = await mintReadKey(s);
    const revoke = await request(app()).delete(`/api/agents/${s.reader.id}/keys/${key.id}`);
    expect(revoke.status).toBe(200);
    expect((await request(app()).get(docPath(s.issue.id)).set(bearer(key.token))).status).toBe(401);
    const rows = await activities(s.company.id);
    const mint = rows.find((row) => row.action === "agent.key_created" && (row.details as { keyId?: string }).keyId === key.id);
    expect(mint?.details).toMatchObject({
      keyId: key.id,
      holderAgentId: s.reader.id,
      scope: { kind: "issue_document_read", issueId: s.issue.id, documentKey: "sandbox-deny" },
    });
    expect((mint?.details as { expiresAt?: string }).expiresAt).toBeTruthy();
    expect(rows.find((row) => row.action === "agent.key_revoked")?.details).toMatchObject({
      keyId: key.id,
      holderAgentId: s.reader.id,
    });
    await assertNoSecretLeaks(s.company.id);
  }, 60_000);
});
