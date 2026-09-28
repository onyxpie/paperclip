import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  createAgentKeyEnrollmentCodeSchema,
  createAgentKeyIssuerRuleSchema,
  createAgentKeySchema,
  exchangeAgentKeyEnrollmentCodeSchema,
  normalizeAgentApiKeyScope,
} from "@paperclipai/shared";
import { issueDocumentReadKeyGuard } from "../middleware/issue-document-read-guard.js";
import { redactSensitive } from "../middleware/redact-sensitive.js";
import { isSecretSensitiveHttpRequest } from "../middleware/http-log-policy.js";
import {
  assertIssueDocumentReadExpiry,
  claimsIssueDocumentReadScope,
  parseIssueDocumentReadScope,
} from "../services/agent-key-delegation.js";

const ISSUE_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ISSUE_ID = "22222222-2222-4222-8222-222222222222";
const COMPANY_ID = "33333333-3333-4333-8333-333333333333";
const scope = { kind: "issue_document_read" as const, issueId: ISSUE_ID, documentKey: "sandbox-deny" };
const DAY_MS = 24 * 60 * 60 * 1000;

describe("issue_document_read key validators", () => {
  it("requires expiresAt for issue_document_read keys and rejects it for other kinds", () => {
    expect(createAgentKeySchema.safeParse({ name: "reader", scope }).success).toBe(false);
    expect(createAgentKeySchema.safeParse({
      name: "reader",
      scope,
      expiresAt: new Date(Date.now() + DAY_MS).toISOString(),
    }).success).toBe(true);
    expect(createAgentKeySchema.safeParse({
      name: "standard",
      expiresAt: new Date(Date.now() + DAY_MS).toISOString(),
    }).success).toBe(false);
    expect(createAgentKeySchema.parse({ name: "standard" }).scope).toEqual({ kind: "standard" });
  });

  it("rejects malformed issue_document_read scopes instead of widening them", () => {
    expect(parseIssueDocumentReadScope({ ...scope, documentKey: "Bad Key" })).toBeNull();
    expect(parseIssueDocumentReadScope({ ...scope, extra: true })).toBeNull();
    expect(claimsIssueDocumentReadScope({ kind: "issue_document_read" })).toBe(true);
    expect(parseIssueDocumentReadScope(scope)).toEqual(scope);
    expect(normalizeAgentApiKeyScope(scope)).toEqual(scope);
  });

  it("enforces a future expiry at most 30 days out", () => {
    const now = new Date("2026-09-28T00:00:00.000Z");
    expect(() => assertIssueDocumentReadExpiry(new Date(now.getTime() + 30 * DAY_MS), now)).not.toThrow();
    expect(() => assertIssueDocumentReadExpiry(new Date(now.getTime() + 30 * DAY_MS + 1), now)).toThrow(/30 days/);
    expect(() => assertIssueDocumentReadExpiry(new Date(now.getTime() - 1), now)).toThrow(/future/);
    expect(() => assertIssueDocumentReadExpiry(new Date("not a date"), now)).toThrow(/valid/);
  });

  it("caps issuer rule and enrollment TTLs at 30 days and blocks self-issuing", () => {
    const base = {
      issuerAgentId: "44444444-4444-4444-8444-444444444444",
      holderAgentId: "55555555-5555-4555-8555-555555555555",
      kind: "issue_document_read",
      issueId: ISSUE_ID,
      documentKey: "sandbox-deny",
    };
    expect(createAgentKeyIssuerRuleSchema.safeParse({ ...base, maxTtlDays: 30 }).success).toBe(true);
    expect(createAgentKeyIssuerRuleSchema.safeParse({ ...base, maxTtlDays: 31 }).success).toBe(false);
    expect(createAgentKeyIssuerRuleSchema.safeParse({ ...base, kind: "standard", maxTtlDays: 7 }).success).toBe(false);
    expect(createAgentKeyIssuerRuleSchema.safeParse({
      ...base,
      holderAgentId: base.issuerAgentId,
      maxTtlDays: 7,
    }).success).toBe(false);
    expect(createAgentKeyEnrollmentCodeSchema.safeParse({ ttlDays: 31 }).success).toBe(false);
    expect(exchangeAgentKeyEnrollmentCodeSchema.safeParse({ enrollmentCode: "short" }).success).toBe(false);
  });
});

describe("enrollment code logging policy", () => {
  it("redacts enrollment codes from logged request bodies", () => {
    const code = "pcenr_this-value-must-never-be-logged-0123456789";
    const redacted = JSON.stringify(redactSensitive({ enrollmentCode: code, name: "reader" }));
    expect(redacted).not.toContain(code);
    expect(redacted).toContain("reader");
  });

  it("classifies the exchange route as secret-sensitive", () => {
    expect(isSecretSensitiveHttpRequest("POST", "/api/agent-key-enrollments/exchange")).toBe(true);
  });
});

function fakeDb(identifier: string | null) {
  return {
    select: () => ({
      from: () => ({
        where: () => Promise.resolve(identifier ? [{ identifier, companyId: COMPANY_ID }] : []),
      }),
    }),
  } as never;
}

async function runGuard(input: {
  method: string;
  path: string;
  query?: Record<string, unknown>;
  keyScope?: unknown;
  identifier?: string | null;
}) {
  const guard = issueDocumentReadKeyGuard(fakeDb(input.identifier ?? "ONY-199"));
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
  };
  const next = vi.fn();
  await guard(
    {
      method: input.method,
      path: input.path,
      query: input.query ?? {},
      actor: {
        type: "agent",
        agentId: "reader",
        companyId: COMPANY_ID,
        keyScope: input.keyScope ?? scope,
        source: "agent_key",
      },
    } as never,
    res as never,
    next,
  );
  return { allowed: next.mock.calls.length === 1 && next.mock.calls[0]!.length === 0, status: res.statusCode };
}

describe("issueDocumentReadKeyGuard", () => {
  it("allows only the scoped document reads, /agents/me, rotation and self-revoke", async () => {
    for (const [method, path] of [
      ["GET", `/api/issues/${ISSUE_ID}/documents/sandbox-deny`],
      ["HEAD", `/api/issues/${ISSUE_ID}/documents/sandbox-deny`],
      ["GET", `/api/issues/${ISSUE_ID}/documents/sandbox-deny/revisions`],
      ["GET", `/api/issues/ONY-199/documents/sandbox-deny`],
      ["GET", `/api/issues/ony-199/documents/SANDBOX-DENY/`],
      ["GET", "/api/agents/me"],
      ["POST", "/api/agents/me/keys/rotate"],
      ["POST", "/api/agents/me/keys/revoke"],
    ] as const) {
      expect(await runGuard({ method, path }), `${method} ${path}`).toEqual({ allowed: true, status: 200 });
    }
  });

  it("does not apply to other key kinds", async () => {
    expect(await runGuard({
      method: "POST",
      path: `/api/issues/${ISSUE_ID}/comments`,
      keyScope: { kind: "standard" },
    })).toEqual({ allowed: true, status: 200 });
  });
});

// ONY-223 C3 negative proof (iii): a conditional skip must fail the gate.
describe("ony223 negproof", () => {
  it.skipIf(true)("is conditionally skipped", () => {
    expect(true).toBe(true);
  });
});
