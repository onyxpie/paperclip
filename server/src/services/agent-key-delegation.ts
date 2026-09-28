import { createHash, randomBytes } from "node:crypto";
import { and, eq, gt, inArray, isNull } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  agentApiKeys,
  agentKeyEnrollmentCodes,
  agentKeyIssuerRules,
  agents,
  issues,
} from "@paperclipai/db";
import {
  AGENT_KEY_ENROLLMENT_CODE_TTL_MS,
  AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS,
  AGENT_KEY_KIND_ISSUE_DOCUMENT_READ,
  AGENT_KEY_ROTATION_GRACE_MS,
  agentApiKeyScopeSchema,
  type CreateAgentKeyIssuerRule,
  type IssueDocumentReadAgentKeyScope,
  type UpdateAgentKeyIssuerRule,
} from "@paperclipai/shared";
import { conflict, forbidden, notFound, unauthorized, unprocessable } from "../errors.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_TTL_MS = AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS * DAY_MS;

function hashSecret(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Stored hash for `issue_document_read` keys. The `idr:` prefix means a server
 * build without this kind can never match the key (it looks up the bare
 * SHA-256), so a rollback makes these keys fail closed with 401 instead of
 * falling back to standard agent authority.
 */
export const ISSUE_DOCUMENT_READ_KEY_HASH_PREFIX = "idr:";

export function issueDocumentReadKeyHash(token: string) {
  return `${ISSUE_DOCUMENT_READ_KEY_HASH_PREFIX}${hashSecret(token)}`;
}

function createKeyToken() {
  return `pcp_${randomBytes(24).toString("hex")}`;
}

function createEnrollmentCodeValue() {
  return `pcenr_${randomBytes(32).toString("base64url")}`;
}

export type AgentKeyIssuerRule = typeof agentKeyIssuerRules.$inferSelect;
type AgentApiKeyRow = typeof agentApiKeys.$inferSelect;

/** Parses a stored scope and returns it only when it is a valid `issue_document_read` scope. */
export function parseIssueDocumentReadScope(value: unknown): IssueDocumentReadAgentKeyScope | null {
  const parsed = agentApiKeyScopeSchema.safeParse(value);
  if (!parsed.success || parsed.data.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ) return null;
  return parsed.data;
}

/** True when a raw stored scope claims the read-only kind, whether or not it parses. */
export function claimsIssueDocumentReadScope(value: unknown) {
  return Boolean(
    value
    && typeof value === "object"
    && (value as { kind?: unknown }).kind === AGENT_KEY_KIND_ISSUE_DOCUMENT_READ,
  );
}

/** Validates a requested `issue_document_read` expiry: in the future and at most 30 days out. */
export function assertIssueDocumentReadExpiry(expiresAt: Date, now = new Date()) {
  if (Number.isNaN(expiresAt.getTime())) {
    throw unprocessable("expiresAt must be a valid timestamp");
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw unprocessable("expiresAt must be in the future");
  }
  if (expiresAt.getTime() - now.getTime() > MAX_TTL_MS) {
    throw unprocessable(
      `issue_document_read keys can expire at most ${AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS} days from now`,
    );
  }
}

function ruleScope(rule: AgentKeyIssuerRule): IssueDocumentReadAgentKeyScope {
  return {
    kind: AGENT_KEY_KIND_ISSUE_DOCUMENT_READ,
    issueId: rule.issueId,
    documentKey: rule.documentKey,
  };
}

function keyMatchesRule(key: Pick<AgentApiKeyRow, "agentId" | "companyId" | "scopeConfig">, rule: AgentKeyIssuerRule) {
  const scope = parseIssueDocumentReadScope(key.scopeConfig);
  return Boolean(
    scope
    && key.companyId === rule.companyId
    && key.agentId === rule.holderAgentId
    && scope.issueId === rule.issueId
    && scope.documentKey === rule.documentKey,
  );
}

/** Key metadata safe to return to the issuer: never the token or its hash. */
export function toIssueDocumentReadKeyMetadata(key: AgentApiKeyRow) {
  return {
    id: key.id,
    agentId: key.agentId,
    name: key.name,
    scope: parseIssueDocumentReadScope(key.scopeConfig),
    createdAt: key.createdAt,
    lastUsedAt: key.lastUsedAt,
    expiresAt: key.expiresAt,
    rotatedToKeyId: key.rotatedToKeyId,
    revokedAt: key.revokedAt,
  };
}

function isAuthenticatableAgentStatus(status: string) {
  return status !== "terminated" && status !== "pending_approval";
}

export function agentKeyDelegationService(db: Db) {
  async function getAgent(agentId: string) {
    return db
      .select({ id: agents.id, companyId: agents.companyId, status: agents.status })
      .from(agents)
      .where(eq(agents.id, agentId))
      .then((rows) => rows[0] ?? null);
  }

  async function getRule(ruleId: string) {
    return db
      .select()
      .from(agentKeyIssuerRules)
      .where(eq(agentKeyIssuerRules.id, ruleId))
      .then((rows) => rows[0] ?? null);
  }

  async function findRuleForHolderScope(
    companyId: string,
    holderAgentId: string,
    scope: IssueDocumentReadAgentKeyScope,
  ) {
    return db
      .select()
      .from(agentKeyIssuerRules)
      .where(and(
        eq(agentKeyIssuerRules.companyId, companyId),
        eq(agentKeyIssuerRules.holderAgentId, holderAgentId),
        eq(agentKeyIssuerRules.issueId, scope.issueId),
        eq(agentKeyIssuerRules.documentKey, scope.documentKey),
      ))
      .then((rows) => rows[0] ?? null);
  }

  async function insertIssueDocumentReadKey(
    tx: Pick<Db, "insert">,
    input: {
      agentId: string;
      companyId: string;
      name: string;
      scope: IssueDocumentReadAgentKeyScope;
      expiresAt: Date;
      responsibleUserId: string;
    },
  ) {
    const token = createKeyToken();
    const created = await tx
      .insert(agentApiKeys)
      .values({
        agentId: input.agentId,
        companyId: input.companyId,
        name: input.name,
        keyHash: issueDocumentReadKeyHash(token),
        responsibleUserId: input.responsibleUserId,
        scopeConfig: input.scope,
        expiresAt: input.expiresAt,
      })
      .returning()
      .then((rows) => rows[0]!);
    return { row: created, token };
  }

  async function assertRuleTargets(companyId: string, input: {
    issuerAgentId?: string;
    holderAgentId?: string;
    issueId?: string;
  }) {
    for (const agentId of [input.issuerAgentId, input.holderAgentId]) {
      if (!agentId) continue;
      const agent = await getAgent(agentId);
      if (!agent || agent.companyId !== companyId) {
        throw unprocessable("Issuer and holder must be agents in this company");
      }
    }
    if (input.issueId) {
      const issue = await db
        .select({ id: issues.id, companyId: issues.companyId })
        .from(issues)
        .where(eq(issues.id, input.issueId))
        .then((rows) => rows[0] ?? null);
      if (!issue || issue.companyId !== companyId) {
        throw unprocessable("Issue must belong to this company");
      }
    }
  }

  return {
    getRule,
    findRuleForHolderScope,

    listRules: (companyId: string) =>
      db
        .select()
        .from(agentKeyIssuerRules)
        .where(eq(agentKeyIssuerRules.companyId, companyId)),

    listRulesForIssuer: (companyId: string, issuerAgentId: string) =>
      db
        .select()
        .from(agentKeyIssuerRules)
        .where(and(
          eq(agentKeyIssuerRules.companyId, companyId),
          eq(agentKeyIssuerRules.issuerAgentId, issuerAgentId),
        )),

    createRule: async (companyId: string, input: CreateAgentKeyIssuerRule, createdByUserId: string) => {
      await assertRuleTargets(companyId, input);
      const existing = await findRuleForHolderScope(companyId, input.holderAgentId, {
        kind: AGENT_KEY_KIND_ISSUE_DOCUMENT_READ,
        issueId: input.issueId,
        documentKey: input.documentKey,
      });
      if (existing) throw conflict("An issuer rule already exists for this holder and document");
      return db
        .insert(agentKeyIssuerRules)
        .values({
          companyId,
          issuerAgentId: input.issuerAgentId,
          holderAgentId: input.holderAgentId,
          kind: input.kind,
          issueId: input.issueId,
          documentKey: input.documentKey,
          maxTtlDays: input.maxTtlDays,
          createdByUserId,
        })
        .returning()
        .then((rows) => rows[0]!);
    },

    updateRule: async (rule: AgentKeyIssuerRule, input: UpdateAgentKeyIssuerRule, updatedByUserId: string) => {
      if (input.issuerAgentId) {
        if (input.issuerAgentId === rule.holderAgentId) {
          throw unprocessable("The issuer cannot be the key holder");
        }
        await assertRuleTargets(rule.companyId, { issuerAgentId: input.issuerAgentId });
      }
      return db
        .update(agentKeyIssuerRules)
        .set({
          ...(input.issuerAgentId ? { issuerAgentId: input.issuerAgentId } : {}),
          ...(input.maxTtlDays ? { maxTtlDays: input.maxTtlDays } : {}),
          updatedByUserId,
          updatedAt: new Date(),
        })
        .where(eq(agentKeyIssuerRules.id, rule.id))
        .returning()
        .then((rows) => rows[0]!);
    },

    /**
     * Deletes the rule and, in the same transaction, revokes every live holder
     * key it covers, so no key outlives the rule that let it be issued or rotated.
     */
    deleteRule: async (rule: AgentKeyIssuerRule) => {
      return db.transaction(async (tx) => {
        await tx.delete(agentKeyIssuerRules).where(eq(agentKeyIssuerRules.id, rule.id));
        const holderKeys = await tx
          .select()
          .from(agentApiKeys)
          .where(and(
            eq(agentApiKeys.companyId, rule.companyId),
            eq(agentApiKeys.agentId, rule.holderAgentId),
            isNull(agentApiKeys.revokedAt),
          ))
          .for("update");
        const keyIds = holderKeys.filter((row) => keyMatchesRule(row, rule)).map((row) => row.id);
        if (keyIds.length > 0) {
          await tx.update(agentApiKeys).set({ revokedAt: new Date() }).where(inArray(agentApiKeys.id, keyIds));
        }
        return { revokedKeyIds: keyIds };
      });
    },

    /** Holder keys that exactly match the rule's kind, issue and document. */
    listRuleKeys: async (rule: AgentKeyIssuerRule) => {
      const rows = await db
        .select()
        .from(agentApiKeys)
        .where(and(
          eq(agentApiKeys.companyId, rule.companyId),
          eq(agentApiKeys.agentId, rule.holderAgentId),
        ));
      return rows.filter((row) => keyMatchesRule(row, rule)).map(toIssueDocumentReadKeyMetadata);
    },

    /** Revokes one key; 404 when unknown in this company, 403 when outside the rule. */
    revokeRuleKey: async (rule: AgentKeyIssuerRule, keyId: string) => {
      const key = await db
        .select()
        .from(agentApiKeys)
        .where(eq(agentApiKeys.id, keyId))
        .then((rows) => rows[0] ?? null);
      if (!key || key.companyId !== rule.companyId) throw notFound("Key not found");
      if (!keyMatchesRule(key, rule)) {
        throw forbidden("Key is outside this issuer rule's holder, kind, issue or document");
      }
      const now = new Date();
      const revoked = await db
        .update(agentApiKeys)
        .set({ revokedAt: key.revokedAt ?? now })
        .where(eq(agentApiKeys.id, key.id))
        .returning()
        .then((rows) => rows[0]!);
      // A predecessor still inside its rotation grace period dies with its successor.
      const retiredPredecessors = await db
        .update(agentApiKeys)
        .set({ revokedAt: now })
        .where(and(eq(agentApiKeys.rotatedToKeyId, key.id), isNull(agentApiKeys.revokedAt)))
        .returning({ id: agentApiKeys.id });
      return {
        key: revoked,
        alreadyRevoked: Boolean(key.revokedAt),
        retiredPredecessorKeyIds: retiredPredecessors.map((row) => row.id),
      };
    },

    createEnrollmentCode: async (rule: AgentKeyIssuerRule, createdByAgentId: string, ttlDays?: number) => {
      const holder = await getAgent(rule.holderAgentId);
      if (!holder || holder.companyId !== rule.companyId || !isAuthenticatableAgentStatus(holder.status)) {
        throw conflict("The holder agent cannot receive keys");
      }
      const keyTtlDays = ttlDays ?? rule.maxTtlDays;
      if (keyTtlDays > rule.maxTtlDays) {
        throw forbidden(`ttlDays exceeds this issuer rule's maxTtlDays (${rule.maxTtlDays})`);
      }
      const code = createEnrollmentCodeValue();
      const expiresAt = new Date(Date.now() + AGENT_KEY_ENROLLMENT_CODE_TTL_MS);
      const row = await db
        .insert(agentKeyEnrollmentCodes)
        .values({
          companyId: rule.companyId,
          ruleId: rule.id,
          holderAgentId: rule.holderAgentId,
          issueId: rule.issueId,
          documentKey: rule.documentKey,
          ttlDays: keyTtlDays,
          codeHash: hashSecret(code),
          createdByAgentId,
          expiresAt,
        })
        .returning()
        .then((rows) => rows[0]!);
      return { row, code, scope: ruleScope(rule) };
    },

    /**
     * Single-use exchange. The code row is claimed atomically; a reused,
     * expired or unknown code fails with the same 401 so the endpoint is not
     * an oracle. `rejected` carries audit context for known codes.
     */
    exchangeEnrollmentCode: async (code: string, name: string | undefined) => {
      const codeHash = hashSecret(code);
      const now = new Date();
      return db.transaction(async (tx) => {
        const claimed = await tx
          .update(agentKeyEnrollmentCodes)
          .set({ consumedAt: now })
          .where(and(
            eq(agentKeyEnrollmentCodes.codeHash, codeHash),
            isNull(agentKeyEnrollmentCodes.consumedAt),
            gt(agentKeyEnrollmentCodes.expiresAt, now),
          ))
          .returning()
          .then((rows) => rows[0] ?? null);
        if (!claimed) {
          const known = await tx
            .select()
            .from(agentKeyEnrollmentCodes)
            .where(eq(agentKeyEnrollmentCodes.codeHash, codeHash))
            .then((rows) => rows[0] ?? null);
          return {
            ok: false as const,
            rejected: known
              ? { code: known, reason: known.consumedAt ? "already_used" as const : "expired" as const }
              : null,
          };
        }

        const rule = await tx
          .select()
          .from(agentKeyIssuerRules)
          .where(eq(agentKeyIssuerRules.id, claimed.ruleId))
          .then((rows) => rows[0] ?? null);
        const holder = await tx
          .select({ id: agents.id, companyId: agents.companyId, status: agents.status })
          .from(agents)
          .where(eq(agents.id, claimed.holderAgentId))
          .then((rows) => rows[0] ?? null);
        if (
          !rule
          || rule.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ
          || rule.companyId !== claimed.companyId
          || rule.holderAgentId !== claimed.holderAgentId
          || rule.issueId !== claimed.issueId
          || rule.documentKey !== claimed.documentKey
          // A code minted by a replaced issuer dies with that issuer's authority.
          || rule.issuerAgentId !== claimed.createdByAgentId
          || !holder
          || holder.companyId !== claimed.companyId
          || !isAuthenticatableAgentStatus(holder.status)
        ) {
          return {
            ok: false as const,
            rejected: { code: claimed, reason: "rule_or_holder_invalid" as const },
          };
        }

        const ttlDays = Math.min(claimed.ttlDays, rule.maxTtlDays, AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS);
        const scope = ruleScope(rule);
        const { row, token } = await insertIssueDocumentReadKey(tx, {
          agentId: rule.holderAgentId,
          companyId: rule.companyId,
          name: name ?? "sandbox-deny-sync",
          scope,
          expiresAt: new Date(now.getTime() + ttlDays * DAY_MS),
          responsibleUserId: rule.createdByUserId,
        });
        await tx
          .update(agentKeyEnrollmentCodes)
          .set({ consumedKeyId: row.id })
          .where(eq(agentKeyEnrollmentCodes.id, claimed.id));
        return { ok: true as const, code: claimed, rule, key: row, token, scope };
      });
    },

    /**
     * Self-rotation for an `issue_document_read` key. The successor copies the
     * stored scope (never request input), keeps the caller's original lifetime
     * capped by the issuer rule (403 when no rule covers the key), and the caller's key stays valid
     * until the successor is first used or the grace period ends.
     */
    rotate: async (keyId: string) => {
      const now = new Date();
      return db.transaction(async (tx) => {
        const current = await tx
          .select()
          .from(agentApiKeys)
          .where(eq(agentApiKeys.id, keyId))
          .for("update")
          .then((rows) => rows[0] ?? null);
        const scope = current ? parseIssueDocumentReadScope(current.scopeConfig) : null;
        if (!current || !scope || current.revokedAt || !current.expiresAt || current.expiresAt <= now) {
          throw unauthorized("Key is not an active issue_document_read key");
        }
        if (current.rotatedToKeyId) {
          throw conflict("Key was already rotated; use its successor");
        }
        const responsibleUserId = current.responsibleUserId?.trim();
        if (!responsibleUserId) throw forbidden("Responsible user is unavailable for this agent key");

        const rule = await tx
          .select()
          .from(agentKeyIssuerRules)
          .where(and(
            eq(agentKeyIssuerRules.companyId, current.companyId),
            eq(agentKeyIssuerRules.holderAgentId, current.agentId),
            eq(agentKeyIssuerRules.issueId, scope.issueId),
            eq(agentKeyIssuerRules.documentKey, scope.documentKey),
          ))
          .then((rows) => rows[0] ?? null);
        // Rotation is a delegated privilege: without a matching rule the key
        // cannot renew itself and simply runs out at its current expiry.
        if (!rule || rule.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ) {
          throw forbidden("No issuer rule covers this key; it cannot be rotated");
        }
        const capMs = Math.min(rule.maxTtlDays, AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS) * DAY_MS;
        const originalLifetimeMs = current.expiresAt.getTime() - current.createdAt.getTime();
        const lifetimeMs = Math.max(60_000, Math.min(originalLifetimeMs, capMs));

        const { row, token } = await insertIssueDocumentReadKey(tx, {
          agentId: current.agentId,
          companyId: current.companyId,
          name: current.name,
          scope,
          expiresAt: new Date(now.getTime() + lifetimeMs),
          responsibleUserId,
        });
        const graceEnd = new Date(now.getTime() + AGENT_KEY_ROTATION_GRACE_MS);
        const previous = await tx
          .update(agentApiKeys)
          .set({
            rotatedToKeyId: row.id,
            expiresAt: current.expiresAt < graceEnd ? current.expiresAt : graceEnd,
          })
          .where(eq(agentApiKeys.id, current.id))
          .returning()
          .then((rows) => rows[0]!);
        return { previous, key: row, token, scope, ruleId: rule.id };
      });
    },
  };
}
