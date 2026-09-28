import { Router, type Request, type Response } from "express";
import type { Db } from "@paperclipai/db";
import {
  AGENT_KEY_KIND_ISSUE_DOCUMENT_READ,
  createAgentKeyEnrollmentCodeSchema,
  createAgentKeyIssuerRuleSchema,
  exchangeAgentKeyEnrollmentCodeSchema,
  updateAgentKeyIssuerRuleSchema,
} from "@paperclipai/shared";
import { forbidden, notFound } from "../errors.js";
import { validate } from "../middleware/validate.js";
import { accessService, logActivity } from "../services/index.js";
import {
  agentKeyDelegationService,
  toIssueDocumentReadKeyMetadata,
  type AgentKeyIssuerRule,
} from "../services/agent-key-delegation.js";
import { authorizationDeniedDetails } from "../services/authorization.js";
import { assertBoard, assertCompanyAccess, getActorInfo, hasCompanyAccess } from "./authz.js";

function ruleView(rule: AgentKeyIssuerRule) {
  return {
    id: rule.id,
    companyId: rule.companyId,
    issuerAgentId: rule.issuerAgentId,
    holderAgentId: rule.holderAgentId,
    kind: rule.kind,
    issueId: rule.issueId,
    documentKey: rule.documentKey,
    maxTtlDays: rule.maxTtlDays,
    createdByUserId: rule.createdByUserId,
    updatedByUserId: rule.updatedByUserId,
    createdAt: rule.createdAt,
    updatedAt: rule.updatedAt,
  };
}

function ruleScopeDetails(rule: AgentKeyIssuerRule) {
  return { kind: rule.kind, issueId: rule.issueId, documentKey: rule.documentKey };
}

function noStore(res: Response) {
  res.set("Cache-Control", "no-store");
}

/**
 * ONY-200 K2–K5: self-rotation and self-revoke for `issue_document_read` keys, board-managed
 * delegated issuer rules, issuer-scoped key operations, and single-use
 * enrollment codes. Every mint, rotate, revoke, enroll-create and exchange is
 * written to the activity log without the key or code value.
 */
export function agentKeyDelegationRoutes(db: Db) {
  const router = Router();
  const access = accessService(db);
  const delegation = agentKeyDelegationService(db);

  async function assertBoardCanManageRules(req: Request, companyId: string) {
    assertBoard(req);
    assertCompanyAccess(req, companyId);
    const decision = await access.decide({
      actor: req.actor,
      action: "agents:create",
      resource: { type: "company", companyId },
    });
    if (!decision.allowed) throw forbidden(decision.explanation, authorizationDeniedDetails(decision));
  }

  async function loadBoardRule(req: Request) {
    assertBoard(req);
    const rule = await delegation.getRule(req.params.ruleId as string);
    if (!rule || !hasCompanyAccess(req, rule.companyId)) {
      throw notFound("Issuer rule not found");
    }
    await assertBoardCanManageRules(req, rule.companyId);
    return rule;
  }

  /** Issuer operations require the rule's issuer agent with full (standard) agent authority. */
  async function loadIssuerRule(req: Request) {
    if (req.actor.type !== "agent" || !req.actor.agentId || !req.actor.companyId) {
      throw forbidden("Only the rule's issuer agent can manage these keys");
    }
    const scopeKind = req.actor.keyScope?.kind ?? "standard";
    if (scopeKind !== "standard") {
      throw forbidden("Scoped agent keys cannot manage delegated keys");
    }
    const rule = await delegation.getRule(req.params.ruleId as string);
    if (!rule || !hasCompanyAccess(req, rule.companyId)) throw notFound("Issuer rule not found");
    if (rule.issuerAgentId !== req.actor.agentId) {
      throw forbidden("Only the rule's issuer agent can manage these keys");
    }
    assertCompanyAccess(req, rule.companyId);
    return rule;
  }

  // ---- Board: issuer rule administration (K3) ----

  router.get("/companies/:companyId/agent-key-issuer-rules", async (req, res) => {
    const companyId = req.params.companyId as string;
    await assertBoardCanManageRules(req, companyId);
    const rules = await delegation.listRules(companyId);
    res.json(rules.map(ruleView));
  });

  router.post(
    "/companies/:companyId/agent-key-issuer-rules",
    validate(createAgentKeyIssuerRuleSchema),
    async (req, res) => {
      const companyId = req.params.companyId as string;
      await assertBoardCanManageRules(req, companyId);
      const actor = getActorInfo(req);
      const rule = await delegation.createRule(companyId, req.body, actor.actorId);
      await logActivity(db, {
        companyId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action: "agent_key_issuer_rule.created",
        entityType: "agent_key_issuer_rule",
        entityId: rule.id,
        details: {
          ruleId: rule.id,
          issuerAgentId: rule.issuerAgentId,
          holderAgentId: rule.holderAgentId,
          scope: ruleScopeDetails(rule),
          maxTtlDays: rule.maxTtlDays,
        },
      });
      res.status(201).json(ruleView(rule));
    },
  );

  router.patch(
    "/agent-key-issuer-rules/:ruleId",
    validate(updateAgentKeyIssuerRuleSchema),
    async (req, res) => {
      const rule = await loadBoardRule(req);
      const actor = getActorInfo(req);
      const updated = await delegation.updateRule(rule, req.body, actor.actorId);
      await logActivity(db, {
        companyId: rule.companyId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action: "agent_key_issuer_rule.updated",
        entityType: "agent_key_issuer_rule",
        entityId: rule.id,
        details: {
          ruleId: rule.id,
          holderAgentId: rule.holderAgentId,
          scope: ruleScopeDetails(rule),
          previous: { issuerAgentId: rule.issuerAgentId, maxTtlDays: rule.maxTtlDays },
          next: { issuerAgentId: updated.issuerAgentId, maxTtlDays: updated.maxTtlDays },
        },
      });
      res.json(ruleView(updated));
    },
  );

  router.delete("/agent-key-issuer-rules/:ruleId", async (req, res) => {
    const rule = await loadBoardRule(req);
    const actor = getActorInfo(req);
    const { revokedKeyIds } = await delegation.deleteRule(rule);
    await logActivity(db, {
      companyId: rule.companyId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      action: "agent_key_issuer_rule.deleted",
      entityType: "agent_key_issuer_rule",
      entityId: rule.id,
      details: {
        ruleId: rule.id,
        issuerAgentId: rule.issuerAgentId,
        holderAgentId: rule.holderAgentId,
        scope: ruleScopeDetails(rule),
        revokedKeyIds,
      },
    });
    for (const keyId of revokedKeyIds) {
      await logActivity(db, {
        companyId: rule.companyId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action: "agent_key.revoked",
        entityType: "agent_api_key",
        entityId: keyId,
        details: {
          ruleId: rule.id,
          holderAgentId: rule.holderAgentId,
          keyId,
          scope: ruleScopeDetails(rule),
          reason: "issuer_rule_deleted",
        },
      });
    }
    res.json({ ok: true, revokedKeyIds });
  });

  // ---- Issuer: rule-bound key operations (K3/K4) ----

  router.get("/agents/me/key-issuer-rules", async (req, res) => {
    if (req.actor.type !== "agent" || !req.actor.agentId || !req.actor.companyId) {
      throw forbidden("Agent authentication required");
    }
    if ((req.actor.keyScope?.kind ?? "standard") !== "standard") {
      throw forbidden("Scoped agent keys cannot manage delegated keys");
    }
    const rules = await delegation.listRulesForIssuer(req.actor.companyId, req.actor.agentId);
    res.json(rules.map(ruleView));
  });

  router.get("/agent-key-issuer-rules/:ruleId/keys", async (req, res) => {
    const rule = await loadIssuerRule(req);
    res.json(await delegation.listRuleKeys(rule));
  });

  router.post("/agent-key-issuer-rules/:ruleId/keys/:keyId/revoke", async (req, res) => {
    const rule = await loadIssuerRule(req);
    const { key, alreadyRevoked, retiredPredecessorKeyIds } = await delegation.revokeRuleKey(
      rule,
      req.params.keyId as string,
    );
    if (!alreadyRevoked || retiredPredecessorKeyIds.length > 0) {
      const actor = getActorInfo(req);
      await logActivity(db, {
        companyId: rule.companyId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        agentId: actor.agentId,
        runId: actor.runId,
        agentApiKeyId: actor.agentApiKeyId,
        action: "agent_key.revoked",
        entityType: "agent_api_key",
        entityId: key.id,
        details: {
          via: "issuer_rule",
          ruleId: rule.id,
          issuerAgentId: rule.issuerAgentId,
          holderAgentId: rule.holderAgentId,
          keyId: key.id,
          retiredPredecessorKeyIds,
          scope: ruleScopeDetails(rule),
          expiresAt: key.expiresAt,
        },
      });
    }
    res.json(toIssueDocumentReadKeyMetadata(key));
  });

  router.post(
    "/agent-key-issuer-rules/:ruleId/enrollment-codes",
    validate(createAgentKeyEnrollmentCodeSchema),
    async (req, res) => {
      const rule = await loadIssuerRule(req);
      const body = req.body as {
        holderAgentId?: string;
        kind?: string;
        issueId?: string;
        documentKey?: string;
        ttlDays?: number;
      };
      if (
        (body.holderAgentId !== undefined && body.holderAgentId !== rule.holderAgentId)
        || (body.kind !== undefined && body.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ)
        || (body.issueId !== undefined && body.issueId !== rule.issueId)
        || (body.documentKey !== undefined && body.documentKey !== rule.documentKey)
      ) {
        throw forbidden("Enrollment codes can only target this rule's holder, kind, issue and document");
      }
      const actor = getActorInfo(req);
      const { row, code, scope } = await delegation.createEnrollmentCode(rule, req.actor.agentId!, body.ttlDays);
      await logActivity(db, {
        companyId: rule.companyId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        agentId: actor.agentId,
        runId: actor.runId,
        agentApiKeyId: actor.agentApiKeyId,
        action: "agent_key.enrollment_code_created",
        entityType: "agent_key_enrollment_code",
        entityId: row.id,
        details: {
          ruleId: rule.id,
          codeId: row.id,
          issuerAgentId: rule.issuerAgentId,
          holderAgentId: rule.holderAgentId,
          scope,
          codeExpiresAt: row.expiresAt,
          keyTtlDays: row.ttlDays,
        },
      });
      noStore(res);
      res.status(201).json({
        id: row.id,
        enrollmentCode: code,
        expiresAt: row.expiresAt,
        holderAgentId: rule.holderAgentId,
        scope,
        keyTtlDays: row.ttlDays,
      });
    },
  );

  // ---- Unauthenticated: single-use code exchange (K4) ----

  router.post(
    "/agent-key-enrollments/exchange",
    validate(exchangeAgentKeyEnrollmentCodeSchema),
    async (req, res) => {
      noStore(res);
      const result = await delegation.exchangeEnrollmentCode(req.body.enrollmentCode, req.body.name);
      if (!result.ok) {
        if (result.rejected) {
          const { code, reason } = result.rejected;
          await logActivity(db, {
            companyId: code.companyId,
            actorType: "system",
            actorId: "agent-key-enrollment",
            action: "agent_key.enrollment_code_rejected",
            entityType: "agent_key_enrollment_code",
            entityId: code.id,
            details: {
              reason,
              ruleId: code.ruleId,
              codeId: code.id,
              holderAgentId: code.holderAgentId,
              scope: { kind: AGENT_KEY_KIND_ISSUE_DOCUMENT_READ, issueId: code.issueId, documentKey: code.documentKey },
              consumedKeyId: code.consumedKeyId,
            },
          });
        }
        res.status(401).json({ error: "Invalid or expired enrollment code" });
        return;
      }
      const { code, rule, key, token, scope } = result;
      await logActivity(db, {
        companyId: rule.companyId,
        actorType: "agent",
        actorId: rule.holderAgentId,
        agentId: rule.holderAgentId,
        action: "agent_key.enrollment_code_exchanged",
        entityType: "agent_api_key",
        entityId: key.id,
        details: {
          via: "enrollment_code",
          ruleId: rule.id,
          codeId: code.id,
          issuerAgentId: code.createdByAgentId,
          holderAgentId: rule.holderAgentId,
          keyId: key.id,
          scope,
          expiresAt: key.expiresAt,
        },
      });
      res.status(201).json({
        id: key.id,
        agentId: key.agentId,
        companyId: key.companyId,
        name: key.name,
        token,
        scope,
        expiresAt: key.expiresAt,
        createdAt: key.createdAt,
      });
    },
  );

  // ---- Holder: self-rotation (K2) ----

  router.post("/agents/me/keys/rotate", async (req, res) => {
    if (
      req.actor.type !== "agent"
      || req.actor.source !== "agent_key"
      || !req.actor.keyId
      || req.actor.keyScope?.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ
    ) {
      throw forbidden("Only issue_document_read keys can self-rotate");
    }
    // The request body is intentionally ignored: scope comes from the calling key.
    const { previous, key, token, scope, ruleId } = await delegation.rotate(req.actor.keyId);
    const actor = getActorInfo(req);
    await logActivity(db, {
      companyId: key.companyId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      agentId: actor.agentId,
      runId: actor.runId,
      agentApiKeyId: actor.agentApiKeyId,
      action: "agent_key.rotated",
      entityType: "agent_api_key",
      entityId: key.id,
      details: {
        ruleId,
        holderAgentId: key.agentId,
        previousKeyId: previous.id,
        previousKeyExpiresAt: previous.expiresAt,
        keyId: key.id,
        scope,
        expiresAt: key.expiresAt,
      },
    });
    noStore(res);
    res.status(201).json({
      id: key.id,
      agentId: key.agentId,
      name: key.name,
      token,
      scope,
      expiresAt: key.expiresAt,
      createdAt: key.createdAt,
      previousKeyId: previous.id,
      previousKeyExpiresAt: previous.expiresAt,
    });
  });

  // ---- Holder: self-revoke (S1, uninstall) ----

  router.post("/agents/me/keys/revoke", async (req, res) => {
    if (
      req.actor.type !== "agent"
      || req.actor.source !== "agent_key"
      || !req.actor.keyId
      || req.actor.keyScope?.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ
    ) {
      throw forbidden("Only issue_document_read keys can self-revoke");
    }
    // The request body is intentionally ignored: a key can only revoke itself and its rotation chain.
    const { key, scope, revokedKeyIds } = await delegation.revokeSelf(req.actor.keyId);
    const actor = getActorInfo(req);
    await logActivity(db, {
      companyId: key.companyId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      agentId: actor.agentId,
      runId: actor.runId,
      agentApiKeyId: actor.agentApiKeyId,
      action: "agent_key.revoked",
      entityType: "agent_api_key",
      entityId: key.id,
      details: {
        via: "self",
        holderAgentId: key.agentId,
        keyId: key.id,
        revokedKeyIds,
        scope,
        expiresAt: key.expiresAt,
      },
    });
    noStore(res);
    res.json({ ok: true, keyId: key.id, revokedAt: key.revokedAt, revokedKeyIds });
  });

  return router;
}
