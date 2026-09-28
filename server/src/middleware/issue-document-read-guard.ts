import type { RequestHandler } from "express";
import { eq } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { issues } from "@paperclipai/db";
import { AGENT_KEY_KIND_ISSUE_DOCUMENT_READ, type IssueDocumentReadAgentKeyScope } from "@paperclipai/shared";

const READ_METHODS = new Set(["GET", "HEAD"]);
const AGENTS_ME_PATH = /^\/api\/agents\/me\/?$/i;
const ROTATE_PATH = /^\/api\/agents\/me\/keys\/rotate\/?$/i;
const DOCUMENT_PATH = /^\/api\/issues\/([^/]+)\/documents\/([^/]+)(\/revisions)?\/?$/i;

function decodeSegment(segment: string) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

function deny(res: Parameters<RequestHandler>[1]) {
  res.status(403).json({
    error: "issue_document_read keys can only read their scoped issue document",
    code: "agent_key_scope_denied",
  });
}

/**
 * Fail-closed allowlist for `issue_document_read` agent keys (ONY-200 K1).
 * Runs once after actor resolution for every request, so a new or unaudited
 * route can never become reachable with a read-only document key. Allowed:
 * GET the scoped document and its revisions, GET `/api/agents/me`, and
 * POST `/api/agents/me/keys/rotate`. Everything else returns 403.
 */
export function issueDocumentReadKeyGuard(db: Db): RequestHandler {
  async function paramMatchesScopedIssue(param: string, scope: IssueDocumentReadAgentKeyScope, companyId: string) {
    if (param.toLowerCase() === scope.issueId.toLowerCase()) return true;
    const issue = await db
      .select({ identifier: issues.identifier, companyId: issues.companyId })
      .from(issues)
      .where(eq(issues.id, scope.issueId))
      .then((rows) => rows[0] ?? null);
    return Boolean(
      issue?.identifier
      && issue.companyId === companyId
      && issue.identifier.toUpperCase() === param.trim().toUpperCase(),
    );
  }

  return async (req, res, next) => {
    const scope = req.actor.type === "agent" ? req.actor.keyScope : undefined;
    if (scope?.kind !== AGENT_KEY_KIND_ISSUE_DOCUMENT_READ) {
      next();
      return;
    }
    try {
      const method = req.method.toUpperCase();
      const path = req.path;
      if (READ_METHODS.has(method) && AGENTS_ME_PATH.test(path)) {
        next();
        return;
      }
      if (method === "POST" && ROTATE_PATH.test(path)) {
        next();
        return;
      }
      const match = READ_METHODS.has(method) ? DOCUMENT_PATH.exec(path) : null;
      if (!match || Object.keys(req.query ?? {}).length > 0) {
        deny(res);
        return;
      }
      const issueParam = decodeSegment(match[1]!);
      const keyParam = decodeSegment(match[2]!);
      if (
        issueParam === null
        || keyParam === null
        || keyParam.trim().toLowerCase() !== scope.documentKey
        || !req.actor.companyId
        || !(await paramMatchesScopedIssue(issueParam, scope, req.actor.companyId))
      ) {
        deny(res);
        return;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}
