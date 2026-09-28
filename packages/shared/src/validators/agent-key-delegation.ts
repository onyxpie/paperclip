import { z } from "zod";
import {
  AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS,
  AGENT_KEY_KIND_ISSUE_DOCUMENT_READ,
} from "../constants.js";
import { agentKeyDocumentKeySchema } from "./agent.js";

const maxTtlDaysSchema = z.number().int().min(1).max(AGENT_KEY_ISSUE_DOCUMENT_READ_MAX_TTL_DAYS);

/**
 * Board-only company setting that lets one agent (the issuer) manage
 * `issue_document_read` keys for exactly one holder agent, issue and document.
 */
export const createAgentKeyIssuerRuleSchema = z.object({
  issuerAgentId: z.string().guid(),
  holderAgentId: z.string().guid(),
  kind: z.literal(AGENT_KEY_KIND_ISSUE_DOCUMENT_READ),
  issueId: z.string().guid(),
  documentKey: agentKeyDocumentKeySchema,
  maxTtlDays: maxTtlDaysSchema,
}).strict().superRefine((value, ctx) => {
  if (value.issuerAgentId === value.holderAgentId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "The issuer cannot be the key holder",
      path: ["issuerAgentId"],
    });
  }
});

export type CreateAgentKeyIssuerRule = z.infer<typeof createAgentKeyIssuerRuleSchema>;

/** Holder, kind, issue and document are immutable; replace the rule to change them. */
export const updateAgentKeyIssuerRuleSchema = z.object({
  issuerAgentId: z.string().guid().optional(),
  maxTtlDays: maxTtlDaysSchema.optional(),
}).strict();

export type UpdateAgentKeyIssuerRule = z.infer<typeof updateAgentKeyIssuerRuleSchema>;

/**
 * Issuer request for a single-use enrollment code. Target fields are optional
 * assertions: when present they must equal the rule, otherwise the server
 * returns 403. `ttlDays` sets the lifetime of the key minted on exchange.
 */
export const createAgentKeyEnrollmentCodeSchema = z.object({
  holderAgentId: z.string().guid().optional(),
  kind: z.string().optional(),
  issueId: z.string().optional(),
  documentKey: z.string().optional(),
  ttlDays: maxTtlDaysSchema.optional(),
}).strict();

export type CreateAgentKeyEnrollmentCode = z.infer<typeof createAgentKeyEnrollmentCodeSchema>;

export const exchangeAgentKeyEnrollmentCodeSchema = z.object({
  enrollmentCode: z.string().trim().min(16).max(256),
  name: z.string().trim().min(1).max(100).optional(),
}).strict();

export type ExchangeAgentKeyEnrollmentCode = z.infer<typeof exchangeAgentKeyEnrollmentCodeSchema>;
