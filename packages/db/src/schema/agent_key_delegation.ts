import { pgTable, uuid, text, integer, timestamp, index, uniqueIndex } from "drizzle-orm/pg-core";
import { agents } from "./agents.js";
import { companies } from "./companies.js";
import { issues } from "./issues.js";
import { agentApiKeys } from "./agent_api_keys.js";

/**
 * Board-managed delegation: `issuerAgentId` may list, revoke and enroll
 * `issue_document_read` keys for exactly `holderAgentId` on one issue document.
 */
export const agentKeyIssuerRules = pgTable(
  "agent_key_issuer_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
    issuerAgentId: uuid("issuer_agent_id").notNull().references(() => agents.id, { onDelete: "cascade" }),
    holderAgentId: uuid("holder_agent_id").notNull().references(() => agents.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    issueId: uuid("issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
    documentKey: text("document_key").notNull(),
    maxTtlDays: integer("max_ttl_days").notNull(),
    /** Board user who created the rule; becomes the responsible user of enrolled keys. */
    createdByUserId: text("created_by_user_id").notNull(),
    updatedByUserId: text("updated_by_user_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    holderScopeUniqueIdx: uniqueIndex("agent_key_issuer_rules_holder_scope_idx").on(
      table.companyId,
      table.holderAgentId,
      table.issueId,
      table.documentKey,
    ),
    companyIssuerIdx: index("agent_key_issuer_rules_company_issuer_idx").on(table.companyId, table.issuerAgentId),
  }),
);

/** Single-use enrollment codes. Only the SHA-256 of the code is stored. */
export const agentKeyEnrollmentCodes = pgTable(
  "agent_key_enrollment_codes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
    ruleId: uuid("rule_id").notNull().references(() => agentKeyIssuerRules.id, { onDelete: "cascade" }),
    holderAgentId: uuid("holder_agent_id").notNull().references(() => agents.id, { onDelete: "cascade" }),
    issueId: uuid("issue_id").notNull(),
    documentKey: text("document_key").notNull(),
    ttlDays: integer("ttl_days").notNull(),
    codeHash: text("code_hash").notNull(),
    createdByAgentId: uuid("created_by_agent_id").notNull().references(() => agents.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    consumedKeyId: uuid("consumed_key_id").references(() => agentApiKeys.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    codeHashUniqueIdx: uniqueIndex("agent_key_enrollment_codes_code_hash_idx").on(table.codeHash),
    ruleIdx: index("agent_key_enrollment_codes_rule_idx").on(table.ruleId),
  }),
);
