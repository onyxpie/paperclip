import { pgTable, uuid, text, timestamp, index, jsonb } from "drizzle-orm/pg-core";
import type { AgentApiKeyScope } from "@paperclipai/shared";
import { agents } from "./agents.js";
import { companies } from "./companies.js";

export const agentApiKeys = pgTable(
  "agent_api_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    agentId: uuid("agent_id").notNull().references(() => agents.id),
    companyId: uuid("company_id").notNull().references(() => companies.id),
    name: text("name").notNull(),
    keyHash: text("key_hash").notNull(),
    responsibleUserId: text("responsible_user_id"),
    scopeConfig: jsonb("scope_config").$type<AgentApiKeyScope | null>(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    /** Authentication fails at or after this instant. Mandatory for `issue_document_read` keys. */
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    /** Set on the previous key by self-rotation; first use of that successor revokes this key. */
    rotatedToKeyId: uuid("rotated_to_key_id"),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    keyHashIdx: index("agent_api_keys_key_hash_idx").on(table.keyHash),
    companyAgentIdx: index("agent_api_keys_company_agent_idx").on(table.companyId, table.agentId),
    rotatedToKeyIdx: index("agent_api_keys_rotated_to_key_idx").on(table.rotatedToKeyId),
  }),
);
