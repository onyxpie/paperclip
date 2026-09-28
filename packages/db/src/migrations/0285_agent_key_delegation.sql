CREATE TABLE "agent_key_enrollment_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"holder_agent_id" uuid NOT NULL,
	"issue_id" uuid NOT NULL,
	"document_key" text NOT NULL,
	"ttl_days" integer NOT NULL,
	"code_hash" text NOT NULL,
	"created_by_agent_id" uuid NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"consumed_key_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_key_issuer_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"issuer_agent_id" uuid NOT NULL,
	"holder_agent_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"issue_id" uuid NOT NULL,
	"document_key" text NOT NULL,
	"max_ttl_days" integer NOT NULL,
	"created_by_user_id" text NOT NULL,
	"updated_by_user_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agent_api_keys" ADD COLUMN "expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agent_api_keys" ADD COLUMN "rotated_to_key_id" uuid;--> statement-breakpoint
ALTER TABLE "agent_key_enrollment_codes" ADD CONSTRAINT "agent_key_enrollment_codes_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_enrollment_codes" ADD CONSTRAINT "agent_key_enrollment_codes_rule_id_agent_key_issuer_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."agent_key_issuer_rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_enrollment_codes" ADD CONSTRAINT "agent_key_enrollment_codes_holder_agent_id_agents_id_fk" FOREIGN KEY ("holder_agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_enrollment_codes" ADD CONSTRAINT "agent_key_enrollment_codes_created_by_agent_id_agents_id_fk" FOREIGN KEY ("created_by_agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_enrollment_codes" ADD CONSTRAINT "agent_key_enrollment_codes_consumed_key_id_agent_api_keys_id_fk" FOREIGN KEY ("consumed_key_id") REFERENCES "public"."agent_api_keys"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_issuer_rules" ADD CONSTRAINT "agent_key_issuer_rules_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_issuer_rules" ADD CONSTRAINT "agent_key_issuer_rules_issuer_agent_id_agents_id_fk" FOREIGN KEY ("issuer_agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_issuer_rules" ADD CONSTRAINT "agent_key_issuer_rules_holder_agent_id_agents_id_fk" FOREIGN KEY ("holder_agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_key_issuer_rules" ADD CONSTRAINT "agent_key_issuer_rules_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "agent_key_enrollment_codes_code_hash_idx" ON "agent_key_enrollment_codes" USING btree ("code_hash");--> statement-breakpoint
CREATE INDEX "agent_key_enrollment_codes_rule_idx" ON "agent_key_enrollment_codes" USING btree ("rule_id");--> statement-breakpoint
CREATE UNIQUE INDEX "agent_key_issuer_rules_holder_scope_idx" ON "agent_key_issuer_rules" USING btree ("company_id","holder_agent_id","issue_id","document_key");--> statement-breakpoint
CREATE INDEX "agent_key_issuer_rules_company_issuer_idx" ON "agent_key_issuer_rules" USING btree ("company_id","issuer_agent_id");--> statement-breakpoint
CREATE INDEX "agent_api_keys_rotated_to_key_idx" ON "agent_api_keys" USING btree ("rotated_to_key_id");