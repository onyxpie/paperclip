import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

/**
 * Operator-only, time-boxed Claude sandbox network canary.
 *
 * The setting lives in the Paperclip SERVER process environment, never in
 * `adapterConfig`: agents can PATCH their own adapterConfig (allow_self), and
 * `adapterConfig.env` only reaches the child process, not this process. So an
 * agent cannot set, widen, or retarget the canary.
 *
 * Value: JSON `{ "agentId", "settingsPath", "sha256", "expiresAt" }`.
 * For that one agent, before `expiresAt`, the CLI lane passes the verified
 * bytes of `settingsPath` to `claude --settings` (Claude Code's flag tier, where
 * `sandbox.network.strictAllowlist` is honored). The bytes are passed inline,
 * so the file cannot change between the sha check and Claude reading it.
 *
 * When the variable is unset or targets another agent, this returns
 * `inactive` and the caller changes nothing (same argv, same logs).
 */
export const CLAUDE_SANDBOX_NETWORK_CANARY_ENV = "PAPERCLIP_CLAUDE_SANDBOX_NETWORK_CANARY";

export type ClaudeSandboxNetworkCanary =
  | { kind: "inactive"; notice?: string }
  | {
      kind: "active";
      agentId: string;
      settingsPath: string;
      sha256: string;
      expiresAt: string;
      settingsJson: string;
    }
  | { kind: "rejected"; message: string };

const SHA256_HEX = /^[0-9a-f]{64}$/;

export async function resolveClaudeSandboxNetworkCanary(input: {
  agentId: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  readFile?: (filePath: string) => Promise<Buffer>;
}): Promise<ClaudeSandboxNetworkCanary> {
  const raw = (input.env ?? process.env)[CLAUDE_SANDBOX_NETWORK_CANARY_ENV];
  if (typeof raw !== "string" || raw.trim().length === 0) return { kind: "inactive" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Unparseable: the target agent can't be identified, so no run can be
    // matched. The canary probe requires the sha log line, so a missing
    // canary is visible there rather than silently passing.
    return {
      kind: "inactive",
      notice: `${CLAUDE_SANDBOX_NETWORK_CANARY_ENV} is not valid JSON; sandbox-network canary ignored.`,
    };
  }
  const config = parsed && typeof parsed === "object" && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : null;
  const agentId = typeof config?.agentId === "string" ? config.agentId.trim() : "";
  if (!agentId || agentId !== input.agentId) return { kind: "inactive" };

  // From here on the canary targets this agent: any problem fails the run closed.
  const reject = (message: string): ClaudeSandboxNetworkCanary => ({
    kind: "rejected",
    message: `sandbox-network canary rejected: ${message}`,
  });
  const settingsPath = typeof config?.settingsPath === "string" ? config.settingsPath.trim() : "";
  const expectedSha = typeof config?.sha256 === "string" ? config.sha256.trim().toLowerCase() : "";
  const expiresAtRaw = typeof config?.expiresAt === "string" ? config.expiresAt.trim() : "";
  if (!settingsPath || !path.isAbsolute(settingsPath)) return reject("settingsPath must be an absolute path.");
  if (!SHA256_HEX.test(expectedSha)) return reject("sha256 must be 64 lowercase hex characters.");
  const expiresAtMs = Date.parse(expiresAtRaw);
  if (!expiresAtRaw || Number.isNaN(expiresAtMs)) return reject("expiresAt must be an ISO-8601 timestamp.");

  const now = input.now ?? new Date();
  if (now.getTime() >= expiresAtMs) {
    return {
      kind: "inactive",
      notice: `sandbox-network canary expired at ${new Date(expiresAtMs).toISOString()}; ignored.`,
    };
  }

  let bytes: Buffer;
  try {
    bytes = await (input.readFile ?? ((p: string) => fs.readFile(p)))(settingsPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code ?? "read_failed";
    return reject(`could not read settingsPath (${code}).`);
  }
  const actualSha = createHash("sha256").update(bytes).digest("hex");
  if (actualSha !== expectedSha) {
    return reject(`sha256 mismatch for ${settingsPath} (expected ${expectedSha}, got ${actualSha}).`);
  }
  const settingsJson = bytes.toString("utf8");
  let settings: unknown;
  try {
    settings = JSON.parse(settingsJson);
  } catch {
    return reject("settings file is not valid JSON.");
  }
  if (!settings || typeof settings !== "object" || Array.isArray(settings)) {
    return reject("settings file must contain a JSON object.");
  }

  return {
    kind: "active",
    agentId,
    settingsPath,
    sha256: actualSha,
    expiresAt: new Date(expiresAtMs).toISOString(),
    settingsJson,
  };
}

/** Flags the canary owns; adapter extraArgs must not also set them. */
const CANARY_OWNED_FLAGS = ["--settings", "--setting-sources"];

export function findCanaryConflictingArg(extraArgs: readonly string[]): string | null {
  for (const arg of extraArgs) {
    for (const flag of CANARY_OWNED_FLAGS) {
      if (arg === flag || arg.startsWith(`${flag}=`)) return flag;
    }
  }
  return null;
}

export function claudeSandboxNetworkCanaryArgs(canary: ClaudeSandboxNetworkCanary): string[] {
  return canary.kind === "active" ? ["--settings", canary.settingsJson] : [];
}

export function describeClaudeSandboxNetworkCanary(
  canary: Extract<ClaudeSandboxNetworkCanary, { kind: "active" }>,
): string {
  return `[paperclip] sandbox-network canary sha=${canary.sha256} path=${canary.settingsPath} expiresAt=${canary.expiresAt} tier=flag(--settings)\n`;
}
