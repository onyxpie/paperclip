import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CLAUDE_SANDBOX_NETWORK_CANARY_ENV,
  claudeSandboxNetworkCanaryArgs,
  describeClaudeSandboxNetworkCanary,
  findCanaryConflictingArg,
  resolveClaudeSandboxNetworkCanary,
} from "./sandbox-network-canary.js";

const AGENT = "11111111-2222-3333-4444-555555555555";
const OTHER_AGENT = "99999999-8888-7777-6666-555555555555";
const SETTINGS_PATH = "/opt/paperclip/canary/settings.json";
const SETTINGS = Buffer.from(
  JSON.stringify({ sandbox: { network: { allowedDomains: ["127.0.0.1:3100"], strictAllowlist: true } } }, null, 2) + "\n",
);
const SHA = createHash("sha256").update(SETTINGS).digest("hex");
const NOW = new Date("2026-09-28T12:00:00.000Z");
const LATER = "2026-09-28T14:00:00.000Z";

function envFor(config: unknown): NodeJS.ProcessEnv {
  return { [CLAUDE_SANDBOX_NETWORK_CANARY_ENV]: typeof config === "string" ? config : JSON.stringify(config) };
}

function readFileFrom(files: Record<string, Buffer>) {
  const reads: string[] = [];
  const readFile = async (filePath: string) => {
    reads.push(filePath);
    const bytes = files[filePath];
    if (!bytes) throw Object.assign(new Error("missing"), { code: "ENOENT" });
    return bytes;
  };
  return { readFile, reads };
}

describe("Claude sandbox-network canary", () => {
  it("is inactive and reads nothing when unset", async () => {
    const { readFile, reads } = readFileFrom({ [SETTINGS_PATH]: SETTINGS });
    for (const env of [{}, { [CLAUDE_SANDBOX_NETWORK_CANARY_ENV]: "" }, { [CLAUDE_SANDBOX_NETWORK_CANARY_ENV]: "  " }]) {
      const canary = await resolveClaudeSandboxNetworkCanary({ agentId: AGENT, env, now: NOW, readFile });
      expect(canary).toEqual({ kind: "inactive" });
      expect(claudeSandboxNetworkCanaryArgs(canary)).toEqual([]);
    }
    expect(reads).toEqual([]);
  });

  it("is inactive and silent for any other agent", async () => {
    const { readFile, reads } = readFileFrom({ [SETTINGS_PATH]: SETTINGS });
    const canary = await resolveClaudeSandboxNetworkCanary({
      agentId: OTHER_AGENT,
      env: envFor({ agentId: AGENT, settingsPath: SETTINGS_PATH, sha256: SHA, expiresAt: LATER }),
      now: NOW,
      readFile,
    });
    expect(canary).toEqual({ kind: "inactive" });
    expect(reads).toEqual([]);
  });

  it("passes the verified bytes inline to --settings for the matching agent", async () => {
    const { readFile } = readFileFrom({ [SETTINGS_PATH]: SETTINGS });
    const canary = await resolveClaudeSandboxNetworkCanary({
      agentId: AGENT,
      env: envFor({ agentId: AGENT, settingsPath: SETTINGS_PATH, sha256: SHA.toUpperCase(), expiresAt: LATER }),
      now: NOW,
      readFile,
    });
    expect(canary).toMatchObject({ kind: "active", sha256: SHA, settingsPath: SETTINGS_PATH, expiresAt: LATER });
    expect(claudeSandboxNetworkCanaryArgs(canary)).toEqual(["--settings", SETTINGS.toString("utf8")]);
    if (canary.kind !== "active") throw new Error("expected active");
    expect(describeClaudeSandboxNetworkCanary(canary)).toContain(`sandbox-network canary sha=${SHA}`);
  });

  it("fails closed on a sha256 mismatch", async () => {
    const { readFile } = readFileFrom({ [SETTINGS_PATH]: Buffer.concat([SETTINGS, Buffer.from(" ")]) });
    const canary = await resolveClaudeSandboxNetworkCanary({
      agentId: AGENT,
      env: envFor({ agentId: AGENT, settingsPath: SETTINGS_PATH, sha256: SHA, expiresAt: LATER }),
      now: NOW,
      readFile,
    });
    expect(canary.kind).toBe("rejected");
    if (canary.kind === "rejected") expect(canary.message).toContain("sha256 mismatch");
    expect(claudeSandboxNetworkCanaryArgs(canary)).toEqual([]);
  });

  it("is ignored once expired, without reading the file", async () => {
    const { readFile, reads } = readFileFrom({ [SETTINGS_PATH]: SETTINGS });
    for (const expiresAt of ["2026-09-28T11:59:59.000Z", NOW.toISOString()]) {
      const canary = await resolveClaudeSandboxNetworkCanary({
        agentId: AGENT,
        env: envFor({ agentId: AGENT, settingsPath: SETTINGS_PATH, sha256: SHA, expiresAt }),
        now: NOW,
        readFile,
      });
      expect(canary.kind).toBe("inactive");
      expect(canary.kind === "inactive" && canary.notice).toContain("expired");
      expect(claudeSandboxNetworkCanaryArgs(canary)).toEqual([]);
    }
    expect(reads).toEqual([]);
  });

  it.each([
    [{ settingsPath: "relative/settings.json", sha256: SHA, expiresAt: LATER }, "absolute path"],
    [{ settingsPath: SETTINGS_PATH, sha256: "abc", expiresAt: LATER }, "sha256 must be"],
    [{ settingsPath: SETTINGS_PATH, sha256: SHA, expiresAt: "soon" }, "expiresAt must be"],
    [{ settingsPath: "/missing.json", sha256: SHA, expiresAt: LATER }, "ENOENT"],
  ])("fails closed on an invalid config for the target agent (%j)", async (config, expected) => {
    const { readFile } = readFileFrom({ [SETTINGS_PATH]: SETTINGS });
    const canary = await resolveClaudeSandboxNetworkCanary({
      agentId: AGENT,
      env: envFor({ agentId: AGENT, ...config }),
      now: NOW,
      readFile,
    });
    expect(canary.kind).toBe("rejected");
    if (canary.kind === "rejected") expect(canary.message).toContain(expected);
  });

  it("fails closed when the pinned file is not a JSON object", async () => {
    const bytes = Buffer.from("[1,2]\n");
    const { readFile } = readFileFrom({ [SETTINGS_PATH]: bytes });
    const canary = await resolveClaudeSandboxNetworkCanary({
      agentId: AGENT,
      env: envFor({
        agentId: AGENT,
        settingsPath: SETTINGS_PATH,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        expiresAt: LATER,
      }),
      now: NOW,
      readFile,
    });
    expect(canary.kind).toBe("rejected");
  });

  it("ignores unparseable config with a notice (target agent cannot be identified)", async () => {
    const canary = await resolveClaudeSandboxNetworkCanary({ agentId: AGENT, env: envFor("{not json"), now: NOW });
    expect(canary.kind).toBe("inactive");
    expect(canary.kind === "inactive" && canary.notice).toContain("not valid JSON");
  });

  it("detects extraArgs that would override the canary", () => {
    expect(findCanaryConflictingArg([])).toBeNull();
    expect(findCanaryConflictingArg(["--verbose"])).toBeNull();
    expect(findCanaryConflictingArg(["--settings", "/tmp/x.json"])).toBe("--settings");
    expect(findCanaryConflictingArg(["--settings={}"])).toBe("--settings");
    expect(findCanaryConflictingArg(["--setting-sources=user,project"])).toBe("--setting-sources");
  });
});
