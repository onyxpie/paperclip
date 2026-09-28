import { execFile, execFileSync } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp, mkdir, readFile, readdir, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { githubBrokerEnvironment, githubLauncherSource } from "./github-launcher.js";
const exec = promisify(execFile);
const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

const U = "https://github.com/onyxpie/paperclip";
const FAKE_TOKEN = `ghs_${"B".repeat(36)}`;
const REAL_GIT = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
const basic = (token: string) => `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}`;
// No proxy or inherited credentials unless a test sets them.
const QUIET = { HTTP_PROXY: "", http_proxy: "", HTTPS_PROXY: "", https_proxy: "", NO_PROXY: "", no_proxy: "",
  GIT_CONFIG_PARAMETERS: "", PAPERCLIP_WORKSPACE_CWD: "", PAPERCLIP_RUN_ID: "" };

async function run(command: string, args: string[], options: { cwd?: string; env: NodeJS.ProcessEnv }) {
  try { return { code: 0, ...(await exec(command, args, options)) }; }
  catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: typeof e.code === "number" ? e.code : 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

/** Launchers in bin/, plus a stub "real git" that records remote commands and delegates the rest. */
async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "paperclip-github-launcher-"));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  const bin = path.join(root, "managed"), realBin = path.join(root, "real"), repo = path.join(root, "repo");
  for (const dir of [bin, realBin, repo]) await mkdir(dir, { recursive: true });
  for (const name of ["git", "gh"]) await writeFile(path.join(bin, name), githubLauncherSource(), { mode: 0o700 });
  await writeFile(path.join(realBin, "git"), `#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const args = process.argv.slice(2);
if (args.some(a => ['clone', 'fetch', 'push', 'ls-remote'].includes(a))) {
  const config = [];
  for (let n = 0; n < Number(process.env.GIT_CONFIG_COUNT || 0); n++) config.push([process.env['GIT_CONFIG_KEY_' + n], process.env['GIT_CONFIG_VALUE_' + n]]);
  process.stdout.write(JSON.stringify({ args, config, envNames: Object.keys(process.env).sort() }));
  process.exit(0);
}
const result = spawnSync(${JSON.stringify(REAL_GIT)}, args, { stdio: 'inherit' });
process.exit(result.status === null ? 1 : result.status);
`, { mode: 0o700 });
  await writeFile(path.join(realBin, "gh"), `#!/usr/bin/env node
process.stdout.write(JSON.stringify({ config: process.env.GH_CONFIG_DIR, envNames: Object.keys(process.env).sort() }));
`, { mode: 0o700 });
  await exec(REAL_GIT, ["init", "-q", repo]);
  await exec(REAL_GIT, ["-C", repo, "config", "user.name", "Repository Author"]);
  await exec(REAL_GIT, ["-C", repo, "config", "user.email", "repository@example.test"]);
  await exec(REAL_GIT, ["-C", repo, "remote", "add", "origin", U]);
  return { root, bin, realBin, repo };
}

type Broker = { url: string; port: number; requests: IncomingMessage[] };
async function broker(reply: (req: IncomingMessage, res: ServerResponse) => void): Promise<Broker> {
  const requests: IncomingMessage[] = [];
  const server = createServer((req, res) => { requests.push(req); reply(req, res); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => new Promise<void>(resolve => server.close(() => resolve())));
  const { port } = server.address() as { port: number };
  return { url: `http://127.0.0.1:${port}`, port, requests };
}
const json = (body: unknown) => (_req: IncomingMessage, res: ServerResponse) => {
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
};
// The broker shape on master: token env, a sh credential helper, and an identity.
const MASTER_SHAPE = { status: "available", env: {
  PAPERCLIP_GIT_TOKEN: FAKE_TOKEN, GH_TOKEN: FAKE_TOKEN, GITHUB_TOKEN: FAKE_TOKEN,
  GIT_AUTHOR_NAME: "Broker Bot", GIT_AUTHOR_EMAIL: "bot@example.test", GIT_COMMITTER_NAME: "Broker Bot", GIT_COMMITTER_EMAIL: "bot@example.test",
  GIT_CONFIG_COUNT: "3", GIT_CONFIG_KEY_0: "credential.helper", GIT_CONFIG_VALUE_0: "",
  GIT_CONFIG_KEY_1: "credential.https://github.com.helper", GIT_CONFIG_VALUE_1: "!f() { echo password=$PAPERCLIP_GIT_TOKEN; }; f",
  GIT_CONFIG_KEY_2: "user.name", GIT_CONFIG_VALUE_2: "Broker Bot",
} };

function launcherEnv(f: { bin: string; realBin: string }, url: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { ...process.env, ...QUIET, ...githubBrokerEnvironment({ GH_TOKEN: "host-must-not-leak" }, { url, token: "private-capability" }),
    PATH: `${f.bin}:${f.realBin}:${process.env.PATH}`, ...extra };
}

describe("managed GitHub launchers", { timeout: 30_000 }, () => {
  it.each(["repository", "command"])("uses explicit %s identity for local commits without managed credentials", async (identitySource) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "paperclip-github-local-identity-"));
    cleanups.push(() => rm(root, { recursive: true, force: true }));
    const bin = path.join(root, "managed");
    await mkdir(bin);
    await exec("git", ["init", root]);
    await writeFile(path.join(bin, "git"), githubLauncherSource(), { mode: 0o700 });
    const env = { ...process.env, ...githubBrokerEnvironment({
      GH_TOKEN: "host-token", GIT_AUTHOR_NAME: "Host", GIT_COMMITTER_NAME: "Host",
    }, { url: "", token: "" }), PATH: `${bin}:${process.env.PATH}` };
    const git = async (...args: string[]) => (await exec(path.join(bin, "git"), args, { cwd: root, env })).stdout.trim();
    // No configured identity must fail, rather than guessing the host user's.
    await expect(git("var", "GIT_AUTHOR_IDENT")).rejects.toThrow();
    await expect(git("var", "GIT_COMMITTER_IDENT")).rejects.toThrow();
    if (identitySource === "repository") {
      await git("config", "user.name", "Local Author");
      await git("config", "user.email", "local@example.test");
    }
    await git(...(identitySource === "command" ? ["-c", "user.name=Local Author", "-c", "user.email=local@example.test"] : []),
      "commit", "--allow-empty", "-m", "Local work");
    expect(await git("log", "-1", "--format=%an <%ae>|%cn <%ce>"))
      .toBe("Local Author <local@example.test>|Local Author <local@example.test>");
  });

  it.each(["broker-offline", "capability-rejected", "redirect"])("keeps real local Git usable when %s", async (failure) => {
    const f = await fixture();
    const b = await broker((_req, res) => {
      if (failure === "redirect") { res.writeHead(302, { location: "http://127.0.0.1:1/elsewhere" }); res.end(); }
      else { res.writeHead(403); res.end(); }
    });
    const url = failure === "broker-offline" ? "http://127.0.0.1:1" : b.url;
    const result = await run(path.join(f.bin, "git"), ["ls-remote", U], { cwd: f.repo, env: launcherEnv(f, url) });
    expect(result.code, result.stderr).toBe(0);
    expect(result.stderr).toContain(failure === "capability-rejected" ? "capability_rejected" : "broker_transport_unavailable");
    expect(result.stderr).not.toMatch(/host-must-not-leak|private-capability/);
    if (failure === "redirect") expect(b.requests).toHaveLength(1); // [S5] the broker redirect is never followed
    const recorded = JSON.parse(result.stdout);
    expect(recorded.config.filter(([k, v]: [string, string]) => /extraheader/i.test(k) && v)).toEqual([]);
    const commit = await run(path.join(f.bin, "git"), ["commit", "--allow-empty", "-m", "Offline work"], { cwd: f.repo, env: launcherEnv(f, url) });
    expect(commit.code, commit.stderr).toBe(0);
  });

  it("explains unavailable access while allowing the command without credentials", async () => {
    const f = await fixture();
    const b = await broker(json({ status: "unavailable", reason: "More than one managed GitHub identity matches this run", env: { PAPERCLIP_GIT_TOKEN: FAKE_TOKEN } }));
    const result = await run(path.join(f.bin, "git"), ["ls-remote", U], { cwd: f.repo, env: launcherEnv(f, b.url) });
    expect(result.code).toBe(0);
    expect(result.stderr).toContain("More than one managed GitHub identity matches this run");
    expect(result.stdout).not.toContain(FAKE_TOKEN);
    expect(result.stderr).not.toMatch(/host-must-not-leak|private-capability/);
  });

  it("[R5-a/V1/V3] forwards the master-shape credential as one exact-URL header and nothing else", async () => {
    const f = await fixture();
    const b = await broker(json(MASTER_SHAPE));
    const env = launcherEnv(f, b.url, { GIT_TRACE_REDACT: "0", GIT_TRACE_CURL: "1", GIT_TRACE_PACKET: "1", FOO_TOKEN: "x" });
    const result = await run(path.join(f.bin, "git"), ["push", "origin", "HEAD"], { cwd: f.repo, env });
    expect(result.code, result.stderr).toBe(0);
    expect(b.requests).toHaveLength(1);
    expect(b.requests[0]!.headers["x-paperclip-github-capability"]).toBe("private-capability");
    const recorded = JSON.parse(result.stdout);
    expect(recorded.args[0]).toBe("--no-pager");
    const config = recorded.config as Array<[string, string]>;
    expect(config[0]).toEqual(["credential.helper", ""]);
    const credentialed = config.filter(([k, v]) => /extraheader/i.test(k) && v);
    expect(credentialed).toEqual([[`http.${U}.extraHeader`, basic(FAKE_TOKEN)]]);
    const resetIndex = config.findIndex(([k, v]) => k === `http.${U}.extraHeader` && v === "");
    expect(config.findIndex(([, v]) => v === basic(FAKE_TOKEN))).toBeGreaterThan(resetIndex);
    expect(config.map(([k]) => k.toLowerCase())).not.toEqual(expect.arrayContaining(["credential.https://github.com.helper", "user.name"]));
    expect(config).toEqual(expect.arrayContaining([["http.followRedirects", "false"], [`http.${U}.followRedirects`, "false"],
      ["core.hooksPath", "/dev/null"], ["core.fsmonitor", "false"], ["push.gpgSign", "false"]]));
    for (const name of ["PAPERCLIP_GIT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "PAPERCLIP_GITHUB_BROKER_TOKEN", "PAPERCLIP_GITHUB_BROKER_URL",
      "PAPERCLIP_API_KEY", "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME", "GIT_CONFIG_PARAMETERS", "FOO_TOKEN",
      "GIT_TRACE_REDACT", "GIT_TRACE_CURL", "GIT_TRACE_PACKET"]) expect(recorded.envNames, name).not.toContain(name); // [S2]
    expect(`${result.stdout}${result.stderr}`.replace(JSON.stringify(basic(FAKE_TOKEN)), "")).not.toContain(FAKE_TOKEN);
    // [R5-b] Local commits make no broker call and keep the repository identity.
    const commit = await run(path.join(f.bin, "git"), ["commit", "--allow-empty", "-m", "Local"], { cwd: f.repo, env });
    expect(commit.code, commit.stderr).toBe(0);
    expect(b.requests).toHaveLength(1);
    expect((await exec(REAL_GIT, ["-C", f.repo, "log", "-1", "--format=%an <%ae>"])).stdout.trim()).toBe("Repository Author <repository@example.test>");
  });

  it("[S1] prefers a valid token over a broker header and refuses a malformed header", async () => {
    const f = await fixture();
    const header = (value: string) => ({ GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader", GIT_CONFIG_VALUE_0: value });
    let body: unknown = { status: "available", env: { PAPERCLIP_GIT_TOKEN: FAKE_TOKEN, ...header(basic("other-token-value-000000")) } };
    const b = await broker((req, res) => json(body)(req, res));
    const env = launcherEnv(f, b.url, { PAPERCLIP_GITHUB_LAUNCHER_DEBUG: "1" });
    const headers = async () => {
      const result = await run(path.join(f.bin, "git"), ["ls-remote", U], { cwd: f.repo, env });
      return { stderr: result.stderr, sent: (JSON.parse(result.stdout).config as Array<[string, string]>).filter(([k, v]) => /extraheader/i.test(k) && v).map(([, v]) => v) };
    };
    let result = await headers();
    expect(result.sent).toEqual([basic(FAKE_TOKEN)]);
    expect(result.stderr).toContain("broker token: valid, header: valid");
    expect(result.stderr).toContain("config:http.https://github.com/.extraheader");
    body = { status: "available", env: header(`${basic("other-token-value-000000")}\r\nX-Injected: 1`) };
    result = await headers();
    expect(result.sent).toEqual([]);
    expect(result.stderr).toContain("credential_invalid");
    expect(result.stderr).toContain("broker token: absent, header: invalid");
    // [S3] diagnostics never carry token material.
    for (const material of [FAKE_TOKEN, "other-token-value-000000", Buffer.from(`x-access-token:${FAKE_TOKEN}`).toString("base64")])
      expect(result.stderr).not.toContain(material);
  });

  it("[B1/V2] refuses before any broker call", async () => {
    const f = await fixture();
    const b = await broker(json(MASTER_SHAPE));
    const env = launcherEnv(f, b.url);
    for (const args of [["clone", "-u", "x", U], ["ls-remote", "--upload-pack=x", U], ["push", "--signed", "origin"], ["ls-remote", "ext::sh -c x"],
      ["-c", "a=b", "fetch"], ["ls-remote", "https://github.com:443/o/r"]]) {
      const result = await run(path.join(f.bin, "git"), args, { cwd: f.repo, env });
      expect(result.code, args.join(" ")).toBe(2);
      expect(result.stderr).toContain("refused before any credential was requested");
    }
    await exec(REAL_GIT, ["-C", f.repo, "config", "core.fsmonitor", "/bin/true"]);
    await exec(REAL_GIT, ["-C", f.repo, "config", "url.https://evil.invalid/.insteadOf", "https://github.com/"]);
    const planted = await run(path.join(f.bin, "git"), ["push", "origin", "HEAD"], { cwd: f.repo, env });
    expect(planted.code).toBe(2);
    expect(planted.stderr).toContain("local_config_not_allowed (core.fsmonitor, url.https://evil.invalid/.insteadof)");
    expect(b.requests).toHaveLength(0);
  });

  it("[C2c] re-adds only the sandbox proxy auth entry for a loopback HTTPS_PROXY", async () => {
    const f = await fixture();
    const b = await broker(json(MASTER_SHAPE));
    const proxy = "http://127.0.0.1:9";
    const result = await run(path.join(f.bin, "git"), ["ls-remote", U], { cwd: f.repo, env: launcherEnv(f, b.url, {
      HTTPS_PROXY: proxy, NO_PROXY: "127.0.0.1",
      GIT_CONFIG_PARAMETERS: "'http.proxyAuthMethod'='basic' 'credential.http://127.0.0.1:9.helper'='!sh -c x' 'credential.https://github.com.helper'='!x'",
    }) });
    const config = JSON.parse(result.stdout).config as Array<[string, string]>;
    expect(config.at(-1)).toEqual(["http.proxyAuthMethod", "basic"]);
    expect(config.filter(([k]) => k.toLowerCase().startsWith("credential."))).toEqual([["credential.helper", ""]]);
    expect(config).toEqual(expect.arrayContaining([["http.proxy", proxy], [`http.${U}.proxy`, proxy]]));
  });

  it("[C2a/R2] sends the broker request through a loopback HTTP_PROXY unless NO_PROXY matches", async () => {
    const f = await fixture();
    const direct = await broker(json(MASTER_SHAPE));
    const viaProxy = await broker(json(MASTER_SHAPE));
    const env = (noProxy: string) => launcherEnv(f, direct.url, { HTTP_PROXY: `http://user:pass@127.0.0.1:${viaProxy.port}`, NO_PROXY: noProxy });
    expect((await run(path.join(f.bin, "git"), ["ls-remote", U], { cwd: f.repo, env: env("") })).code).toBe(0);
    expect(viaProxy.requests).toHaveLength(1);
    expect(viaProxy.requests[0]!.url).toBe(`${direct.url}/runtime-tools/github/credentials`);
    expect(viaProxy.requests[0]!.headers["proxy-authorization"]).toBe(`Basic ${Buffer.from("user:pass").toString("base64")}`);
    expect(direct.requests).toHaveLength(0);
    expect((await run(path.join(f.bin, "git"), ["ls-remote", U], { cwd: f.repo, env: env("localhost,127.0.0.1,::1") })).code).toBe(0);
    expect(direct.requests).toHaveLength(1);
    expect(viaProxy.requests).toHaveLength(1);
  });

  it("[B2] gives gh no credential and a per-run config dir that is removed and swept", async () => {
    const f = await fixture();
    const b = await broker(json(MASTER_SHAPE));
    const runId = "3f1c9a52-0d4e-4c7a-9b1e-2a6d8c0f7e11";
    const stale = path.join(f.repo, ".paperclip-gh", `${runId}-999999`);
    await mkdir(stale, { recursive: true });
    await writeFile(path.join(stale, "owner.pid"), "999999");
    const env = launcherEnv(f, b.url, { PAPERCLIP_WORKSPACE_CWD: f.repo, PAPERCLIP_RUN_ID: runId });
    const result = await run(path.join(f.bin, "gh"), ["api", "user"], { cwd: f.repo, env });
    expect(result.code, result.stderr).toBe(0);
    const recorded = JSON.parse(result.stdout);
    expect(recorded.config).toMatch(new RegExp(`/\\.paperclip-gh/${runId}-\\d+$`));
    for (const name of ["GH_TOKEN", "GITHUB_TOKEN", "PAPERCLIP_GIT_TOKEN", "PAPERCLIP_GITHUB_BROKER_TOKEN", "PAPERCLIP_API_KEY"]) expect(recorded.envNames).not.toContain(name);
    expect(b.requests).toHaveLength(0);
    expect(await readdir(path.join(f.repo, ".paperclip-gh"))).toEqual([]); // own dir removed, stale dir swept
    expect(await readFile(path.join(f.repo, ".git", "info", "exclude"), "utf8")).toMatch(/^\.paperclip-gh\/$/m);
    const unwritable = await run(path.join(f.bin, "gh"), [], { cwd: f.repo, env: launcherEnv(f, b.url, { GH_CONFIG_DIR: path.join(f.root, "missing", "x") }) });
    expect(unwritable.stderr).toContain("configuration_directory_unavailable");
    expect(JSON.parse(unwritable.stdout).config).toMatch(/unavailable-gh-config$/);
  });
});
