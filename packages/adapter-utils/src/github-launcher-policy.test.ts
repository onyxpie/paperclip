import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { githubLauncherPolicySource, loadGithubLauncherPolicy } from "./github-launcher-policy.js";

const P = loadGithubLauncherPolicy();
const b64 = (s: string) => Buffer.from(s).toString("base64");
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "paperclip-launcher-policy-"));
afterAll(() => fs.rmSync(scratch, { recursive: true, force: true }));
const U = "https://github.com/onyxpie/paperclip";
const PROXY = "http://127.0.0.1:61234";
const FAKE_TOKEN = `ghs_${"A".repeat(36)}`;
const gitEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: scratch, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };

function fixtureRepo(name: string) {
  const dir = path.join(scratch, name);
  fs.rmSync(dir, { recursive: true, force: true });
  execFileSync("git", ["init", "-q", "--bare", dir], { env: gitEnv });
  return dir;
}
const plant = (repo: string, key: string, value: string) => execFileSync("git", ["-C", repo, "config", "--add", key, value], { env: gitEnv });
const gitIn = (repo: string, entries: Array<[string, string]>, args: string[]) =>
  execFileSync("git", ["-C", repo, ...args], { env: { ...gitEnv, ...P.configEnv(entries) }, encoding: "utf8" }).trim();
const gitOutIn = (cwd: string) => (args: string[]) => {
  try { return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; }
};

describe("GitHub launcher policy (ONY-223 C2)", () => {
  it("embeds as plain JavaScript without template placeholders", () => {
    const source = githubLauncherPolicySource();
    expect(source).not.toMatch(/[`]|\$\{/);
  });

  it("[V2] refuses options outside the per-subcommand allowlist", () => {
    const refuse = [
      ["clone", "-u", "x", U], ["ls-remote", "-u", "x", U], ["clone", "--upload-pack=x", U],
      ["push", "--receive-pack=x"], ["push", "--exec=x"], ["push", "--signed"], ["push", "--sign=yes"],
      ["push", "-o", "x"], ["fetch", "--upload-pack=x"], ["fetch", "--upl=x"], ["push", "-qu", "origin"],
      ["fetch", "--unknown"], ["-c", "k=v", "push"], ["--git-dir=/x", "fetch"], ["clone", "--template=/x", U],
      ["clone", "--config", "a=b", U], ["clone", "--recurse-submodules", U], ["push", "--mirror"], ["clone", "-bmain", U],
    ];
    for (const argv of refuse) expect(P.classifyGitArgv(argv).mode, argv.join(" ")).toBe("refuse");
    expect(P.classifyGitArgv(["push", "-u", "origin", "HEAD"]).mode).toBe("credentialed");
    expect(P.classifyGitArgv(["-C", "/w", "push", "--force-with-lease=main:abc", "origin", "HEAD:main"]).mode).toBe("credentialed");
    expect(P.classifyGitArgv(["-C", "/w", "fetch", "--prune", "--", "origin"]).repo).toBe("origin");
  });

  it("[B1] gives no credential to commands that do not talk to the remote", () => {
    for (const argv of [["pull"], ["commit", "-m", "x"], ["rebase", "origin/main"], ["submodule", "update"], ["-c", "a=b", "commit"], ["status"], []])
      expect(P.classifyGitArgv(argv).mode, argv.join(" ")).toBe("uncredentialed");
  });

  it("[V2] accepts only the canonical https://github.com/<owner>/<repo>(.git) form, unchanged", () => {
    const bad = ["ext::sh -c x", "file:///x", "https://github.com.evil.invalid/o/r", "https://x@github.com/o/r",
      "https://github.com:443/o/r", "https://GITHUB.com/o/r", "https://github.com/o/r/", "https://github.com/o/%72",
      "ssh://git@github.com/o/r", "git@github.com:o/r", "https://github.com/o/r?x=1", "https://github.com/o/r#f",
      "https://github.com/../r", "https://github.com/o/.git", "http://github.com/o/r"];
    for (const url of bad) expect(P.canonicalGitHubUrl(url), url).toBeNull();
    for (const url of [U, `${U}.git`]) expect(P.canonicalGitHubUrl(url)).toBe(url);
  });

  it("[C2c/B5] keeps only http.proxyAuthMethod=basic for a loopback proxy", () => {
    const keep = (p: string) => P.keptProxyEntries(p, PROXY);
    expect(keep("'http.proxyAuthMethod'='basic'")).toEqual([["http.proxyAuthMethod", "basic"]]);
    expect(keep("'http.proxyauthmethod=basic' 'credential.http://127.0.0.1:61234.helper'=''")).toEqual([["http.proxyAuthMethod", "basic"]]);
    const none = [
      "'credential.https://github.com.helper'='!x'", "'credential.http://127.0.0.1:61234.helper'='!sh -c x'", "'credential.helper'='x'",
      "'CREDENTIAL.http://127.0.0.1:61234.HELPER'=''", "'http.proxyAuthMethod'='anyauth'", "'http.extraHeader'='a'", "'http.proxy'='x'",
      "'include.path'='x'", "'core.sshCommand'='x'", "'core.hooksPath'='x'", "'url.x.insteadOf'='y'",
      "'http.proxyAuthMethod'='basic", "'http.proxyAuthMethod'\\='basic'", "'http.proxyAuthMethod'", "http.proxyAuthMethod=basic",
      "'http.proxyAuthMethod'='basic' 'http.proxyAuthMethod'='basic'",
    ];
    for (const p of none) expect(keep(p), p).toEqual([]);
    for (const proxy of ["http://127.0.0.2:61234", "http://proxy.example:3128", "https://127.0.0.1:61234", "http://127.0.0.1", "", undefined])
      expect(P.keptProxyEntries("'http.proxyAuthMethod'='basic'", proxy), String(proxy)).toEqual([]);
    expect(P.parseConfigParameters("'a'='it'\\''s'")).toEqual([["a", "it's"]]);
  });

  it("[B1/S4] preflight allows exactly user.name and user.email from the user section", () => {
    const ok = ["core.repositoryformatversion", "core.bare", "remote.origin.url", "remote.origin.fetch", "branch.main.remote", "branch.main.merge", "user.name", "user.email"];
    expect(P.disallowedLocalConfigKeys(ok)).toEqual([]);
    const bad = ["url.https://evil.invalid/.insteadof", "include.path", "includeif.gitdir:/x.path", "http.proxy", "credential.helper",
      "core.sshcommand", "core.fsmonitor", "core.hookspath", "remote.origin.pushurl", "filter.x.clean", "extensions.worktreeconfig",
      "remote.origin.vcs", "core.alternaterefscommand", "branch.main.pushremote", "remote.pushdefault", "alias.p",
      "user.signingkey", "user.useconfigonly", "user.x.email"];
    expect(P.disallowedLocalConfigKeys(bad)).toEqual(bad);
  });

  it("[B1/S4] preflight reads git's lowercased names: USER.EMAIL is allowed, user.signingKey refuses (real git)", () => {
    const repo = fixtureRepo("preflight");
    plant(repo, "USER.EMAIL", "a@example.test");
    plant(repo, "user.signingKey", "x");
    plant(repo, "url.https://evil.invalid/.insteadOf", "https://github.com/");
    plant(repo, "core.fsmonitor", "/bin/true");
    plant(repo, "remote.origin.url", U);
    const plan = P.planCredentialed({ mode: "credentialed", subcommand: "push", dirs: [], repo: "origin" }, gitOutIn(repo));
    expect(plan.refuse).toBe("local_config_not_allowed");
    expect([...plan.names].sort()).toEqual(["core.fsmonitor", "url.https://evil.invalid/.insteadof", "user.signingkey"]);
  });

  it("[V2] resolves remotes to one canonical URL or refuses", () => {
    const repo = fixtureRepo("remotes");
    plant(repo, "remote.origin.url", `${U}.git`);
    plant(repo, "remote.two.url", U);
    plant(repo, "remote.two.url", U);
    plant(repo, "remote.ssh.url", "git@github.com:onyxpie/paperclip");
    const plan = (repoArg: string | null, subcommand = "fetch") => P.planCredentialed({ mode: "credentialed", subcommand, dirs: [], repo: repoArg }, gitOutIn(repo));
    expect(plan("origin")).toEqual({ url: `${U}.git` });
    expect(plan(null)).toEqual({ url: `${U}.git` });
    expect(plan("two").refuse).toBe("remote_url_count");
    expect(plan("ssh").refuse).toBe("remote_url_not_canonical");
    expect(plan("missing").refuse).toBe("remote_url_count");
    expect(plan("https://github.com.evil.invalid/o/r", "ls-remote").refuse).toBe("remote_url_not_canonical");
    const outside = P.planCredentialed({ mode: "credentialed", subcommand: "fetch", dirs: [], repo: "origin" }, () => null);
    expect(outside.refuse).toBe("not_a_repository");
    expect(P.planCredentialed({ mode: "credentialed", subcommand: "clone", dirs: [], repo: U }, () => null)).toEqual({ url: U });
  });

  it("[R5-a/S1/S3] turns the broker token into one header and drops everything else by name", () => {
    const broker = { PAPERCLIP_GIT_TOKEN: FAKE_TOKEN, GH_TOKEN: FAKE_TOKEN, GITHUB_TOKEN: FAKE_TOKEN, GIT_TERMINAL_PROMPT: "0",
      GIT_AUTHOR_NAME: "bot", GIT_CONFIG_COUNT: "3", GIT_CONFIG_KEY_0: "credential.helper", GIT_CONFIG_VALUE_0: "",
      GIT_CONFIG_KEY_1: "credential.https://github.com.helper", GIT_CONFIG_VALUE_1: "!f(){ :; }; f",
      GIT_CONFIG_KEY_2: "user.name", GIT_CONFIG_VALUE_2: "bot" };
    const { header, dropped, verdict } = P.brokerCredentialHeader(broker, b64);
    expect(header).toBe(`Authorization: Basic ${b64(`x-access-token:${FAKE_TOKEN}`)}`);
    expect(verdict).toEqual({ token: "valid", header: "absent" });
    expect(dropped).toEqual(expect.arrayContaining(["env:GH_TOKEN", "env:GITHUB_TOKEN", "env:GIT_AUTHOR_NAME", "config:credential.https://github.com.helper", "config:user.name"]));
    // S3: no token material (literal, base64, or length) in diagnostics.
    const diagnostics = JSON.stringify({ dropped, verdict });
    for (const material of [FAKE_TOKEN, b64(FAKE_TOKEN), b64(`x-access-token:${FAKE_TOKEN}`), String(FAKE_TOKEN.length)])
      expect(diagnostics).not.toContain(material);
    for (const bad of ["short", `${FAKE_TOKEN}\nX: y`, `${FAKE_TOKEN} `, "A".repeat(256)]) {
      const result = P.brokerCredentialHeader({ PAPERCLIP_GIT_TOKEN: bad }, b64);
      expect(result.header).toBeNull();
      expect(result.verdict.token).toBe("invalid");
      expect(JSON.stringify(result)).not.toContain(bad);
    }
  });

  it("[S1] accepts exactly one well-formed extraheader and lets a valid token win over it", () => {
    const entry = (...values: string[]) => Object.fromEntries([["GIT_CONFIG_COUNT", String(values.length)],
      ...values.flatMap((v, n) => [[`GIT_CONFIG_KEY_${n}`, "http.https://github.com/.extraheader"], [`GIT_CONFIG_VALUE_${n}`, v]])]);
    const good = `Authorization: Basic ${b64("x-access-token:abc")}`;
    expect(P.brokerCredentialHeader(entry(good), b64)).toMatchObject({ header: good, verdict: { token: "absent", header: "valid" } });
    expect(P.brokerCredentialHeader(entry(`Authorization: Bearer ${FAKE_TOKEN}`), b64).header).toBe(`Authorization: Bearer ${FAKE_TOKEN}`);
    for (const bad of [`${good}\r\nX-Injected: 1`, `${good}\nX: 1`, "X-Other: 1", `authorization: Basic ${b64("a:b")}`,
      "Authorization: Basic", "Authorization: Bearer short", `Authorization: Basic ${b64("a:b")}===`, `Authorization: Token ${FAKE_TOKEN}`]) {
      const result = P.brokerCredentialHeader(entry(bad), b64);
      expect(result.header, JSON.stringify(bad)).toBeNull();
      expect(result.verdict.header).toBe("invalid");
      expect(result.dropped).toContain("config:http.https://github.com/.extraheader");
    }
    const two = P.brokerCredentialHeader(entry(good, good), b64);
    expect(two.header).toBeNull();
    expect(two.verdict.header).toBe("invalid");
    const both = P.brokerCredentialHeader({ ...entry(good), PAPERCLIP_GIT_TOKEN: FAKE_TOKEN }, b64);
    expect(both.header).toBe(`Authorization: Basic ${b64(`x-access-token:${FAKE_TOKEN}`)}`);
    expect(both.dropped).toContain("config:http.https://github.com/.extraheader");
  });

  it("[R1/V1] builds one list: index-0 reset, header after the exact-URL reset, proxy auth last and once", () => {
    const e = P.buildConfigEntries({ url: U, proxy: PROXY, header: "Authorization: Basic eA==", kept: [["http.proxyAuthMethod", "basic"]] });
    expect(e[0]).toEqual(["credential.helper", ""]);
    const keys = e.map(([k]: [string, string]) => k);
    const reset = keys.findIndex((k: string, n: number) => k === `http.${U}.extraHeader` && e[n][1] === "");
    const header = keys.findIndex((k: string, n: number) => k === `http.${U}.extraHeader` && e[n][1] !== "");
    expect(reset).toBeGreaterThan(0);
    expect(header).toBeGreaterThan(reset);
    expect(keys).not.toContain("http.https://github.com/.extraheader");
    expect(e.at(-1)).toEqual(["http.proxyAuthMethod", "basic"]);
    expect(keys.filter((k: string) => k.toLowerCase() === "http.proxyauthmethod")).toHaveLength(1);
    expect(e).toEqual(expect.arrayContaining([["http.followRedirects", "false"], [`http.${U}.followRedirects`, "false"], ["push.gpgSign", "false"]]));
    const uncredentialed = P.buildConfigEntries({ url: null, kept: [] });
    expect(uncredentialed.map(([k]: [string, string]) => k)).not.toContain("http.extraHeader");
  });

  it.each([U, `${U}.git`])("[V1/S5] command scope beats planted exact-URL and generic keys for %s (real git, no network)", (url) => {
    const repo = fixtureRepo(`v1${url.endsWith(".git") ? "-git" : ""}`);
    plant(repo, "remote.origin.url", url);
    plant(repo, "http.https://github.com/.sslVerify", "false");
    plant(repo, `http.${url}.sslVerify`, "false");
    plant(repo, `http.${url}.proxy`, "http://evil.invalid:1");
    plant(repo, `http.${url}.extraHeader`, "X-Planted: 1");
    plant(repo, `http.${url}.followRedirects`, "true");
    plant(repo, "http.followRedirects", "true");
    const effective = gitIn(repo, [], ["config", "--get", "remote.origin.url"]);
    expect(P.canonicalGitHubUrl(effective)).toBe(effective); // <U> byte-equal to the effective URL
    const entries = P.buildConfigEntries({ url: effective, proxy: PROXY, header: "X-Broker: 1", kept: [["http.proxyAuthMethod", "basic"]] });
    expect(gitIn(repo, entries, ["config", "--type=bool", "--get-urlmatch", "http.sslverify", url])).toBe("true");
    expect(gitIn(repo, entries, ["config", "--get-urlmatch", "http.proxy", url]) === PROXY ? "match" : "mismatch").toBe("match");
    expect(gitIn(repo, entries, ["config", "--get-urlmatch", "http.followredirects", url])).toBe("false");
    const headers = gitIn(repo, entries, ["config", "--get-all", `http.${url}.extraheader`]).split("\n");
    expect(headers.slice(headers.lastIndexOf("") + 1)).toEqual(["X-Broker: 1"]);
    const scopes = gitIn(repo, entries, ["config", "--list", "--show-scope", "--name-only"]).split("\n");
    expect(scopes.filter((line) => line.endsWith("http.proxyauthmethod"))).toEqual(["command\thttp.proxyauthmethod"]);
    expect(gitIn(repo, entries, ["config", "--get", "core.hookspath"])).toBe("/dev/null");
    expect(gitIn(repo, entries, ["config", "--get", "core.fsmonitor"])).toBe("false");
  });

  it("[V3/S2] scrubs secrets and all inherited GIT_* (including GIT_TRACE_REDACT=0) from child envs", () => {
    const input = { PAPERCLIP_API_KEY: "x", PAPERCLIP_GITHUB_BROKER_TOKEN: "x", PAPERCLIP_GITHUB_BROKER_URL: "x", PAPERCLIP_GIT_TOKEN: "x",
      PAPERCLIP_NEW_THING: "x", FOO_TOKEN: "x", BAR_KEY: "x", baz_secret: "x", GH_TOKEN: "x", GIT_CONFIG_PARAMETERS: "x", GIT_SSH_COMMAND: "x",
      GIT_TEMPLATE_DIR: "x", GIT_EXEC_PATH: "x", GIT_DIR: "x", GIT_TRACE_REDACT: "0", GIT_TRACE_CURL: "1", GIT_TRACE_PACKET: "1",
      PAPERCLIP_RUN_ID: "r", PAPERCLIP_WORKSPACE_CWD: "/w", PATH: "/bin", HOME: "/h", HTTPS_PROXY: PROXY };
    const { env, removed } = P.scrubChildEnv(input);
    expect(Object.keys(env).sort()).toEqual(["HOME", "HTTPS_PROXY", "PAPERCLIP_RUN_ID", "PAPERCLIP_WORKSPACE_CWD", "PATH"]);
    expect(removed).toHaveLength(Object.keys(input).length - 5);
  });

  it("[R2] honours NO_PROXY as given", () => {
    const loopbackNoProxy = "localhost,127.0.0.1,::1,10.0.0.0/8,.internal.example";
    for (const host of ["127.0.0.1", "localhost", "[::1]", "10.1.2.3", "a.internal.example"]) expect(P.bypassesProxy(host, loopbackNoProxy), host).toBe(true);
    for (const host of ["127.0.0.2", "11.0.0.1", "example.com"]) expect(P.bypassesProxy(host, loopbackNoProxy), host).toBe(false);
    expect(P.bypassesProxy("127.0.0.1", "")).toBe(false);
    expect(P.bypassesProxy("127.0.0.1", "*")).toBe(true);
    expect(P.bypassesProxy("127.0.0.1", "127.0.0.1:3100")).toBe(true);
  });

  it("[B2] gh config dir is exclusive, marked, symlink-safe, and swept when its owner is gone", () => {
    const ws = path.join(scratch, "ws");
    fs.mkdirSync(ws);
    const dir = P.createGhConfigDir(fs, path, ws, "run-0123456789", 4242);
    expect(fs.readFileSync(path.join(dir, "owner.pid"), "utf8")).toBe("4242");
    expect((fs.statSync(dir).mode & 0o777).toString(8)).toBe("700");
    expect(() => P.createGhConfigDir(fs, path, ws, "run-0123456789", 4242)).toThrow(/EEXIST/);
    expect(() => P.createGhConfigDir(fs, path, ws, "../x", 1)).toThrow(/run_id_invalid/);
    const ws2 = path.join(scratch, "ws2");
    fs.mkdirSync(ws2);
    fs.symlinkSync(ws, path.join(ws2, ".paperclip-gh"));
    expect(() => P.createGhConfigDir(fs, path, ws2, "run-0123456789", 1)).toThrow(/parent_untrusted/);
    expect(P.sweepGhConfigDirs(fs, path, ws, Date.now(), () => false)).toEqual(["run-0123456789-4242"]);
    const alive = P.createGhConfigDir(fs, path, ws, "run-0123456789", 4243);
    expect(P.sweepGhConfigDirs(fs, path, ws, Date.now(), () => true)).toEqual([]);
    expect(fs.existsSync(alive)).toBe(true);
  });
});
