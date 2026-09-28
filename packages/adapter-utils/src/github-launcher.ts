import { githubLauncherPolicySource } from "./github-launcher-policy.js";

/**
 * Standalone source is staged unchanged on local, SSH, and sandbox runtimes. No secrets in files.
 *
 * Credential scope (ONY-223 C2): only git clone/fetch/push/ls-remote call the
 * broker, and the credential reaches git only as one Authorization header
 * scoped to the exact canonical remote URL. gh never receives a credential;
 * GitHub API reads go through the connector. Local git commands make no broker
 * call, so commit author fields come from repo or -c config (self-asserted);
 * GitHub push attribution comes from the installation token.
 */
export function githubLauncherSource(): string {
  return String.raw`#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
` + githubLauncherPolicySource() + String.raw`
const directory = path.dirname(fs.realpathSync(process.argv[1]));
const program = path.basename(process.argv[1]);
const originalPath = (process.env.PATH || '').split(path.delimiter).filter(p => {
  try { return fs.realpathSync(p) !== directory; } catch { return true; }
});
const executable = originalPath.map(p => path.join(p, program)).find(p => {
  try { fs.accessSync(p, fs.constants.X_OK); return fs.statSync(p).isFile(); } catch { return false; }
});
if (!['git', 'gh'].includes(program) || !executable) {
  process.stderr.write('Paperclip: requested GitHub command is not installed.\n');
  process.exit(127);
}
const inherited = { ...process.env };
const debug = inherited.PAPERCLIP_GITHUB_LAUNCHER_DEBUG === '1';
// Diagnostics carry codes, key names and valid/invalid verdicts only [S3].
const note = (message) => process.stderr.write('Paperclip: GitHub ' + message + '\n');
const diagnostic = (code) => note(code + '; continuing without managed credentials.');
const base64 = (text) => Buffer.from(text, 'utf8').toString('base64');

function childEnv(ghConfigDirectory) {
  const { env, removed } = scrubChildEnv(inherited);
  if (debug && removed.length) note('removed env names: ' + removed.join(','));
  Object.assign(env, {
    GH_CONFIG_DIR: ghConfigDirectory, SSH_AUTH_SOCK: '',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_SSH_COMMAND: 'ssh -F /dev/null -o IdentityAgent=none -o IdentitiesOnly=yes -o IdentityFile=none -o BatchMode=yes',
  });
  // Children use the real binaries. Nested shells must not reload the parent
  // launcher profile.
  env.PATH = originalPath.join(path.delimiter);
  env.ZDOTDIR = ghConfigDirectory;
  env.BASH_ENV = '/dev/null';
  return env;
}

function excludeFromGit(root) {
  try {
    if (!fs.lstatSync(path.join(root, '.git')).isDirectory()) return;
    const info = path.join(root, '.git', 'info');
    const file = path.join(info, 'exclude');
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch {}
    if (text.split('\n').includes('.paperclip-gh/')) return;
    fs.mkdirSync(info, { recursive: true });
    fs.appendFileSync(file, (text && !text.endsWith('\n') ? '\n' : '') + '.paperclip-gh/\n');
  } catch {}
}

// [B2] gh gets a per-run, per-process config dir that never holds a credential.
function prepareGhConfigDir() {
  const runId = /^[A-Za-z0-9-]{8,64}$/.test(inherited.PAPERCLIP_RUN_ID || '') ? inherited.PAPERCLIP_RUN_ID : 'run-' + randomUUID();
  for (const root of [inherited.PAPERCLIP_WORKSPACE_CWD, inherited.GH_CONFIG_DIR].filter(Boolean)) {
    try {
      sweepGhConfigDirs(fs, path, root, Date.now(), pidAlive);
      const dir = createGhConfigDir(fs, path, root, runId, process.pid);
      process.once('exit', () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
      excludeFromGit(root);
      return dir;
    } catch {}
  }
  note('configuration_directory_unavailable; gh runs without a config directory.');
  return null;
}

// [C2a, R2] One request, no redirects. An http broker goes through a loopback
// HTTP_PROXY unless NO_PROXY matches it; NO_PROXY is never edited here.
function brokerPost(url, headers) {
  const target = new URL(url);
  const proxy = target.protocol === 'http:' ? (inherited.HTTP_PROXY || inherited.http_proxy || '') : '';
  const viaProxy = isLoopbackProxy(proxy) && !bypassesProxy(target.hostname, inherited.NO_PROXY || inherited.no_proxy || '');
  if (!viaProxy) {
    return fetch(url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000), headers, body: '{}' })
      .then(async (response) => ({ status: response.status, body: await response.text() }));
  }
  const p = new URL(proxy);
  const proxyAuth = p.username
    ? { 'proxy-authorization': 'Basic ' + base64(decodeURIComponent(p.username) + ':' + decodeURIComponent(p.password)) }
    : {};
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: p.hostname.replace(/^\[|\]$/g, ''), port: Number(p.port), method: 'POST', path: target.href, timeout: 10000,
      headers: { ...headers, host: target.host, 'content-length': '2', ...proxyAuth },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
    request.end('{}');
  });
}

async function requestCredentialHeader() {
  const base = inherited.PAPERCLIP_GITHUB_BROKER_URL || inherited.PAPERCLIP_API_URL;
  const capability = inherited.PAPERCLIP_GITHUB_BROKER_TOKEN;
  if (!base || !capability) { diagnostic('capability_missing'); return null; }
  const url = base.replace(/\/+$/, '').replace(/\/api$/, '') + '/runtime-tools/github/credentials';
  const headers = {
    authorization: 'Bearer ' + (inherited.PAPERCLIP_GITHUB_BRIDGE_TOKEN || inherited.PAPERCLIP_API_KEY || capability),
    'x-paperclip-github-capability': capability, 'content-type': 'application/json',
  };
  let response;
  try {
    for (let attempt = 0; attempt < 30; attempt++) {
      response = await brokerPost(url, headers);
      if (response.status !== 409) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  } catch { diagnostic('broker_transport_unavailable'); return null; }
  if (response.status < 200 || response.status > 299) {
    diagnostic(response.status === 401 || response.status === 403 ? 'capability_rejected' : 'broker_response_unavailable');
    return null;
  }
  let result;
  try { result = JSON.parse(response.body); } catch { diagnostic('broker_response_unavailable'); return null; }
  if (result.status === 'unavailable') {
    const reason = typeof result.reason === 'string'
      ? result.reason.replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 500)
      : 'Check the GitHub connection in Paperclip';
    process.stderr.write('Paperclip: GitHub access unavailable: ' + reason + '. Continuing without GitHub credentials.\n');
    return null;
  }
  if (result.status !== 'available') return null;
  const brokerEnv = {};
  for (const [key, value] of Object.entries(result.env || {})) if (typeof value === 'string') brokerEnv[key] = value;
  const { header, dropped, verdict } = brokerCredentialHeader(brokerEnv, base64);
  if (debug) note('broker token: ' + verdict.token + ', header: ' + verdict.header + (dropped.length ? '; dropped: ' + dropped.join(',') : ''));
  if (!header) diagnostic('credential_invalid');
  return header;
}

async function main() {
  const httpsProxy = inherited.HTTPS_PROXY || inherited.https_proxy || '';
  const kept = keptProxyEntries(inherited.GIT_CONFIG_PARAMETERS, httpsProxy);
  const ghConfigDirectory = (program === 'gh' && prepareGhConfigDir()) || path.join(directory, 'unavailable-gh-config');
  const env = childEnv(ghConfigDirectory);
  let args = process.argv.slice(2);
  let entries = buildConfigEntries({ url: null, kept });
  if (program === 'git') {
    const refused = (reason) => {
      note('git ' + reason + '; refused before any credential was requested.');
      process.exitCode = 2;
    };
    const classified = classifyGitArgv(args);
    if (classified.mode === 'refuse') return refused(classified.reason);
    if (classified.mode === 'credentialed') {
      let cwd = process.cwd();
      for (const dir of classified.dirs) cwd = path.resolve(cwd, dir);
      const probeEnv = { ...env, ...configEnv([...entries, ['core.fsmonitor', 'false'], ['core.hooksPath', '/dev/null']]) };
      const gitOut = (gitArgs) => {
        const result = spawnSync(executable, gitArgs, { cwd, env: probeEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
        return result.status === 0 ? result.stdout.trim() : null;
      };
      const plan = planCredentialed(classified, gitOut);
      if (plan.refuse) return refused(plan.refuse + (plan.names ? ' (' + plan.names.map(safeName).join(', ') + ')' : ''));
      const header = await requestCredentialHeader();
      entries = buildConfigEntries({ url: plan.url, proxy: httpsProxy, header, kept });
      args = ['--no-pager', ...args];
    }
  }
  Object.assign(env, configEnv(entries));
  const child = spawn(executable, args, { env, stdio: 'inherit' });
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => child.kill(signal));
  child.once('error', () => { process.stderr.write('Paperclip: GitHub command could not start.\n'); process.exitCode = 1; });
  child.once('exit', (code) => { process.exitCode = code === null ? 128 : code; });
}
main().catch(() => { process.stderr.write('Paperclip: GitHub launcher_setup_failed.\n'); process.exitCode = 1; });
`;
}

/** Override inherited credentials even when adapters merge the host environment later. */
export function githubBrokerEnvironment(input: Record<string, unknown>, broker: { url: string; token: string }): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) if (typeof value === "string") env[key] = value;
  for (const key of ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "PAPERCLIP_GIT_TOKEN", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_CONFIG_COUNT", "PAPERCLIP_GITHUB_OPERATION_ACTIVE"]) env[key] = "";
  for (const key of Object.keys(env)) {
    if (/^GIT_CONFIG_(KEY|VALUE)_\d+$/.test(key)) env[key] = "";
  }
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_SYSTEM = "/dev/null";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_ASKPASS = "";
  env.SSH_ASKPASS = "";
  env.GIT_SSH_COMMAND = "ssh -F /dev/null -o IdentityAgent=none -o IdentitiesOnly=yes -o IdentityFile=none -o BatchMode=yes";
  env.SSH_AUTH_SOCK = "";
  env.PAPERCLIP_GITHUB_BROKER_URL = broker.url;
  env.PAPERCLIP_GITHUB_BROKER_TOKEN = broker.token;
  return env;
}
