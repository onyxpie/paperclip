/**
 * Credential policy for the standalone GitHub launcher (ONY-223 C2).
 *
 * The source below is embedded verbatim in githubLauncherSource(), so it must
 * stay plain CommonJS-compatible JavaScript: no imports, no backticks, no
 * template placeholders. Every function is pure except createGhConfigDir and
 * sweepGhConfigDirs, which take fs/path as arguments. Nothing here returns or
 * prints a secret value; diagnostics carry names and verdicts only.
 */
export function githubLauncherPolicySource(): string {
  return String.raw`
const REMOTE_SUBCOMMANDS = new Set(['clone', 'fetch', 'push', 'ls-remote']);

// Per-subcommand option allowlists [V2]. "value" options take the next token
// (or an "=" suffix for long forms). Anything absent refuses, so -u is
// --set-upstream for push but refuses for clone/ls-remote (--upload-pack).
const OPTION_ALLOWLIST = {
  clone: {
    flags: ['--single-branch', '--no-single-branch', '--bare', '--no-checkout', '-n', '--quiet', '-q', '--filter=blob:none', '--filter=tree:0'],
    value: ['--depth', '--branch', '-b', '--origin', '-o'],
  },
  fetch: {
    flags: ['--prune', '-p', '--unshallow', '--tags', '--no-tags', '--quiet', '-q', '--force', '-f', '--dry-run'],
    value: ['--depth', '--deepen'],
  },
  push: {
    flags: ['--set-upstream', '-u', '--delete', '-d', '--dry-run', '-n', '--quiet', '-q', '--porcelain', '--atomic'],
    value: [],
    prefix: [/^--force-with-lease(=[^\s]*)?$/],
  },
  'ls-remote': {
    flags: ['--heads', '--tags', '-t', '--refs', '--quiet', '-q', '--exit-code', '--symref'],
    value: [],
  },
};

// Global options that consume the following token when not written as --x=v.
const GLOBAL_VALUE_OPTIONS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env', '--exec-path', '--super-prefix']);

/**
 * Classify one git argv [B1, V2]:
 *   { mode: 'uncredentialed' }                        no broker call
 *   { mode: 'refuse', reason }                        exit 2, no broker call
 *   { mode: 'credentialed', subcommand, dirs, repo }  repo is the URL or remote
 *                                                     positional, or null
 */
function classifyGitArgv(argv) {
  const dirs = [];
  let otherGlobal = null;
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('-')) break;
    if (a === '-C') { if (i + 1 >= argv.length) return { mode: 'uncredentialed' }; dirs.push(argv[++i]); continue; }
    otherGlobal = otherGlobal || a;
    if (GLOBAL_VALUE_OPTIONS.has(a)) i++;
  }
  const subcommand = argv[i];
  if (!REMOTE_SUBCOMMANDS.has(subcommand)) return { mode: 'uncredentialed' };
  if (otherGlobal) return { mode: 'refuse', reason: 'global_option_not_allowed' };
  const allow = OPTION_ALLOWLIST[subcommand];
  const positionals = [];
  for (let j = i + 1; j < argv.length; j++) {
    const a = argv[j];
    if (a === '--') { positionals.push(...argv.slice(j + 1)); break; }
    if (!a.startsWith('-') || a === '-') { positionals.push(a); continue; }
    if (allow.flags.includes(a)) continue;
    if ((allow.prefix || []).some(re => re.test(a))) continue;
    const eq = a.indexOf('=');
    const name = eq === -1 ? a : a.slice(0, eq);
    if (allow.value.includes(name)) {
      // Short value options only in the separate-token form: -b main, never -bmain.
      if (eq !== -1 && !name.startsWith('--')) return { mode: 'refuse', reason: 'option_not_allowed' };
      if (eq === -1) { if (j + 1 >= argv.length) return { mode: 'refuse', reason: 'option_missing_value' }; j++; }
      continue;
    }
    return { mode: 'refuse', reason: 'option_not_allowed' };
  }
  if (subcommand === 'clone' && (positionals.length < 1 || positionals.length > 2)) return { mode: 'refuse', reason: 'clone_arguments' };
  return { mode: 'credentialed', subcommand, dirs, repo: positionals.length ? positionals[0] : null };
}

/** True when the positional must be treated as a URL rather than a remote name. */
function looksLikeUrl(value) { return /[:/\\]/.test(value); }

/**
 * Canonical GitHub remote [V2]. Returns the input unchanged, so it is
 * byte-equal to git's effective URL (V1, finding 9), or null.
 */
function canonicalGitHubUrl(value) {
  if (typeof value !== 'string') return null;
  const m = /^https:\/\/github\.com\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/.exec(value);
  if (!m) return null;
  const repo = m[2].endsWith('.git') ? m[2].slice(0, -4) : m[2];
  for (const part of [m[1], repo]) if (!part || /^\.+$/.test(part)) return null;
  return value;
}

// Local-config preflight allowlist [B1, S4]. Names as printed by
// git config --name-only --list: section and key lowercased by git, so
// USER.EMAIL arrives as user.email. Every other user.* key refuses.
const LOCAL_CONFIG_ALLOW = [
  /^core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode)$/,
  /^remote\.[^\n]+\.(url|fetch)$/,
  /^branch\.[^\n]+\.(remote|merge)$/,
  /^user\.(name|email)$/,
];
function disallowedLocalConfigKeys(names) {
  return names.filter(n => n && !LOCAL_CONFIG_ALLOW.some(re => re.test(n)));
}

/**
 * Resolve the canonical remote URL for a credentialed command and run the
 * repo-local config preflight [B1, V2]. gitOut(args) runs the real git with no
 * credential and returns trimmed stdout, or null on a non-zero exit.
 */
function planCredentialed(cls, gitOut) {
  const inRepo = gitOut(['rev-parse', '--git-dir']) !== null;
  if (inRepo) {
    const listed = gitOut(['config', '--local', '--name-only', '--list']);
    const names = (listed || '').split('\n').filter(Boolean);
    const bad = disallowedLocalConfigKeys(names);
    if (bad.length) return { refuse: 'local_config_not_allowed', names: bad };
  }
  let target = cls.repo;
  let url;
  if (cls.subcommand === 'clone' || (target !== null && looksLikeUrl(target))) {
    url = canonicalGitHubUrl(target);
  } else {
    if (!inRepo) return { refuse: 'not_a_repository' };
    if (target === null) {
      const branch = gitOut(['symbolic-ref', '--short', '-q', 'HEAD']);
      target = (branch && gitOut(['config', '--get', 'branch.' + branch + '.remote'])) || 'origin';
    }
    if (!/^[A-Za-z0-9._-]+$/.test(target) || /^\.+$/.test(target)) return { refuse: 'remote_name_invalid' };
    const urls = (gitOut(['config', '--get-all', 'remote.' + target + '.url']) || '').split('\n').filter(Boolean);
    if (urls.length !== 1) return { refuse: 'remote_url_count' };
    url = canonicalGitHubUrl(urls[0]);
  }
  if (!url) return { refuse: 'remote_url_not_canonical' };
  return { url };
}

/**
 * Strict parser for GIT_CONFIG_PARAMETERS: space-separated 'key'='value',
 * 'key=value' entries, sq-quoted with '\'' escapes. Any parse error returns
 * null, which keeps nothing [C2c, B5].
 */
function parseConfigParameters(text) {
  if (typeof text !== 'string') return null;
  const out = [];
  let i = 0;
  const readQuoted = () => {
    if (text[i] !== "'") return null;
    i++;
    let s = '';
    for (;;) {
      if (i >= text.length) return null;
      const c = text[i];
      if (c === "'") {
        if (text.startsWith("\\''", i + 1)) { s += "'"; i += 4; continue; }
        i++;
        return s;
      }
      if (c === '\\') return null;
      s += c; i++;
    }
  };
  while (i < text.length) {
    if (text[i] === ' ') { i++; continue; }
    const first = readQuoted();
    if (first === null) return null;
    let key, value;
    if (text[i] === '=') {
      i++;
      const v = readQuoted();
      if (v === null) return null;
      key = first; value = v;
    } else {
      const eq = first.indexOf('=');
      if (eq === -1) return null;
      key = first.slice(0, eq); value = first.slice(eq + 1);
    }
    if (i < text.length && text[i] !== ' ') return null;
    if (!key) return null;
    out.push([key, value]);
  }
  return out;
}

function isLoopbackProxy(proxy) {
  if (typeof proxy !== 'string' || !proxy) return false;
  let u;
  try { u = new URL(proxy); } catch { return false; }
  if (u.protocol !== 'http:' || !u.port) return false;
  return ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

/** C2c keep rule [B5, finding 6]: at most http.proxyAuthMethod=basic, loopback proxy only. */
function keptProxyEntries(configParameters, httpsProxy) {
  const parsed = parseConfigParameters(configParameters || '');
  if (!parsed || !isLoopbackProxy(httpsProxy)) return [];
  const hits = parsed.filter(([k]) => k.toLowerCase() === 'http.proxyauthmethod');
  if (hits.length !== 1 || hits[0][1] !== 'basic') return [];
  return [['http.proxyAuthMethod', 'basic']];
}

/** NO_PROXY is honoured as-is [R2]: a match means the broker request goes direct. */
function bypassesProxy(hostname, noProxy) {
  const host = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  const ipv4 = s => { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s); return m ? m.slice(1).reduce((n, o) => n * 256 + Number(o), 0) : null; };
  for (const raw of String(noProxy || '').split(/[\s,]+/)) {
    let e = raw.trim().toLowerCase();
    if (!e) continue;
    if (e === '*') return true;
    const cidr = /^([0-9.]+)\/(\d{1,2})$/.exec(e);
    if (cidr) {
      const h = ipv4(host), net = ipv4(cidr[1]), bits = Number(cidr[2]);
      if (h !== null && net !== null && bits <= 32) {
        const size = 2 ** (32 - bits);
        if (Math.floor(h / size) === Math.floor(net / size)) return true;
      }
      continue;
    }
    e = e.replace(/^\[|\]$/g, '');
    if ((e.match(/:/g) || []).length === 1) e = e.split(':')[0];
    if (e.startsWith('*.')) e = e.slice(1);
    if (e.startsWith('.')) { if (host.endsWith(e) || host === e.slice(1)) return true; continue; }
    if (host === e || host.endsWith('.' + e)) return true;
  }
  return false;
}

const BROKER_TOKEN_RE = /^[A-Za-z0-9_.-]{20,255}$/;
// S1: exactly one Authorization header, no CR/LF (the character classes admit none).
const BROKER_HEADER_RE = /^Authorization: (Basic [A-Za-z0-9+\/]+={0,2}|Bearer [A-Za-z0-9_.-]{20,255})$/;
const safeName = s => String(s).replace(/[^A-Za-z0-9._:\/-]/g, '?').slice(0, 120);

/**
 * The one credential the launcher forwards from a broker response, as an HTTP
 * Authorization header value [R5-a, S1, S3]. The master broker returns
 * PAPERCLIP_GIT_TOKEN (plus GH_TOKEN/GITHUB_TOKEN and a sh credential helper);
 * a future broker may return one http.https://github.com/.extraheader entry.
 * When both arrive the token wins and the header entry is dropped. Everything
 * else is dropped. dropped/verdict carry names and valid/invalid only.
 */
function brokerCredentialHeader(brokerEnv, base64) {
  const dropped = [];
  const headers = [];
  const count = Number.parseInt(brokerEnv.GIT_CONFIG_COUNT || '0', 10);
  const indexed = new Set();
  for (let n = 0; Number.isInteger(count) && n < count && n < 64; n++) {
    const k = brokerEnv['GIT_CONFIG_KEY_' + n];
    const v = brokerEnv['GIT_CONFIG_VALUE_' + n];
    indexed.add('GIT_CONFIG_KEY_' + n); indexed.add('GIT_CONFIG_VALUE_' + n);
    if (typeof k !== 'string') continue;
    if (k.toLowerCase() === 'http.https://github.com/.extraheader') headers.push(v);
    else dropped.push('config:' + safeName(k));
  }
  const token = brokerEnv.PAPERCLIP_GIT_TOKEN;
  const verdict = {
    token: token === undefined || token === '' ? 'absent' : typeof token === 'string' && BROKER_TOKEN_RE.test(token) ? 'valid' : 'invalid',
    header: headers.length === 0 ? 'absent' : headers.length === 1 && typeof headers[0] === 'string' && BROKER_HEADER_RE.test(headers[0]) ? 'valid' : 'invalid',
  };
  let header = null;
  if (verdict.token === 'valid') {
    header = 'Authorization: Basic ' + base64('x-access-token:' + token);
    if (headers.length) dropped.push('config:http.https://github.com/.extraheader');
  } else if (verdict.header === 'valid') {
    header = headers[0];
  } else if (headers.length) {
    dropped.push('config:http.https://github.com/.extraheader');
  }
  for (const name of Object.keys(brokerEnv)) {
    if (name === 'GIT_CONFIG_COUNT' || indexed.has(name) || name === 'PAPERCLIP_GIT_TOKEN') continue;
    dropped.push('env:' + safeName(name));
  }
  return { header, dropped, verdict };
}

/**
 * The single launcher-built GIT_CONFIG_* list, in the plan's fixed order
 * [R1/B3, V1, finding 10, R5-c/S5]. url is the canonical <U>; header is null
 * when the broker gave no usable credential. Without url the list is the
 * uncredentialed base plus the proxy auth entry.
 */
function buildConfigEntries({ url, proxy, header, kept }) {
  const entries = [
    ['credential.helper', ''],
    ['url.https://github.com/.insteadOf', 'git@github.com:'],
    ['url.https://github.com/.insteadOf', 'ssh://git@github.com/'],
    ['core.askPass', ''],
    ['user.useConfigOnly', 'true'],
  ];
  if (url) {
    const p = isLoopbackProxy(proxy) ? proxy : '';
    entries.push(
      ['core.hooksPath', '/dev/null'], ['core.fsmonitor', 'false'], ['core.sshCommand', 'false'],
      ['http.sslVerify', 'true'], ['http.proxy', p], ['http.extraHeader', ''],
      ['http.' + url + '.sslVerify', 'true'], ['http.' + url + '.proxy', p], ['http.' + url + '.extraHeader', ''],
      ['http.followRedirects', 'false'], ['http.' + url + '.followRedirects', 'false'],
      ['push.gpgSign', 'false'],
      ['protocol.allow', 'never'], ['protocol.https.allow', 'always'],
      ['gc.auto', '0'], ['maintenance.auto', 'false'],
      ['fetch.recurseSubmodules', 'false'], ['submodule.recurse', 'false'],
    );
    if (header) entries.push(['http.' + url + '.extraHeader', header]);
  }
  entries.push(...(kept || []));
  return entries;
}

function configEnv(entries) {
  const env = { GIT_CONFIG_COUNT: String(entries.length) };
  entries.forEach(([k, v], n) => { env['GIT_CONFIG_KEY_' + n] = k; env['GIT_CONFIG_VALUE_' + n] = v; });
  return env;
}

const KEEP_ENV = new Set(['PAPERCLIP_RUN_ID', 'PAPERCLIP_TASK_ID', 'PAPERCLIP_AGENT_ID', 'PAPERCLIP_COMPANY_ID', 'PAPERCLIP_API_URL']);
const SECRET_SUFFIX = /(_TOKEN|_KEY|_SECRET|_PASSWORD|_JWT|_CAPABILITY)$/i;

/**
 * [V3] + GIT_* scrub for every git/gh child. Returns a new env and the removed
 * NAMES only. Removes GIT_TRACE* and GIT_TRACE_REDACT with the rest of GIT_*,
 * so a parent GIT_TRACE_REDACT=0 never reaches git [S2]. The launcher re-adds
 * only its own GIT_* afterwards.
 */
function scrubChildEnv(input) {
  const env = {};
  const removed = [];
  for (const [name, value] of Object.entries(input)) {
    const keep = KEEP_ENV.has(name) || /^PAPERCLIP_WORKSPACE_/.test(name);
    const drop = !keep && (
      /^PAPERCLIP_/.test(name) || SECRET_SUFFIX.test(name) || /^GIT_/.test(name) ||
      /^(GH_|GITHUB_TOKEN$|SSH_ASKPASS$|SSH_AUTH_SOCK$)/.test(name));
    if (drop) removed.push(name); else env[name] = value;
  }
  return { env, removed: removed.sort() };
}

/**
 * [B2] Exclusive per-run gh config dir under <root>/.paperclip-gh/. Holds no
 * credential; checked as an integrity surface. Throws on any failure.
 */
function createGhConfigDir(fs, path, root, runId, pid) {
  if (!/^[A-Za-z0-9-]{8,64}$/.test(runId || '')) throw new Error('run_id_invalid');
  const parent = path.join(root, '.paperclip-gh');
  try { fs.mkdirSync(parent, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const ps = fs.lstatSync(parent);
  if (ps.isSymbolicLink() || !ps.isDirectory() || ps.uid !== process.getuid()) throw new Error('parent_untrusted');
  const dir = path.join(parent, runId + '-' + pid);
  fs.mkdirSync(dir, { mode: 0o700 }); // EEXIST throws: exclusive
  const st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory() || st.uid !== process.getuid()) throw new Error('dir_untrusted');
  const fd = fs.openSync(path.join(dir, 'owner.pid'), 'wx', 0o600);
  fs.writeSync(fd, String(pid)); fs.closeSync(fd);
  const again = fs.lstatSync(dir);
  if (again.dev !== st.dev || again.ino !== st.ino) throw new Error('dir_replaced');
  return dir;
}

/** [B2/R3] Startup sweep: owner gone (ESRCH), or no marker and older than 24 h. EPERM counts as alive. */
function sweepGhConfigDirs(fs, path, root, now, isAlive) {
  const parent = path.join(root, '.paperclip-gh');
  let names;
  try {
    const ps = fs.lstatSync(parent);
    if (ps.isSymbolicLink() || !ps.isDirectory()) return [];
    names = fs.readdirSync(parent);
  } catch { return []; }
  const swept = [];
  for (const name of names) {
    const dir = path.join(parent, name);
    let st;
    try { st = fs.lstatSync(dir); } catch { continue; }
    if (st.isSymbolicLink() || !st.isDirectory() || st.uid !== process.getuid()) continue;
    let pid = null;
    try { pid = Number.parseInt(fs.readFileSync(path.join(dir, 'owner.pid'), 'utf8'), 10); } catch {}
    const dead = Number.isInteger(pid) && pid > 0 ? !isAlive(pid) : now - st.mtimeMs > 24 * 3600 * 1000;
    if (dead) { try { fs.rmSync(dir, { recursive: true, force: true }); swept.push(name); } catch {} }
  }
  return swept;
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
`;
}

/** Test/inspection handle: evaluates the embedded policy in isolation. */
export function loadGithubLauncherPolicy() {
  return new Function(`${githubLauncherPolicySource()}
return { classifyGitArgv, canonicalGitHubUrl, disallowedLocalConfigKeys, planCredentialed, parseConfigParameters,
  keptProxyEntries, bypassesProxy, brokerCredentialHeader, buildConfigEntries, configEnv, scrubChildEnv,
  createGhConfigDir, sweepGhConfigDirs, pidAlive };`)();
}
