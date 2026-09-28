#!/usr/bin/env node
// Fork focused-tests gate (ONY-223 C3). Fails closed unless every named suite
// is in the vitest JSON report, matched by exact repo-relative path, with at
// least one passed test and no skipped/pending/todo/disabled/failed tests.
// skipIf/runIf show up as "skipped" in the JSON reporter.
import fs from 'node:fs';
import path from 'node:path';

const BAD = new Set(['skipped', 'pending', 'todo', 'disabled', 'failed']);

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

const [reportPath, ...required] = process.argv.slice(2);
if (!reportPath) fail('usage: check-focused-suites.mjs <vitest-report.json> <suite>...');
if (required.length === 0) fail('FAIL: empty suite list');

let raw;
try {
  raw = fs.readFileSync(reportPath, 'utf8');
} catch {
  fail(`FAIL: report ${reportPath} missing or unreadable`);
}
if (raw.trim() === '') fail(`FAIL: report ${reportPath} is empty`);
let report;
try {
  report = JSON.parse(raw);
} catch {
  fail(`FAIL: report ${reportPath} is not valid JSON`);
}
if (!report || !Array.isArray(report.testResults)) fail('FAIL: report has no testResults array');

const root = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
const byFile = new Map();
for (const file of report.testResults) {
  if (!file || typeof file.name !== 'string') continue;
  const rel = path.relative(root, path.resolve(root, file.name)).split(path.sep).join('/');
  byFile.set(rel, file);
}

let failed = false;
for (const suite of required) {
  const want = path.posix.normalize(suite);
  const file = byFile.get(want);
  if (!file) {
    console.error(`MISSING ${want}: not in the vitest report`);
    failed = true;
    continue;
  }
  const counts = {};
  for (const t of file.assertionResults ?? []) counts[t.status] = (counts[t.status] ?? 0) + 1;
  const bad = Object.entries(counts).filter(([s]) => BAD.has(s)).reduce((n, [, c]) => n + c, 0);
  const unknown = Object.keys(counts).filter((s) => s !== 'passed' && !BAD.has(s));
  const passed = counts.passed ?? 0;
  if (bad > 0 || unknown.length > 0 || passed === 0 || file.status !== 'passed') {
    console.error(`FAIL ${want}: suite status=${file.status} ${JSON.stringify(counts)}`);
    failed = true;
  } else {
    console.log(`OK ${want}: ${passed} passed, 0 skipped`);
  }
}
process.exit(failed ? 1 : 0);
