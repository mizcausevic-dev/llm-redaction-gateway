// Disposable local process-switch drill. This does not deploy the API.
const { spawn, spawnSync } = require('node:child_process');
const { mkdirSync, mkdtempSync, realpathSync, rmSync } = require('node:fs');
const { createServer } = require('node:net');
const { once } = require('node:events');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const baselineRef = process.argv[2];
if (!baselineRef || !/^[0-9a-f]{7,40}$/i.test(baselineRef)) {
  console.error('Usage: node scripts/drill-local-rollback.js <prior-commit-sha>');
  process.exit(2);
}

const nodeModules = path.join(root, 'node_modules');
const tsc = path.join(nodeModules, 'typescript', 'bin', 'tsc');
let active;
let drillDir;

function run(file, args, cwd = root) {
  const result = spawnSync(file, args, { cwd, encoding: 'utf8', timeout: 120_000 });
  if (result.error || result.status !== 0) {
    throw new Error(`${file} ${args[0]} failed: ${result.error?.message ?? result.stderr?.trim() ?? result.status}`);
  }
  return result.stdout.trim();
}

async function unusedPort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  server.close();
  await once(server, 'close');
  return port;
}

async function getJson(url, options) {
  let lastError;
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        headers: { Connection: 'close', ...options?.headers },
        signal: AbortSignal.timeout(2_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }
  throw lastError;
}

async function start(directory, port) {
  const child = spawn(process.execPath, [path.join(directory, 'dist', 'index.js')], {
    cwd: directory,
    env: { ...process.env, NODE_ENV: 'development', GATEWAY_LOCAL_DEMO: '1', PORT: String(port), NODE_PATH: nodeModules },
    stdio: 'ignore',
  });
  active = child;
  const health = await getJson(`http://127.0.0.1:${port}/health`);
  if (child.exitCode !== null || health.status !== 'ok' || health.service !== 'llm-redaction-gateway') {
    throw new Error('Local server did not pass health check');
  }
  return health;
}

async function stop() {
  if (!active) return;
  const child = active;
  active = undefined;
  if (child.exitCode === null) {
    const exited = once(child, 'exit');
    child.kill();
    await exited;
  }
}

async function decide(port, prompt) {
  return getJson(`http://127.0.0.1:${port}/api/gateway/process`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
}

function expect(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
}

async function main() {
  if (run('git', ['-c', `safe.directory=${root.replace(/\\/g, '/')}`, 'status', '--porcelain'])) {
    throw new Error('Commit the candidate before the local drill so the tested code matches candidateOid');
  }
  const baselineOid = run('git', ['-c', `safe.directory=${root.replace(/\\/g, '/')}`, 'rev-parse', baselineRef]);
  const candidateOid = run('git', ['-c', `safe.directory=${root.replace(/\\/g, '/')}`, 'rev-parse', 'HEAD']);
  if (baselineOid === candidateOid) throw new Error('Baseline and candidate commits must differ');

  drillDir = mkdtempSync(path.join(root, '.local-release-drill-'));
  const baseline = path.join(drillDir, 'baseline');
  const archive = path.join(drillDir, 'baseline.tar');
  mkdirSync(baseline);
  const tree = run('git', ['-c', `safe.directory=${root.replace(/\\/g, '/')}`, 'ls-tree', '-r', baselineOid]);
  if (tree.split(/\r?\n/).some((entry) => /^(?:120000|160000) /.test(entry))) {
    throw new Error('Baseline contains a link or submodule; refusing archive extraction');
  }
  run('git', ['-c', `safe.directory=${root.replace(/\\/g, '/')}`, 'archive', '--format=tar', '--output', archive, baselineOid]);
  // Verify every archive entry stays inside the disposable baseline before
  // extraction; do not let a repository path escape the drill directory.
  for (const entry of run('tar', ['-tf', archive]).split(/\r?\n/).filter(Boolean)) {
    const relative = path.relative(baseline, path.resolve(baseline, entry));
    if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Unsafe archive path');
  }
  run('tar', ['-xf', archive, '-C', baseline]);
  run(process.execPath, [tsc, '-p', path.join(baseline, 'tsconfig.json')]);
  run(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.json')]);

  const port = await unusedPort();
  const checks = [];
  const challenge = 'user [at] example [dot] com';
  const ticket = 'Ticket 1234-5678-9012-3456';
  const card = 'Card 4532-1234-5678-9014';

  await start(baseline, port);
  const oldDecision = await decide(port, challenge);
  expect(oldDecision.decision, 'allow', 'baseline challenge miss');
  expect(oldDecision.redactedPrompt, challenge, 'baseline unchanged prompt');
  checks.push('baseline healthy; synthetic obfuscated-email challenge missed');
  await stop();

  await start(root, port);
  const newDecision = await decide(port, challenge);
  expect(newDecision.decision, 'redact', 'candidate challenge detection');
  expect(newDecision.redactedPrompt.includes(challenge), false, 'candidate tokenized prompt');
  expect((await decide(port, ticket)).decision, 'allow', 'candidate ticket behavior');
  expect((await decide(port, card)).decision, 'block', 'candidate card behavior');
  checks.push('candidate healthy; synthetic challenge tokenized, invalid ticket allowed, valid card blocked');
  await stop();

  await start(baseline, port);
  const restoredDecision = await decide(port, challenge);
  expect(restoredDecision.decision, 'allow', 'restored baseline challenge miss');
  expect(restoredDecision.redactedPrompt, challenge, 'restored unchanged prompt');
  checks.push('baseline restored on same port; previous detection miss returned');
  console.log(JSON.stringify({ simulationOnly: true, unsafeAsReleaseRollback: true, baselineOid, candidateOid, checks }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
}).finally(async () => {
  await stop();
  if (drillDir) {
    const resolved = realpathSync.native(drillDir);
    const relative = path.relative(root, resolved);
    if (!relative.startsWith('..') && !path.isAbsolute(relative) && relative.startsWith('.local-release-drill-')) {
      rmSync(resolved, { recursive: true, force: true });
    } else {
      console.error('Refusing to clean a drill directory outside the repository');
      process.exitCode = 1;
    }
  }
});
