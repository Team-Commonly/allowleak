import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { run } from '../src/cli.js';
import { inClaudeRule } from '../src/detect.js';
import { fixture } from './fixture.js';

const git = (cwd, ...args) => execFileSync('git', args, { cwd, stdio: 'pipe' });
const repo = () => {
  const dir = mkdtempSync(join(os.tmpdir(), 'allowleak-'));
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.com');
  git(dir, 'config', 'user.name', 'test');
  git(dir, 'config', 'commit.gpgsign', 'false');
  return dir;
};
const settings = (dir, name, allow) => {
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', name), JSON.stringify({ permissions: { allow } }, null, 2));
};
const cli = (args, opts = {}) => {
  const lines = [];
  const prev = process.cwd();
  if (opts.cwd) process.chdir(opts.cwd);
  try {
    const code = run(args, { out: (s) => lines.push(s), err: (s) => lines.push(s), env: opts.env || process.env });
    return { code, text: lines.join('\n') };
  } finally {
    process.chdir(prev);
  }
};
const PW = 'Falcon' + '0937!';

test('a credential in a file that could be committed fails, and the output never shows it', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { tok, plain } = fixture('human');
  const rules = [...tok, ...plain].map(([, r]) => r);
  settings(dir, 'settings.json', rules);
  const { code, text } = cli([dir]);
  assert.equal(code, 1);
  assert.match(text, /allowleak: \d+ credentials in 1 file/);
  const json = cli([dir, '--json']).text;
  // Independent of the detector: no fixture password, in any form, reaches the output.
  assert.doesNotMatch(text + json, /(Summer|Winter|Falcon)\d{4}/);
  // And none of the values the detector found.
  for (const value of rules.flatMap((r) => inClaudeRule(r).map((f) => f.value))) {
    assert.ok(!text.includes(value) && !json.includes(value), `printed a value starting ${value.slice(0, 3)}`);
  }
});

test('a file git ignores is shown but does not fail, unless --strict', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, '.gitignore'), '.claude/settings.local.json\n');
  settings(dir, 'settings.local.json', [`Bash(mysql -u root -p${PW})`]);
  const plain = cli([dir]);
  assert.equal(plain.code, 0);
  assert.match(plain.text, /ignored by git/);
  assert.equal(cli([dir, '--strict']).code, 1);
});

test('a committed settings.local.json is called out even when it holds no credential', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  settings(dir, 'settings.local.json', ['Bash(npm test)']);
  git(dir, 'add', '.');
  git(dir, 'commit', '-qm', 'add');
  const { code, text } = cli([dir]);
  assert.equal(code, 0);
  assert.match(text, /settings\.local\.json is committed/);
});

test('--staged reads what the commit would contain, not the working copy', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  settings(dir, 'settings.json', [`Bash(docker login -u ci -p ${PW} registry.acme.dev)`]);
  git(dir, 'add', '.');
  settings(dir, 'settings.json', ['Bash(npm test)']); // fixed on disk, not staged
  assert.equal(cli(['--staged'], { cwd: dir }).code, 1);
  git(dir, 'add', '.');
  const after = cli(['--staged'], { cwd: dir });
  assert.equal(after.code, 0);
  assert.match(after.text, /no credentials in 1 file/);
});

test('--history finds a credential that a later commit removed', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, '.codex', 'rules'), { recursive: true });
  writeFileSync(join(dir, '.codex', 'rules', 'default.rules'), `prefix_rule(pattern=["redis-cli", "-a", "${PW}", "PING"], decision="allow")\n`);
  git(dir, 'add', '.');
  git(dir, 'commit', '-qm', 'one');
  writeFileSync(join(dir, '.codex', 'rules', 'default.rules'), 'prefix_rule(pattern=["git", "status"], decision="allow")\n');
  git(dir, 'commit', '-qam', 'two');
  assert.equal(cli([dir]).code, 0);
  const { code, text } = cli(['--history'], { cwd: dir });
  assert.equal(code, 1);
  assert.match(text, /in commit [0-9a-f]{10}/);
  assert.match(text, /redis-cli -a ••••/);
  assert.ok(!text.includes(PW));
});

test('--home reads ~/.claude/settings.json and Codex rules under CODEX_HOME', (t) => {
  const home = mkdtempSync(join(os.tmpdir(), 'allowleak-home-'));
  const codex = mkdtempSync(join(os.tmpdir(), 'allowleak-codex-'));
  t.after(() => { rmSync(home, { recursive: true, force: true }); rmSync(codex, { recursive: true, force: true }); });
  settings(home, 'settings.json', [`Bash(sshpass -p '${PW}' ssh deploy@10.0.0.5:*)`]);
  mkdirSync(join(codex, 'rules'));
  writeFileSync(join(codex, 'rules', 'default.rules'), `prefix_rule(pattern=["zip", "-P", "${PW}", "b.zip"], decision="allow")\n`);
  const { code, text } = cli(['--home'], { env: { HOME: home, CODEX_HOME: codex } });
  assert.equal(code, 1);
  assert.match(text, /~[\\/]\.claude[\\/]settings\.json/);
  assert.match(text, /zip -P ••••/);
});

test('no files, clean files and unknown options', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  assert.match(cli([dir]).text, /found no agent settings/);
  settings(dir, 'settings.json', ['Bash(npm test)']);
  assert.equal(cli([dir]).code, 0);
  assert.equal(cli([dir, '--nope']).code, 2);
});

test('a settings file that is not valid JSON fails closed and says so', (t) => {
  const dir = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, '.claude'));
  writeFileSync(join(dir, '.claude', 'settings.json'), '{ "permissions": ');
  const { code, text } = cli([dir]);
  assert.equal(code, 2);
  assert.match(text, /not valid JSON, so it was not checked/);
});

test('a symlinked .claude folder is read, and so is `allowleak .claude`', (t) => {
  const dir = repo();
  const real = mkdtempSync(join(os.tmpdir(), 'allowleak-real-'));
  t.after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(real, { recursive: true, force: true }); });
  writeFileSync(join(real, 'settings.json'), JSON.stringify({ permissions: { allow: [`Bash(redis-cli -a ${PW} PING)`] } }));
  try { symlinkSync(real, join(dir, '.claude'), 'dir'); } catch { t.skip('no symlinks here'); return; }
  assert.equal(cli([dir]).code, 1);
  assert.equal(cli([join(dir, '.claude')]).code, 1);
});
