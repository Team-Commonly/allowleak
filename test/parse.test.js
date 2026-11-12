import assert from 'node:assert/strict';
import test from 'node:test';
import { claudeSettings, codexRules, stripJsonc } from '../src/parse.js';

const PW = 'Winter' + '8812!';

test('Claude Code settings: comments, trailing commas, and the line each rule is on', () => {
  const text = [
    '{',
    '  // saved by "Don\'t ask again"',
    '  "permissions": {',
    '    "allow": [',
    '      "Bash(npm run test:*)",',
    `      "Bash(mysql -u root -p${PW} -e \\"SHOW DATABASES\\")",`,
    '      /* block',
    '         comment */',
    `      "Bash(PGPASSWORD=${PW} psql -h db:*)",`,
    '    ],',
    '  },',
    '}',
  ].join('\n');
  const { items, error } = claudeSettings(text);
  assert.equal(error, undefined);
  assert.deepEqual(items.map((i) => [i.line, i.findings.map((f) => f.where)]), [[6, ['mysql -p••••']], [9, ['PGPASSWORD=••••']]]);
});

test('Claude Code settings: the env block and helper commands in the same file', () => {
  const text = JSON.stringify({
    env: { DATABASE_PASSWORD: PW, NODE_ENV: 'production', OPENAI_BASE_URL: 'https://api.openai.com/v1' },
    apiKeyHelper: `echo ${'sk-' + 'ant-api03-' + 'k'.repeat(10) + 'Q7x2Lm9Pq4Rs8Tv1Wy5Za3Bc6De0'}`,
    hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `curl -u bot:${PW} https://hooks.acme.dev` }] }] },
  }, null, 2);
  const { items } = claudeSettings(text);
  assert.deepEqual(items.flatMap((i) => i.findings.map((f) => f.label)), ['secret in DATABASE_PASSWORD', 'Anthropic API key', 'password in curl -u']);
});

test('a duplicate rule gets its own line, not the first copy\'s', () => {
  const rule = `Bash(redis-cli -a ${PW} PING)`;
  const text = `{\n"permissions": {\n"allow": [\n${JSON.stringify(rule)}\n],\n"ask": [\n${JSON.stringify(rule)}\n]}}`;
  assert.deepEqual(claudeSettings(text).items.map((i) => i.line), [4, 7]);
});

test('a file that is not JSON is reported, not thrown', () => {
  assert.equal(claudeSettings('{ "permissions": ').error, 'not valid JSON');
  assert.equal(stripJsonc('{"a": "//not a comment",}'), '{"a": "//not a comment"}');
});

test('Codex rules: what "always allow" appends, one per line, and hand-written ones across lines', () => {
  const text = [
    'prefix_rule(pattern=["git", "status"], decision="allow")',
    `prefix_rule(pattern=["mysql", "-u", "root", "-p${PW}"], decision="allow")`,
    '# hand-written',
    'prefix_rule(',
    `    pattern = ['sshpass', '-p', '${PW}', 'ssh'],`,
    '    decision = "allow",',
    ')',
  ].join('\n');
  assert.deepEqual(codexRules(text).items.map((i) => [i.line, i.findings.map((f) => f.where)]), [[2, ['mysql -p••••']], [4, ['sshpass -p ••••']]]);
});
