import assert from 'node:assert/strict';
import test from 'node:test';
import { inClaudeRule, inCodexPattern, isSecretName } from '../src/detect.js';
import { fixture, NEAR_MISSES } from './fixture.js';

const RUNS = 25; // values are random, so run the fixture many times

test('every credential-bearing rule in the fixture is found, with human and random passwords', () => {
  for (const style of ['random', 'human']) {
    for (let i = 0; i < RUNS; i += 1) {
      const { tok, plain } = fixture(style);
      const missed = [...tok, ...plain].filter(([, rule]) => !inClaudeRule(rule).length).map(([k]) => k);
      assert.deepEqual(missed, [], `${style} passwords, run ${i}`);
    }
  }
});

test('the fixture\'s clean rules and the near misses stay quiet', () => {
  const { benign } = fixture();
  const loud = [...benign, ...NEAR_MISSES].map((rule) => [rule, inClaudeRule(rule).map((f) => f.where)]).filter(([, w]) => w.length);
  assert.deepEqual(loud, []);
});

test('where a credential sits is shown without its value', () => {
  for (let i = 0; i < RUNS; i += 1) {
    const { tok, plain } = fixture();
    for (const [k, rule] of [...tok, ...plain]) {
      for (const f of inClaudeRule(rule)) {
        assert.ok(!f.where.includes(f.value) && !f.label.includes(f.value), `${k}: ${f.where}`);
        assert.ok(f.value.length < 6 || !f.where.includes(f.value.slice(1)), `${k}: part of the value shows`);
      }
    }
  }
});

test('the places are named the way a person would look for them', () => {
  const where = (rule) => inClaudeRule(rule).map((f) => f.where);
  assert.deepEqual(where('Bash(mysql -u root -p' + 'Falcon' + '2291! -e "SHOW DATABASES")'), ['mysql -p••••']);
  assert.deepEqual(where('Bash(PGPASSWORD=' + 'Winter' + '7731! psql -h db:*)'), ['PGPASSWORD=••••']);
  assert.deepEqual(where('Bash(psql "postgresql://app:' + 'Summer' + '1234!@db.acme.dev:5432/app":*)'), ['postgresql://app:••••@db.acme.dev:5432']);
  assert.deepEqual(where('Bash(curl -u admin:' + 'Summer' + '1234! https://x.acme.dev)'), ['curl -u admin:••••']);
  assert.deepEqual(where('Bash(curl -H "Authorization: Basic ' + 'YWRtaW46' + 'c2VjcmV0MTIz" https://x.acme.dev)'), ['Authorization: Basic ••••']);
});

test('a key in a known format is found whatever follows it: an escaped quote, :*, ) or &', () => {
  const key = 'sk_' + 'live_' + 'aB3dE5fG7hJ9kL1mN3pQ5rS7';
  for (const rule of [`Bash(curl "https://api.stripe.com?k=${key}")`, `Bash(STRIPE=${key}:*)`, `Bash(stripe login --api-key ${key})`, `Bash(curl -u ${key}: https://api.stripe.com)`]) {
    assert.ok(inClaudeRule(rule).some((f) => f.label === 'Stripe key'), rule);
  }
});

test('Codex prefix rules are read word by word', () => {
  const pw = 'Falcon' + '4410!';
  assert.deepEqual(inCodexPattern(['mysql', '-u', 'root', `-p${pw}`]).map((f) => f.where), ['mysql -p••••']);
  assert.deepEqual(inCodexPattern(['sshpass', '-p', pw, 'ssh', 'deploy@10.0.0.5']).map((f) => f.where), ['sshpass -p ••••']);
  assert.deepEqual(inCodexPattern(['curl', '-H', 'Authorization: Bearer ' + 'x9Kd02LmQp7RtYv3Wz8Na1Bc', 'https://api.acme.dev']).map((f) => f.where), ['Authorization: Bearer ••••']);
  assert.deepEqual(inCodexPattern(['git', ['status', 'log']]), []);
});

test('secret names: the words people use, and the lookalikes that are not', () => {
  for (const n of ['PGPASSWORD', 'MYSQL_PWD', 'OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GH_TOKEN', 'dbPassword', 'client_secret', 'NODE_AUTH_TOKEN', 'REDIS_PASS']) assert.ok(isSecretName(n), n);
  for (const n of ['BYPASS_CACHE', 'COMPASS_DIR', 'PASSWORD_FILE', 'TOKEN_URL', 'AUTH_MODE', 'SORT_KEY', 'SSH_KEY_PATH', 'NODE_ENV', 'TOKENIZERS_PARALLELISM', 'KEY']) assert.ok(!isSecretName(n), n);
});
