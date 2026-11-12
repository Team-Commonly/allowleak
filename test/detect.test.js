import assert from 'node:assert/strict';
import test from 'node:test';
import { inClaudeRule, inCodexPattern, isSecretName } from '../src/detect.js';
import { fixture, MADE, NEAR_MISSES } from './fixture.js';

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
  assert.deepEqual(where('Bash(psql "postgresql://app:' + 'Summer' + '1234!@db.acme.dev:5432/app":*)'), ['postgresql://…:••••@…']);
  assert.deepEqual(where('Bash(curl -u admin:' + 'Summer' + '1234! https://x.acme.dev)'), ['curl -u …:••••']);
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

// No output may hold any 8-character piece of any value the fixture generated for the rule,
// whichever finding it belongs to (the review's L3: each finding used to be checked only
// against its own value).
const windows = (v, n = 8) => Array.from({ length: Math.max(0, v.length - n + 1) }, (_, i) => v.slice(i, i + n));
test('no part of any generated value reaches a location or a label', () => {
  for (let i = 0; i < RUNS; i += 1) {
    const { tok, plain } = fixture('random');
    const pieces = MADE.filter((v) => v.length >= 8).flatMap((v) => windows(v));
    for (const [k, rule] of [...tok, ...plain]) {
      const shown = inClaudeRule(rule).map((f) => `${f.where} ${f.label}`).join('\n');
      const hit = pieces.find((p) => shown.includes(p));
      assert.equal(hit, undefined, `${k} printed part of a value`);
    }
  }
});

const T = 'gh' + 'p_' + 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A';
const TOGGL = '1971800d4d82861d8f2c1651fea4d212';
const PW = 'p@ss/' + 'w0rd!' + 'Zq81';
const shownFor = (rule) => inClaudeRule(rule).map((f) => `${f.where} ${f.label}`).join('\n');

test('a token in the user slot is found and never printed (the review\'s L1)', () => {
  for (const rule of [`Bash(git clone https://${T}:x-oauth-basic@github.com/acme/app.git)`, `Bash(curl -u ${T}:x-oauth-basic https://api.github.com/user)`, `Bash(curl -u ${TOGGL}:api_token https://api.track.toggl.com/api/v9/me)`]) {
    const found = inClaudeRule(rule);
    assert.ok(found.length, rule);
    const shown = shownFor(rule);
    for (const secret of [T, TOGGL]) for (const p of windows(secret)) assert.ok(!shown.includes(p), `${rule}: printed part of a token`);
  }
  assert.ok(inClaudeRule(`Bash(curl -u ${TOGGL}:api_token https://api.track.toggl.com/api/v9/me)`).some((f) => f.value === TOGGL));
});

test('a URL password holding @ or / is found whole and never printed (the review\'s L2)', () => {
  const rule = `Bash(psql "postgresql://app:${PW}@db.acme.dev/app")`;
  const found = inClaudeRule(rule);
  assert.ok(found.some((f) => f.value === PW), JSON.stringify(found.map((f) => f.where)));
  const shown = shownFor(rule);
  for (const piece of ['ss/w0rd', 'w0rd!Zq', 'Zq81']) assert.ok(!shown.includes(piece), piece);
});

test('credentials the review found missing', () => {
  const pw = 'Falcon' + '7712!';
  for (const rule of [
    `Bash(kubectl create secret generic db --from-literal=password=${pw})`,
    `Bash(docker run --env=DB_PASSWORD=${pw} app)`,
    `Bash(psql "host=db.acme.dev user=app password=${pw} dbname=app")`,
    `Bash(curl -uadmin:${pw} https://x.acme.dev)`,
    `Bash(curl --user=admin:${pw} https://x.acme.dev)`,
    `Bash(gpg --batch --passphrase ${pw} -d secrets.gpg)`,
    `Bash(aws configure set aws_secret_access_key ${pw})`,
    `Bash(npm config set //registry.npmjs.org/:_authToken ${pw})`,
    `Bash(htpasswd -b -c .htpasswd admin ${pw})`,
  ]) assert.ok(inClaudeRule(rule).some((f) => f.value === pw), rule);
});

test('everyday rules the review found flagged, now quiet', () => {
  for (const rule of [
    'Bash(docker build --secret id=npmrc,src=$HOME/.npmrc -t app .)',
    'Bash(gcloud secrets versions access latest --secret=db-password)',
    'Bash(ssh-add --private-key=id_ed25519)',
    'Bash(NO_AUTH=1 npm start)', 'Bash(SKIP_AUTH=1 npm test)', 'Bash(DISABLE_AUTH=1 npm run dev)', 'Bash(ENABLE_TOKEN_REFRESH=0 npm start)',
    'Bash(docker compose run -p 3000:3000 web npm run login)',
  ]) assert.deepEqual(inClaudeRule(rule).map((f) => f.where), [], rule);
});
