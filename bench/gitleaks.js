// The README's comparison: the same fixture through gitleaks (default config)
// and through allowleak. Needs a gitleaks binary:
//   GITLEAKS=/path/to/gitleaks node bench/gitleaks.js [runs]
// Values are generated fresh on each run and written only to a temp folder.

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import { inClaudeRule } from '../src/detect.js';
import { fixture } from '../test/fixture.js';

const GL = process.env.GITLEAKS || 'gitleaks';
const RUNS = Number(process.argv[2] || 10);
const version = execFileSync(GL, ['version'], { encoding: 'utf8' }).trim();
const tally = {};

for (const style of ['random', 'human']) {
  for (let run = 0; run < RUNS; run += 1) {
    const { tok, plain, benign } = fixture(style);
    const rows = [...tok.map(([k, v]) => ['token', k, v]), ...plain.map(([k, v]) => ['plain', k, v]), ...benign.map((v, i) => ['clean', `clean-${i}`, v])];
    const dir = mkdtempSync(join(os.tmpdir(), 'allowleak-bench-'));
    try {
      mkdirSync(join(dir, '.claude'));
      const lines = ['{', '  "permissions": {', '    "allow": [', ...rows.map(([, , v], i) => `      ${JSON.stringify(v)}${i < rows.length - 1 ? ',' : ''}`), '    ]', '  }', '}'];
      writeFileSync(join(dir, '.claude', 'settings.local.json'), lines.join('\n') + '\n');
      const report = join(dir, 'report.json');
      execFileSync(GL, ['dir', dir, '--no-banner', '--redact', '--report-format', 'json', '--report-path', report, '--exit-code', '0'], { stdio: 'pipe' });
      const hit = new Set(JSON.parse(readFileSync(report, 'utf8')).filter((f) => f.File.endsWith('settings.local.json')).map((f) => f.StartLine - 4));
      rows.forEach(([cat, k, v], i) => {
        const t = (tally[`${style}|${cat}|${k}`] ||= { style, cat, k, gitleaks: 0, allowleak: 0, n: 0 });
        t.n += 1;
        if (hit.has(i)) t.gitleaks += 1;
        if (inClaudeRule(v).length) t.allowleak += 1;
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
}

const rows = Object.values(tally);
const pct = (a, b) => `${Math.round((100 * a) / b)}%`;
console.log(`gitleaks ${version}, default config; ${RUNS} runs per password style\n`);
for (const style of ['random', 'human']) {
  const secret = rows.filter((r) => r.style === style && r.cat !== 'clean');
  const clean = rows.filter((r) => r.style === style && r.cat === 'clean');
  const sum = (rs, key) => rs.reduce((n, r) => n + r[key], 0);
  const n = sum(secret, 'n');
  console.log(`${style} passwords: gitleaks ${sum(secret, 'gitleaks')}/${n} (${pct(sum(secret, 'gitleaks'), n)}), allowleak ${sum(secret, 'allowleak')}/${n} (${pct(sum(secret, 'allowleak'), n)}); clean rules flagged: gitleaks ${sum(clean, 'gitleaks')}, allowleak ${sum(clean, 'allowleak')} of ${sum(clean, 'n')}`);
}
console.log('\nrules gitleaks missed in every run (random passwords):');
console.log(rows.filter((r) => r.style === 'random' && r.cat !== 'clean' && r.gitleaks === 0).map((r) => r.k).join(', '));
console.log('\nrules gitleaks caught only sometimes (random passwords):');
console.log(rows.filter((r) => r.style === 'random' && r.cat !== 'clean' && r.gitleaks > 0 && r.gitleaks < r.n).map((r) => `${r.k} ${r.gitleaks}/${r.n}`).join(', ') || '(none)');
