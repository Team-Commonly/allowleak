import { readFileSync } from 'node:fs';
import { history, home, staged, walk } from './files.js';
import { scanText } from './parse.js';

const HELP = `allowleak: find passwords and tokens in the permission rules your coding agents saved.

  allowleak [folder]   check every .claude/settings*.json and .codex/rules/*.rules under a folder (default: here)
  allowleak --staged   check what the next commit would add (use it as a pre-commit hook)
  allowleak --history  check every version those files ever had in this repo's git history
  allowleak --home     check your own ~/.claude/settings.json and Codex's ~/.codex/rules

  --json      print JSON instead
  --strict    also fail on files git ignores
  --help, --version

Exits 1 when it finds a credential in a file that is or could be committed, 0 when it finds none.
It reads files only. It makes no network calls and never prints a credential.`;

const STATUS = {
  tracked: 'committed',
  untracked: 'not committed yet, and not ignored by git',
  ignored: 'ignored by git, so it stays on this machine',
  staged: 'staged for the next commit',
  'no-git': 'not in a git repository',
  home: 'your own file',
};

export function run(argv, { out = (s) => process.stdout.write(s + '\n'), err = (s) => process.stderr.write(s + '\n'), env = process.env } = {}) {
  const flags = new Set(argv.filter((a) => a.startsWith('--')));
  const rest = argv.filter((a) => !a.startsWith('--'));
  const known = new Set(['--staged', '--history', '--home', '--json', '--strict', '--help', '--version']);
  const unknown = [...flags].filter((f) => !known.has(f));
  if (flags.has('--help')) { out(HELP); return 0; }
  if (flags.has('--version')) {
    out(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
    return 0;
  }
  if (unknown.length) { err(`allowleak: unknown option ${unknown[0]}\n\n${HELP}`); return 2; }
  const dir = rest[0] || '.';

  let source;
  if (flags.has('--staged')) source = staged(dir);
  else if (flags.has('--history')) source = history(dir);
  else if (flags.has('--home')) source = home(env);
  else source = { files: walk(dir) };
  if (source.error) { err(`allowleak: ${source.error}`); return 2; }

  const results = [];
  const seen = new Set();
  for (const file of source.files) {
    const text = file.read();
    if (text === null || text === undefined) continue;
    const { items, error } = scanText(file.path, text);
    const findings = [];
    for (const item of items) {
      for (const f of item.findings) {
        // In --history the same credential shows up in every later version; report the first.
        const key = flags.has('--history') ? `${file.path}\0${f.value}` : null;
        if (key && seen.has(key)) continue;
        if (key) seen.add(key);
        findings.push({ line: item.line, label: f.label, where: f.where });
      }
    }
    const localTracked = /(^|[\\/])\.claude[\\/]settings\.local\.json$/.test(file.path) && file.status === 'tracked';
    if (findings.length || error || localTracked) results.push({ path: file.path, status: file.status, commit: file.commit, error, localTracked, findings });
  }

  const counts = (r) => r.status !== 'ignored' || flags.has('--strict');
  const failing = results.filter((r) => r.findings.length && counts(r));
  const broken = results.filter((r) => r.error);
  const total = results.reduce((n, r) => n + r.findings.length, 0);

  if (flags.has('--json')) {
    out(JSON.stringify({ checked: source.files.length, credentials: total, files: results }, null, 2));
    return broken.length ? 2 : failing.length ? 1 : 0;
  }
  for (const r of broken) err(`allowleak: ${r.path} is ${r.error}, so it was not checked.`);
  if (!source.files.length) {
    out(flags.has('--staged') ? 'allowleak: no agent settings or rules files are staged.' : 'allowleak: found no agent settings or rules files.');
    return 0;
  }
  if (!total) {
    const read = source.files.length - broken.length;
    if (read) out(`allowleak: no credentials in ${read} file${read === 1 ? '' : 's'}.`);
    for (const r of results.filter((x) => x.localTracked)) out(`note: ${r.path} is committed. Claude Code keeps this file for one machine and adds it to .gitignore when it creates it.`);
    return broken.length ? 2 : 0;
  }
  out(`allowleak: ${total} credential${total === 1 ? '' : 's'} in ${results.filter((r) => r.findings.length).length} file${results.length === 1 ? '' : 's'}.\n`);
  for (const r of results.filter((x) => x.findings.length)) {
    const where = r.commit ? `in commit ${r.commit}` : STATUS[r.status] || r.status;
    out(`${r.path}  (${where})`);
    const width = Math.max(...r.findings.map((f) => String(f.line).length));
    for (const f of r.findings) out(`  line ${String(f.line).padEnd(width)}  ${f.where === f.label ? f.where : `${f.where.padEnd(34)}  ${f.label}`}`.trimEnd());
    if (r.localTracked) out('  This file is meant to stay on one machine. Claude Code adds it to .gitignore when it creates it.');
    out('');
  }
  if (flags.has('--history')) out('These are in git history. Deleting the rule now does not remove them; change each credential.');
  else if (failing.length) out('Delete those rules, then change each credential. If one was ever committed, it is in your git history: run allowleak --history.');
  else out('Every file above is ignored by git, so none of this is headed for a commit. Pass --strict to fail on it anyway.');
  return failing.length ? 1 : broken.length ? 2 : 0;
}
