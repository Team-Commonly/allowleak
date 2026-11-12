// Which files to read, and what git thinks of each.

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import os from 'node:os';
import { isAbsolute, join, relative } from 'node:path';

export const WANTED = (rel) => /(^|\/)\.claude\/settings(\.local)?\.json$/.test(rel) || /(^|\/)\.codex\/rules\/[^/]+\.rules$/.test(rel);
const SKIP = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'target', 'dist', 'build', '.next', '.cache', 'vendor', '.turbo', '.gradle']);
const MAX_FILE = 4 * 1024 * 1024;

const git = (cwd, args, input) => {
  try {
    return execFileSync('git', args, { cwd, input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null;
  }
};

export const gitRoot = (dir) => git(dir, ['rev-parse', '--show-toplevel'])?.trim() || null;

/** Every settings and rules file under `dir`, with whether git tracks, ignores or doesn't know it. */
export function walk(start) {
  // Real paths, so a folder reached through a symlink (macOS /var is /private/var) lines up with git's root.
  let dir;
  try { dir = realpathSync(start); } catch { return []; }
  const found = [];
  const visit = (abs, depth) => {
    if (depth > 40) return;
    let entries;
    try { entries = readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(abs, e.name);
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) visit(p, depth + 1);
      } else if (e.isFile() && WANTED(relative(dir, p).split('\\').join('/'))) {
        found.push(p);
      }
    }
  };
  visit(dir, 0);
  const root = gitRoot(dir);
  const rels = root ? found.map((p) => relative(root, p).split('\\').join('/')) : [];
  const tracked = new Set(root && rels.length ? (git(root, ['ls-files', '-z', '--', ...rels]) || '').split('\0').filter(Boolean) : []);
  const ignored = new Set(root && rels.length ? (git(root, ['check-ignore', '--stdin', '-z'], rels.join('\0') + '\0') || '').split('\0').filter(Boolean) : []);
  return found.sort().map((abs, i) => {
    const rel = root ? rels[i] : relative(dir, abs);
    const status = !root ? 'no-git' : tracked.has(rel) ? 'tracked' : ignored.has(rel) ? 'ignored' : 'untracked';
    return { path: relative(process.cwd(), abs) || abs, status, read: () => readSmall(abs) };
  });
}

function readSmall(abs) {
  try {
    if (statSync(abs).size > MAX_FILE) return null;
    return readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

/** The staged version of each wanted file: what the commit would contain. */
export function staged(dir) {
  const root = gitRoot(dir);
  if (!root) return { error: 'not inside a git repository' };
  const names = (git(root, ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR']) || '').split('\0').filter(Boolean).filter(WANTED);
  return {
    files: names.map((rel) => ({ path: relative(process.cwd(), join(root, rel)) || rel, status: 'staged', read: () => git(root, ['show', `:${rel}`]) })),
  };
}

/** Every version of a wanted file that any commit on any branch ever held. */
export function history(dir) {
  const root = gitRoot(dir);
  if (!root) return { error: 'not inside a git repository' };
  const log = git(root, ['log', '--all', '--diff-filter=AM', '--format=@%H', '--name-only', '--', ':(glob)**/.claude/settings*.json', ':(glob)**/.codex/rules/*.rules']) || '';
  const files = [];
  let commit = null;
  for (const line of log.split('\n')) {
    if (line.startsWith('@')) commit = line.slice(1);
    else if (line.trim() && commit && WANTED(line.trim())) {
      const rel = line.trim();
      const c = commit;
      files.push({ path: rel, commit: c.slice(0, 10), status: 'history', read: () => git(root, ['show', `${c}:${rel}`]) });
    }
  }
  return { files };
}

/** Your own files: ~/.claude/settings.json and Codex's rules folder. */
export function home(env = process.env) {
  const homeDir = env.HOME || os.homedir();
  const codexHome = env.CODEX_HOME && isAbsolute(env.CODEX_HOME) ? env.CODEX_HOME : join(homeDir, '.codex');
  const paths = [join(homeDir, '.claude', 'settings.json'), join(homeDir, '.claude', 'settings.local.json')];
  const rulesDir = join(codexHome, 'rules');
  if (existsSync(rulesDir)) {
    try {
      for (const name of readdirSync(rulesDir)) if (name.endsWith('.rules')) paths.push(join(rulesDir, name));
    } catch { /* unreadable */ }
  }
  return {
    files: paths.filter((p) => existsSync(p)).map((abs) => ({
      path: abs.startsWith(homeDir) ? '~' + abs.slice(homeDir.length) : abs,
      status: 'home',
      read: () => readSmall(abs),
    })),
  };
}
