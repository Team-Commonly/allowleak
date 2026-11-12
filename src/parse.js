// Read the files agents keep their permissions in and return what each holds,
// with the line it sits on.
//
// Claude Code: .claude/settings.json and .claude/settings.local.json (and
// ~/.claude/settings.json). Rules under permissions.allow/ask/deny; also the
// `env` block, helper commands and hook commands, since they live in the same file.
//
// Codex: $CODEX_HOME/rules/*.rules and a project's .codex/rules/*.rules.
// "Always allow" in Codex appends `prefix_rule(pattern=[...], decision="allow")`
// to $CODEX_HOME/rules/default.rules (openai/codex rust-v0.167.2,
// codex-rs/core/src/exec_policy.rs and codex-rs/execpolicy/src/amend.rs).

import { inClaudeRule, inCodexPattern, inCommand, inEnv, inValue } from './detect.js';

/** JSON with comments and trailing commas, as Claude Code accepts it. */
export function stripJsonc(text) {
  let out = '';
  let i = 0;
  const s = String(text);
  while (i < s.length) {
    const c = s[i];
    if (c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      out += s.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && s[i + 1] === '/') {
      while (i < s.length && s[i] !== '\n') i += 1;
    } else if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      const stop = end < 0 ? s.length : end + 2;
      out += s.slice(i, stop).replace(/[^\n]/g, ' '); // keep line numbers
      i = stop;
    } else {
      out += c;
      i += 1;
    }
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

const lineAt = (text, index) => (index < 0 ? 0 : text.slice(0, index).split('\n').length);

const COMMAND_KEYS = new Set(['command', 'apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper', 'gcpAuthRefresh']);

export function claudeSettings(text) {
  let data;
  try {
    data = JSON.parse(stripJsonc(text));
  } catch (e) {
    return { error: 'not valid JSON', items: [] };
  }
  const items = [];
  let cursor = 0;
  const locate = (value) => {
    const needle = JSON.stringify(String(value)).slice(1, -1);
    let at = text.indexOf(needle, cursor);
    if (at < 0) at = text.indexOf(needle);
    if (at >= 0) cursor = at + needle.length;
    return lineAt(text, at);
  };
  const walk = (node, path) => {
    if (typeof node === 'string') {
      const key = path[path.length - 1];
      const parent = path[path.length - 2];
      let findings;
      if (path[0] === 'permissions' && ['allow', 'ask', 'deny'].includes(parent)) findings = inClaudeRule(node);
      else if (path[0] === 'env' && path.length === 2) findings = inEnv(key, node);
      else if (parent === 'env') findings = inEnv(key, node);
      else if (COMMAND_KEYS.has(key)) findings = inCommand(node);
      else findings = inValue(node);
      if (findings.length) items.push({ line: locate(node), findings });
    } else if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, [...path, i]));
    } else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) walk(v, [...path, k]);
    }
  };
  walk(data, []);
  return { items };
}

// The bracketed list after `pattern=`, read as JSON (Codex writes JSON
// strings), else with single quotes turned into double.
function readList(s, start) {
  let depth = 0;
  let inStr = null;
  for (let i = start; i < s.length; i += 1) {
    const c = s[i];
    if (inStr) {
      if (c === '\\') i += 1;
      else if (c === inStr) inStr = null;
    } else if (c === '"' || c === "'") inStr = c;
    else if (c === '[') depth += 1;
    else if (c === ']' && --depth === 0) {
      const raw = s.slice(start, i + 1);
      try { return JSON.parse(raw); } catch { /* fall through */ }
      try { return JSON.parse(raw.replace(/'((?:[^'\\]|\\.)*)'/g, (_m, b) => JSON.stringify(b.replace(/\\'/g, "'")))); } catch { return null; }
    }
  }
  return null;
}

export function codexRules(text) {
  const s = String(text);
  const items = [];
  for (const m of s.matchAll(/prefix_rule\s*\(/g)) {
    const pat = s.slice(m.index).match(/pattern\s*=\s*\[/);
    if (!pat) continue;
    const list = readList(s, m.index + pat.index + pat[0].length - 1);
    if (!Array.isArray(list)) continue;
    const findings = inCodexPattern(list);
    if (findings.length) items.push({ line: lineAt(s, m.index), findings });
  }
  return { items };
}

export const isClaudeSettings = (path) => /(^|\/)\.claude\/settings(\.local)?\.json$/.test(path);

export function scanText(rawPath, text) {
  const path = String(rawPath).split('\\').join('/');
  if (isClaudeSettings(path)) return claudeSettings(text);
  if (/\.rules$/.test(path)) return codexRules(text);
  return { items: [] };
}
