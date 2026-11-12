// What a permission rule, an env entry or a command string holds. Every
// finding names where the credential sits ("mysql -p", "PGPASSWORD=",
// "password in a URL") and never carries the value out: callers get `where`,
// a short text with the value replaced by MASK, and `label`.

import { formatsIn, looksLikeKey, randomRunsIn } from './formats.js';
import { commands, tokenize } from './shell.js';

export const MASK = '••••';

// A value that names a secret instead of holding one.
export function isReference(value) {
  const v = String(value).trim();
  if (!v) return true;
  if (/^\$/.test(v) || /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v)) return true; // $VAR, ${VAR}, $(cmd), %VAR%
  if (/^<[^<>]*>$/.test(v) || /^\{\{.*\}\}$/.test(v) || /^\[[A-Z_ ]+\]$/.test(v)) return true; // <password>, {{ secret }}, [REDACTED]
  if (/^(\*+|x+|X+|\.{3}|…|-)$/.test(v)) return true;
  if (/^(true|false|yes|no|on|off|none|null|nil|undefined|redacted)$/i.test(v)) return true;
  return false;
}
const isPathLike = (v) => /^(\/|\.{1,2}\/|~\/|@|file:)/.test(v);
const randomish = (v) => v.length >= 16 && [/[a-z]/, /[A-Z]/, /\d/].filter((r) => r.test(v)).length >= 2;

// Names that hold a secret: PGPASSWORD, MYSQL_PWD, OPENAI_API_KEY, dbPassword, client_secret.
const SECRET_PART = /^(pass|pwd|passwd|auth|creds?|credentials?)$|(password|passwd|passphrase|secret|token|apikey)$/;
const KEY_OWNER = new Set(['api', 'access', 'secret', 'private', 'master', 'encryption', 'signing', 'service', 'license', 'client', 'app', 'account', 'subscription', 'admin', 'deploy']);
const NOT_A_SECRET_PART = new Set(['file', 'path', 'dir', 'url', 'uri', 'host', 'port', 'id', 'name', 'user', 'username', 'endpoint', 'region', 'type', 'mode', 'length', 'len', 'ttl', 'expiry', 'expires', 'header', 'env', 'var', 'count', 'limit', 'prefix', 'suffix', 'format', 'version', 'kind', 'scope', 'method', 'provider', 'cmd', 'command', 'helper', 'location', 'store', 'policy', 'level', 'required', 'enabled', 'disabled']);
export function isSecretName(name) {
  const parts = String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[_.\-]+/).filter(Boolean);
  if (!parts.length || NOT_A_SECRET_PART.has(parts[parts.length - 1])) return false;
  return parts.some((p, i) => SECRET_PART.test(p) || (p === 'key' && i > 0 && KEY_OWNER.has(parts[i - 1])));
}

// Short flags that take a password, per program. `attached` means the value
// is glued on (mysql -pSECRET); `next` means the next word.
const MYSQL = { attached: ['-p'] };
const MONGO = { next: ['-p'] };
const LOGIN = { next: ['-p'], when: (args) => args.includes('login') || (args.includes('repo') && args.includes('add')) };
const SHORT = {
  mysql: MYSQL, mariadb: MYSQL, mysqldump: MYSQL, mysqladmin: MYSQL, mysqlimport: MYSQL, mysqlcheck: MYSQL, mysqlsh: MYSQL, 'mariadb-dump': MYSQL,
  mongosh: MONGO, mongo: MONGO, mongodump: MONGO, mongorestore: MONGO, mongoexport: MONGO, mongoimport: MONGO,
  'redis-cli': { next: ['-a'] }, 'valkey-cli': { next: ['-a'] },
  sshpass: { next: ['-p'], attached: ['-p'] },
  zip: { next: ['-P'] }, unzip: { next: ['-P'] }, '7z': { attached: ['-p'] }, '7za': { attached: ['-p'] }, '7zz': { attached: ['-p'] },
  twine: { next: ['-p'] }, sqlcmd: { next: ['-P'] }, bcp: { next: ['-P'] },
  ldapsearch: { next: ['-w'] }, ldapadd: { next: ['-w'] }, ldapmodify: { next: ['-w'] }, ldapdelete: { next: ['-w'] },
  mosquitto_pub: { next: ['-P'] }, mosquitto_sub: { next: ['-P'] }, rabbitmqadmin: { next: ['-p'] },
  keytool: { next: ['-storepass', '-keypass', '-srcstorepass', '-deststorepass', '-srckeypass', '-destkeypass'] },
  docker: LOGIN, podman: LOGIN, nerdctl: LOGIN, buildah: LOGIN, skopeo: LOGIN, oras: LOGIN, crane: LOGIN, helm: LOGIN, finch: LOGIN,
  az: { next: ['-p'], when: (args) => args.includes('login') },
};
// Long flags that take a secret in any program.
const LONG = /^--(password|passwd|pass|token|api[-_]?key|apikey|secret|client[-_]secret|access[-_]token|auth[-_]token|bearer[-_]token|private[-_]key|storepass|keypass|http[-_]password|ftp[-_]password|proxy[-_]password|oauth2[-_]bearer|registry[-_]password|db[-_]password|admin[-_]password)$/i;
const WRAPPERS = new Set(['sudo', 'env', 'time', 'nice', 'nohup', 'exec', 'command', 'npx', 'pnpx', 'bunx', 'xargs', 'doas']);
const HEADER = /(?:^|[=\s'"])(authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|private-token|x-token|x-vault-token|x-goog-api-key|ocp-apim-subscription-key|cookie)\s*:\s*(.+)$/i;
const AUTH_SCHEME = /^(basic|bearer|token|bot|digest|apikey|key|sso-key)\s+/i;
const URL_PASSWORD = /\b([a-z][a-z0-9+.-]*):\/\/([^\s/@:]*):([^\s@/]+)@([^\s/?#"']*)/gi;
const URL_TOKEN = /\b(https?|git|ssh|wss?):\/\/([^\s/@:]+)@([^\s/?#"']*)/gi;
const QUERY = /[?&;]([A-Za-z_-]+)=([^&#\s"']+)/g;
const QUERY_STRONG = /^(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?token|client[_-]?secret|secret|password|passwd|pwd|x-api-key)$/i;
const QUERY_WEAK = /^(key|token|auth|sig|signature|code)$/i;

const program = (words) => {
  let i = 0;
  let wrapped = false;
  while (i < words.length) {
    const w = words[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) i += 1;
    else if (WRAPPERS.has(w.split('/').pop())) { wrapped = true; i += 1; }
    else if (wrapped && w.startsWith('-')) i += 1;
    else break;
  }
  return { name: (words[i] || '').split('/').pop(), args: words.slice(i + 1) };
};

/** Findings in a shell command line. */
export function inCommand(command) {
  const found = [];
  const add = (label, where, value) => {
    if (isReference(value)) return;
    if (found.some((x) => x.value.includes(value) || value.includes(x.value))) return;
    found.push({ label, where, value });
  };
  for (const { label, value } of formatsIn(command)) add(label, label, value);

  for (const words of commands(tokenize(command))) {
    const { name, args } = program(words);
    for (const w of words) {
      const assign = w.match(/^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$/s);
      if (assign && isSecretName(assign[1])) add(`secret in ${assign[1]}`, `${assign[1]}=${MASK}`, assign[2]);
    }
    const short = SHORT[name];
    for (let j = 0; j < args.length; j += 1) {
      const a = args[j];
      const eq = a.match(/^(--[A-Za-z][\w-]*)=(.*)$/s);
      if (eq && LONG.test(eq[1]) && !isPathLike(eq[2])) add(`password after ${eq[1]}`, `${name} ${eq[1]}=${MASK}`, eq[2]);
      else if (LONG.test(a) && args[j + 1] !== undefined && !args[j + 1].startsWith('-') && !isPathLike(args[j + 1])) add(`password after ${a}`, `${name} ${a} ${MASK}`, args[j + 1]);
      if (short && (!short.when || short.when(args))) {
        for (const flag of short.attached || []) {
          if (a.startsWith(flag) && a.length > flag.length && !a.startsWith('--')) add(`password after ${flag}`, `${name} ${flag}${MASK}`, a.slice(flag.length));
        }
        if ((short.next || []).includes(a) && args[j + 1] !== undefined) add(`password after ${a}`, `${name} ${a} ${MASK}`, args[j + 1]);
      }
      if ((name === 'curl' && (a === '-u' || a === '--user')) || (/^https?$|^xh$/.test(name) && (a === '-a' || a === '--auth'))) {
        const pair = args[j + 1] || '';
        const at = pair.indexOf(':');
        if (at > 0) add(`password in ${name} ${a}`, `${name} ${a} ${pair.slice(0, at)}:${MASK}`, pair.slice(at + 1));
      }
      if (name === 'smbclient' && (a === '-U' || a === '--user') && (args[j + 1] || '').includes('%')) {
        const [user, ...rest] = args[j + 1].split('%');
        add('password in smbclient -U', `smbclient -U ${user}%${MASK}`, rest.join('%'));
      }
      if (name === 'lftp' && a === '-u' && (args[j + 1] || '').includes(',')) {
        const [user, ...rest] = args[j + 1].split(',');
        add('password in lftp -u', `lftp -u ${user},${MASK}`, rest.join(','));
      }
      if (name === 'openssl' && /^-pass(in|out)?$/.test(a) && /^pass:/.test(args[j + 1] || '')) add(`password after ${a}`, `openssl ${a} pass:${MASK}`, args[j + 1].slice(5));
      if (name === 'htpasswd' && /^-[a-zA-Z]*b/.test(a) && args.length >= j + 4) add('password in htpasswd -b', `htpasswd ${a} … ${MASK}`, args[j + 3]);
    }
    for (const w of words) {
      const h = w.match(HEADER);
      if (h) {
        const raw = h[2].trim();
        const value = raw.replace(AUTH_SCHEME, '');
        const scheme = raw.slice(0, raw.length - value.length).trim();
        if (h[1].toLowerCase() !== 'cookie' || randomish(value)) add(`secret in ${h[1]} header`, `${h[1]}: ${scheme ? scheme + ' ' : ''}${MASK}`, value);
      }
      const npmAuth = w.match(/:_(auth|authToken|password)=(.+)$/);
      if (npmAuth) add(`npm _${npmAuth[1]}`, `:_${npmAuth[1]}=${MASK}`, npmAuth[2]);
    }
  }
  inText(command, add);
  return found.map(({ label, where, value }) => ({ label, where, value }));
}

// URL credentials, query strings and random runs: anywhere in any text.
function inText(text, add) {
  for (const m of text.matchAll(URL_PASSWORD)) {
    if (/^\d{1,5}$/.test(m[3])) continue; // host:port, not user:password
    add('password in a URL', `${m[1]}://${m[2]}:${MASK}@${m[4]}`, m[3]);
  }
  for (const m of text.matchAll(URL_TOKEN)) {
    if (m[2].includes(':')) continue;
    if (randomish(m[2]) || formatsIn(m[2]).length) add('token in a URL', `${m[1]}://${MASK}@${m[3]}`, m[2]);
  }
  for (const m of text.matchAll(QUERY)) {
    const [, name, value] = m;
    if (QUERY_STRONG.test(name) ? value.length >= 4 : QUERY_WEAK.test(name) && randomish(value)) add(`secret in ?${name}=`, `?${name}=${MASK}`, decodeURIComponentSafe(value));
  }
  for (const run of randomRunsIn(text)) add('random-looking key', `${run.slice(0, 0)}${MASK} (${run.length} characters)`, run);
}
const decodeURIComponentSafe = (v) => { try { return decodeURIComponent(v); } catch { return v; } };

/** Findings in a value that isn't a command (a WebFetch rule, an MCP rule, a setting). */
export function inValue(text) {
  const found = [];
  const add = (label, where, value) => {
    if (isReference(value)) return;
    if (found.some((x) => x.value.includes(value) || value.includes(x.value))) return;
    found.push({ label, where, value });
  };
  for (const { label, value } of formatsIn(text)) add(label, label, value);
  inText(String(text), add);
  return found;
}

/** Findings in one env entry (Claude Code's settings `env`, a Codex shell env). */
export function inEnv(name, value) {
  const found = inValue(value);
  if (!found.length && isSecretName(name) && !isReference(value) && String(value).length >= 4 && !isPathLike(String(value))) {
    found.push({ label: `secret in ${name}`, where: `${name}=${MASK}`, value: String(value) });
  }
  return found;
}

// Claude Code rules: Tool(content). A Bash rule's content is a command, with
// an optional prefix marker at the end (":*" or " *").
export function inClaudeRule(rule) {
  const m = String(rule).match(/^([A-Za-z_][\w-]*)\(([\s\S]*)\)$/);
  if (m && m[1] === 'Bash') return inCommand(m[2].replace(/(?::\*| \*)$/, ''));
  return inValue(m ? m[2] : rule);
}

/** Codex prefix_rule pattern: a list of words, each word a string or a list of alternatives. */
export function inCodexPattern(words) {
  const flat = words.map((w) => (Array.isArray(w) ? w[0] : w)).map(String);
  const quoted = flat.map((w) => (/[\s"'\\$`;&|()]/.test(w) ? `'${w.replace(/'/g, "'\\''")}'` : w)).join(' ');
  const alternatives = words.filter(Array.isArray).flat().map(String).join(' ');
  return [...inCommand(quoted), ...inValue(alternatives)].filter((x, i, all) => all.findIndex((y) => y.value === x.value) === i);
}
