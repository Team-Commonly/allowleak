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
  if (/^(true|false|yes|no|on|off|none|null|nil|undefined|redacted|0|1)$/i.test(v)) return true;
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
const LOGIN = { next: ['-p'], when: (args) => args[0] === 'login' || (args[0] === 'registry' && args[1] === 'login') || (args[0] === 'repo' && args[1] === 'add') };
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
  az: { next: ['-p'], when: (args) => args[0] === 'login' },
};
// Long flags that take a secret in any program.
const LONG = /^--(password|passwd|pass|token|api[-_]?key|apikey|secret|client[-_]secret|access[-_]token|auth[-_]token|bearer[-_]token|private[-_]key|storepass|keypass|http[-_]password|ftp[-_]password|proxy[-_]password|oauth2[-_]bearer|registry[-_]password|db[-_]password|admin[-_]password|passphrase)$/i;
// For these, a lowercase name (db-password, id_ed25519) or a build-secret spec (id=x,src=y) is a name, not a secret.
const NAMED = /^--(secret|private[-_]key)$/i;
const isNameNotSecret = (flag, v) => NAMED.test(flag) && ((/^[a-z][a-z0-9._-]*$/.test(v) && !/^(0x)?[0-9a-f]{32,}$/.test(v)) || /(^|,)(id|src|source|env|type|target)=/.test(v));
const WRAPPERS = new Set(['sudo', 'env', 'time', 'nice', 'nohup', 'exec', 'command', 'npx', 'pnpx', 'bunx', 'xargs', 'doas']);
const HEADER = /(?:^|[=\s'"])(authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|private-token|x-token|x-vault-token|x-goog-api-key|ocp-apim-subscription-key|cookie)\s*:\s*(.+)$/i;
const AUTH_SCHEME = /^(basic|bearer|token|bot|digest|apikey|key|sso-key)\s+/i;
const URL_PASSWORD = /\b([a-z][a-z0-9+.-]*):\/\/([^\s/@:]*):(\S+)@([^\s@/?#"']*)/gi;
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

// Last check before a finding leaves: if its location or label holds any piece of the value
// (8 characters, or the whole of a shorter value), fall back to text that holds none.
const leaks = (text, value) => {
  const v = String(value);
  if (v.length < 8) return v.length >= 4 && text.includes(v);
  for (let i = 0; i + 8 <= v.length; i += 1) if (text.includes(v.slice(i, i + 8))) return true;
  return false;
};
const finding = (label, where, value) => (leaks(`${label} ${where}`, value) ? { label: 'credential', where: MASK, value } : { label, where, value });

/** Findings in a shell command line. */
export function inCommand(command) {
  const found = [];
  const add = (label, where, value) => {
    if (isReference(value)) return;
    if (found.some((x) => x.value.includes(value) || value.includes(x.value))) return;
    found.push(finding(label, where, value));
  };
  for (const { label, value } of formatsIn(command)) add(label, label, value);

  for (const words of commands(tokenize(command))) {
    const { name, args } = program(words);
    for (const w of words) {
      const pieces = [w, ...w.split(/\s+/)];
      const flagValue = w.match(/^--?[A-Za-z][\w-]*=(.+)$/s);
      if (flagValue) pieces.push(flagValue[1]);
      for (const piece of pieces) {
        const assign = piece.match(/^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$/s);
        if (assign && isSecretName(assign[1])) add(`secret in ${assign[1]}`, `${assign[1]}=${MASK}`, assign[2]);
      }
    }
    // `aws configure set aws_secret_access_key X`, `npm config set //host/:_authToken X`, `git config --global x.token X`
    const set = args.indexOf('set');
    const setKey = set >= 0 ? args[set + 1] : undefined;
    const setValue = set >= 0 ? args[set + 2] : undefined;
    if (setKey !== undefined && setValue !== undefined && !setKey.includes('=') && !/^[-<>|]/.test(setValue)
      && (isSecretName(setKey.split(/[.:/]/).pop().replace(/^_/, '')) || /:_(auth|authToken|password)$/.test(setKey))) {
      add('secret given to config set', `${name} … set … ${MASK}`, setValue);
    }
    const short = SHORT[name];
    for (let j = 0; j < args.length; j += 1) {
      const a = args[j];
      const eq = a.match(/^(--[A-Za-z][\w-]*)=(.*)$/s);
      if (eq && LONG.test(eq[1]) && !isPathLike(eq[2]) && !isNameNotSecret(eq[1], eq[2])) add(`password after ${eq[1]}`, `${name} ${eq[1]}=${MASK}`, eq[2]);
      else if (LONG.test(a) && args[j + 1] !== undefined && !args[j + 1].startsWith('-') && !isPathLike(args[j + 1]) && !isNameNotSecret(a, args[j + 1])) add(`password after ${a}`, `${name} ${a} ${MASK}`, args[j + 1]);
      if (short && (!short.when || short.when(args))) {
        for (const flag of short.attached || []) {
          if (a.startsWith(flag) && a.length > flag.length && !a.startsWith('--')) add(`password after ${flag}`, `${name} ${flag}${MASK}`, a.slice(flag.length));
        }
        if ((short.next || []).includes(a) && args[j + 1] !== undefined) add(`password after ${a}`, `${name} ${a} ${MASK}`, args[j + 1]);
      }
      const userPass = (flag, pair, sep = ':') => {
        const at = pair.indexOf(sep);
        if (at < 0) return;
        const user = pair.slice(0, at);
        if (randomish(user) || formatsIn(user).length) add(`token in ${name} ${flag}`, `${name} ${flag} ${MASK}${sep}…`, user);
        add(`password in ${name} ${flag}`, `${name} ${flag} …${sep}${MASK}`, pair.slice(at + 1));
      };
      if (name === 'curl') {
        if ((a === '-u' || a === '--user') && args[j + 1] !== undefined) userPass(a, args[j + 1]);
        else if (/^-u./.test(a)) userPass('-u', a.slice(2));
        else if (a.startsWith('--user=')) userPass('--user', a.slice(7));
      }
      if (/^https?$|^xh$/.test(name) && (a === '-a' || a === '--auth') && args[j + 1] !== undefined) userPass(a, args[j + 1]);
      if (name === 'smbclient' && (a === '-U' || a === '--user') && (args[j + 1] || '').includes('%')) userPass(a, args[j + 1], '%');
      if (name === 'lftp' && a === '-u' && (args[j + 1] || '').includes(',')) userPass(a, args[j + 1], ',');
      if (name === 'openssl' && /^-pass(in|out)?$/.test(a) && /^pass:/.test(args[j + 1] || '')) add(`password after ${a}`, `openssl ${a} pass:${MASK}`, args[j + 1].slice(5));
      if (name === 'htpasswd' && /^-[a-zA-Z]*b/.test(a)) add('password in htpasswd -b', `htpasswd … ${MASK}`, args[args.length - 1]);
    }
    for (const w of words) {
      const h = w.match(HEADER);
      if (h) {
        const raw = h[2].trim();
        const value = raw.replace(AUTH_SCHEME, '');
        const scheme = raw.slice(0, raw.length - value.length).trim();
        if (h[1].toLowerCase() !== 'cookie' || randomish(value)) add(`secret in ${h[1]} header`, `${h[1]}: ${scheme ? scheme + ' ' : ''}${MASK}`, value);
      }
      const npmAuth = w.match(/:_(auth|authToken|password)=(.+)$/s);
      if (npmAuth) add(`npm _${npmAuth[1]}`, `:_${npmAuth[1]}=${MASK}`, npmAuth[2]);
    }
  }
  inText(command, add);
  return found.map(({ label, where, value }) => ({ label, where, value }));
}

// URL credentials, query strings and random runs: anywhere in any text.
function inText(text, add) {
  // Neither the user nor the host is printed: a token can sit in the user slot
  // (https://<token>:x-oauth-basic@github.com), and a password can hold @.
  for (const m of text.matchAll(URL_PASSWORD)) {
    const [, scheme, user, pass] = m;
    if (/^\d{1,5}(\/|$)/.test(pass)) continue; // host:port/path, not user:password
    if (randomish(user) || formatsIn(user).length) add('token in a URL', `${scheme}://${MASK}:…@…`, user);
    add('password in a URL', `${scheme}://…:${MASK}@…`, pass);
  }
  for (const m of text.matchAll(URL_TOKEN)) {
    if (randomish(m[2]) || formatsIn(m[2]).length) add('token in a URL', `${m[1]}://${MASK}@…`, m[2]);
  }
  for (const m of text.matchAll(QUERY)) {
    const [, name, value] = m;
    if (QUERY_STRONG.test(name) ? value.length >= 4 : QUERY_WEAK.test(name) && randomish(value)) add(`secret in ?${name}=`, `?${name}=${MASK}`, decodeURIComponentSafe(value));
  }
  for (const run of randomRunsIn(text)) add('random-looking key', `${MASK} (${run.length} characters)`, run);
}
const decodeURIComponentSafe = (v) => { try { return decodeURIComponent(v); } catch { return v; } };

/** Findings in a value that isn't a command (a WebFetch rule, an MCP rule, a setting). */
export function inValue(text) {
  const found = [];
  const add = (label, where, value) => {
    if (isReference(value)) return;
    if (found.some((x) => x.value.includes(value) || value.includes(x.value))) return;
    found.push(finding(label, where, value));
  };
  for (const { label, value } of formatsIn(text)) add(label, label, value);
  inText(String(text), add);
  return found;
}

/** Findings in one env entry (Claude Code's settings `env`, a Codex shell env). */
export function inEnv(name, value) {
  const found = inValue(value);
  if (!found.length && isSecretName(name) && !isReference(value) && String(value).length >= 4 && !isPathLike(String(value))) {
    found.push(finding(`secret in ${name}`, `${name}=${MASK}`, String(value)));
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
