// Credential formats with a fixed prefix. Each pattern starts at a word edge
// and runs as far as the format's own characters go, so whatever follows the
// key (a quote, an escaped quote, `:*`, `)`, `&`) ends it. Scanners that
// require a quote, a space or a line end after the key miss keys inside
// agent permission rules, which is the reason this list exists.
//
// The list is adapted from agent-recap's src/redact.js (Team-Commonly, Apache-2.0).

const S = '(?<![A-Za-z0-9_])';
const f = (label, body, flags = 'g') => ({ label, re: new RegExp(S + body, flags) });

export const FORMATS = [
  f('private key (PEM)', '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'),
  f('JWT', 'eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{6,}'),
  f('Anthropic API key', 'sk-ant-[A-Za-z0-9_-]{16,}'),
  f('OpenRouter API key', 'sk-or-v1-[A-Za-z0-9]{32,}'),
  f('OpenAI API key', 'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}'),
  f('GitHub token', 'gh[pousr]_[A-Za-z0-9]{20,}'),
  f('GitHub token', 'github_pat_[A-Za-z0-9_]{20,}'),
  f('GitLab token', 'gl(?:pat|dt|rt|ptt|soat)-[A-Za-z0-9_-]{20,}'),
  f('Hugging Face token', 'hf_[A-Za-z0-9]{20,}'),
  f('Google API key', 'AIza[0-9A-Za-z_-]{30,}'),
  f('Stripe key', '(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}'),
  f('Stripe webhook secret', 'whsec_[0-9A-Za-z]{24,}'),
  f('Slack token', 'xox[abposr]-[0-9A-Za-z-]{10,}'),
  f('Slack webhook', 'https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}'),
  f('Discord webhook', 'https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]{30,}'),
  f('AWS access key id', '(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])'),
  f('npm token', 'npm_[A-Za-z0-9]{30,}'),
  f('PyPI token', 'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{30,}'),
  f('SendGrid key', 'SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}'),
  f('Twilio key', 'SK[0-9a-f]{32}(?![0-9a-f])'),
  f('Shopify token', 'shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}'),
  f('DigitalOcean token', 'do[opr]_v1_[a-f0-9]{64}'),
  f('Linear API key', 'lin_api_[A-Za-z0-9]{40}'),
  f('Notion token', '(?:secret_|ntn_)[A-Za-z0-9]{40,}'),
  f('Supabase token', 'sbp_[a-f0-9]{40}'),
  f('Groq API key', 'gsk_[A-Za-z0-9]{40,}'),
  f('xAI API key', 'xai-[A-Za-z0-9]{40,}'),
  f('Replicate token', 'r8_[A-Za-z0-9]{30,}'),
  f('Doppler token', 'dp\\.(?:st|ct|sa|scim|audit)\\.[A-Za-z0-9_.-]{20,}'),
  f('Mailgun key', 'key-[0-9a-f]{32}(?![0-9a-f])'),
  f('Atlassian token', 'ATATT3[A-Za-z0-9_=-]{30,}'),
  f('Telegram bot token', '\\d{8,10}:AA[A-Za-z0-9_-]{30,}'),
  f('Azure storage key', 'AccountKey=[A-Za-z0-9+/]{40,}={0,2}'),
];

export function formatsIn(text) {
  const found = [];
  for (const { label, re } of FORMATS) {
    re.lastIndex = 0;
    for (const m of String(text).matchAll(re)) {
      const value = m[0];
      if (found.some((x) => x.value.includes(value) || value.includes(x.value))) continue;
      found.push({ label, value });
    }
  }
  return found;
}

// A long run that looks random: base64 switches between upper, lower and
// digits on most characters; names, paths and camelCase switch on few.
// Measured in agent-recap on random keys and real paths, branches and identifiers.
const charClass = (c) => (/[a-z]/.test(c) ? 0 : /[A-Z]/.test(c) ? 1 : /\d/.test(c) ? 2 : 3);
export function looksLikeKey(run) {
  const upper = run.match(/[A-Z]/g)?.length || 0;
  const lower = run.match(/[a-z]/g)?.length || 0;
  const digits = run.match(/\d/g)?.length || 0;
  if (upper < 4 || lower < 4 || digits < 2) return false;
  const letters = upper + lower;
  if (upper < letters * 0.2 || lower < letters * 0.2) return false;
  let switches = 0;
  let upperThenLower = 0;
  for (let i = 1; i < run.length; i += 1) {
    if (charClass(run[i]) !== charClass(run[i - 1])) switches += 1;
    if (charClass(run[i - 1]) === 1 && charClass(run[i]) === 0) upperThenLower += 1;
  }
  if (upperThenLower / upper > 0.8) return false;
  return switches / (run.length - 1) >= 0.38;
}

export function randomRunsIn(text) {
  return [...String(text).matchAll(/[A-Za-z0-9+/=_-]{40,}/g)].map((m) => m[0]).filter(looksLikeKey);
}
