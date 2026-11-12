# allowleak

When you pick "Don't ask again" in Claude Code, it saves the command as an allow rule. If that command had a password in it, so does the rule, and the rule sits in a file people commit.

allowleak reads those files and tells you which rules hold a password or a token, before they reach a commit.

```
npx github:Team-Commonly/allowleak
```

```
allowleak: 3 credentials in 2 files.

.claude/settings.local.json  (not committed yet, and not ignored by git)
  line 15  mysql -p••••                        password after -p
  line 16  postgresql://…:••••@…               password in a URL

.codex/rules/default.rules  (committed)
  line 3  GitHub token

Delete those rules, then change each credential. If one was ever committed, it is in your git history: run allowleak --history.
```

It shows where each credential is and what kind it is. It never prints the credential.

## Why a secret scanner misses these

We ran gitleaks 8.30.1 with its default config over 42 allow rules that each carry a credential, written the way they sit in `.claude/settings.local.json`. We ran it 10 times with fresh values each time.

| | gitleaks | allowleak |
|---|---|---|
| Passwords of 20 random characters | 51% | 100% |
| Passwords a person would pick | 38% | 100% |
| Rules with no credential, flagged | 0 of 120 | 0 of 120 |

gitleaks missed two kinds of rule.

**Keys in formats it knows, followed by the wrong character.** Its token patterns need a quote, a space, `;` or the end of the line right after the key. In a settings file a key is followed by `\"` (a quote, escaped inside JSON), `:*` (how a prefix rule ends) or `)`. A Stripe key and a Google key were missed in every run. The same keys followed by a space were caught.

**Credentials with no keyword next to them.** gitleaks catches `--password=…` and `API_KEY=…` most of the time. It missed every one of these:

- `mysql -p…` and `redis-cli -a …`
- `postgresql://user:pass@…`, `mongodb+srv://user:pass@…` and `https://user:token@…` in a git URL
- `sshpass -p …`, `docker login -p …`, `az login -p …`, `zip -P …`
- `Authorization: Basic …`, `Authorization: Bearer <token>` and `X-API-Key: …` headers
- `?api_key=…` in a URL
- `smbclient -U user%pass` and `lftp -u user,pass`

allowleak reads each rule as the command it is. It knows which flag takes a password for which program, so `mysql -pX` is a password and `psql -p 5432` is a port.

The 100% is on a fixture we wrote next to the tool, so treat it as a ceiling. On the 32 settings and rules files on our own machines (128 rules), allowleak flagged nothing. Keep your secret scanner as well. allowleak reads only these files, and reads them closely.

## Use it before every commit

With [pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/Team-Commonly/allowleak
    rev: v0.1.0
    hooks:
      - id: allowleak
```

As a plain git hook, in `.git/hooks/pre-commit`:

```sh
#!/bin/sh
npx --yes github:Team-Commonly/allowleak --staged
```

`--staged` checks what the commit would contain, not what is on disk. It exits 1 when it finds a credential, which stops the commit.

## Other ways to run it

```
allowleak [folder]   every .claude/settings*.json and .codex/rules/*.rules under a folder (default: here)
allowleak --staged   what the next commit would add
allowleak --history  every version those files ever had in this repo's git history
allowleak --home     your own ~/.claude/settings.json and Codex's ~/.codex/rules
--json               JSON output
--strict             also fail on files git ignores
```

A file git ignores is still shown, but it doesn't fail the run, since it isn't headed for a commit. A committed `.claude/settings.local.json` gets a note even when it is clean. Claude Code keeps that file for one machine and adds it to `.gitignore` when it creates it.

If a credential was ever committed, deleting the rule doesn't take it out of your history. `--history` shows the commit it is in. Change the credential.

## What it reads

**Claude Code:** `.claude/settings.json` and `.claude/settings.local.json` in a repo, and `~/.claude/settings.json` with `--home`. In those files it checks the rules under `permissions` (allow, ask and deny), the `env` block, helper commands such as `apiKeyHelper`, and hook commands.

**Codex:** `.codex/rules/*.rules` in a repo, and `$CODEX_HOME/rules/*.rules` (default `~/.codex/rules`) with `--home`. When you approve a command for good, Codex adds a `prefix_rule(pattern=[...], decision="allow")` line to `~/.codex/rules/default.rules`. That's in openai/codex at rust-v0.167.2, `codex-rs/core/src/exec_policy.rs` and `codex-rs/execpolicy/src/amend.rs`.

**Not Cursor yet.** Cursor's docs put permission rules in `~/.cursor/cli-config.json` and `.cursor/cli.json`, but they don't say that approving a command writes a rule there. We'll add it once that is confirmed.

## What it finds

- keys in about 30 formats with a fixed prefix (GitHub, GitLab, OpenAI, Anthropic, AWS, Google, Stripe, Slack, npm, PyPI, Hugging Face and others), JWTs and PEM private keys
- passwords after the flags that take one: `mysql -p`, `redis-cli -a`, `sshpass -p`, `docker login -p`, `zip -P`, `keytool -storepass`, `openssl -passout pass:`, and `--password`, `--token` or `--api-key` in any program
- values of variables named like a secret (`PGPASSWORD=`, `DB_PASSWORD=`, `OPENAI_API_KEY=`), but not `PASSWORD_FILE=` or `TOKEN_URL=`
- `user:password` in `curl -u`, in URLs, in `smbclient -U` and in `lftp -u`
- `Authorization`, `X-API-Key` and similar headers
- secrets in query strings, and long random-looking strings

It leaves alone values that only name a secret: `$DB_PASSWORD`, `${{ secrets.TOKEN }}`, `<password>`, `***`.

## What it misses

- a password after a flag of a program it doesn't know
- a short random key with no known prefix, no telling flag and no telling name
- secrets in Codex's `config.toml` or in `.mcp.json`, which it doesn't read yet

Claude Code's team said [on Hacker News](https://news.ycombinator.com/item?id=50407882) that they're looking into scrubbing secrets from these files. If that ships, you'll need less of this.

## Privacy

allowleak reads files and runs `git` on your machine. It makes no network calls and sends nothing anywhere. Output names where a credential is and what kind it is, never the value.

## Neighbours

- [gitleaks](https://github.com/gitleaks/gitleaks) and GitHub secret scanning cover a whole repo, for every kind of file. Keep them on.
- [Stroq](https://github.com/AGGIB/Stroq) reads your agent sessions for keys that left your machine. It also flags allow rules that are too broad, like `Bash(*)`.

allowleak does one narrower job: it reads the rules themselves for credentials.

## The numbers, yourself

```
GITLEAKS=/path/to/gitleaks node bench/gitleaks.js 10
```

The fixture is `test/fixture.js`. Every value is generated when it runs, so the repo holds no credential.

Node 18 or newer. Apache-2.0.

Made by the team behind [Commonly](https://commonly.me/?ref=allowleak).
