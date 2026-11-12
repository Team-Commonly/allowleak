// The fixture behind the README numbers: realistic agent allow rules that each carry a credential.
// Every value is generated at run time from parts; nothing secret-looking is stored here.
import { randomBytes } from 'node:crypto';
const AL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// Every generated value is recorded, so a test can check that no part of any of them is printed.
export const MADE = [];
const keep = (v) => { MADE.push(v); return v; };
const r = (n, al = AL) => keep(Array.from(randomBytes(n), (b) => al[b % al.length]).join(''));
const up = (n) => r(n, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0234567');
const digits = (n) => r(n, '0123456789');
const b64u = (s) => Buffer.from(s).toString('base64url');

export function fixture(pwStyle = "random") {
  MADE.length = 0;
  // pwStyle 'human': a person's password, built from parts. 'random': 20 random chars (gitleaks' best case).
  const pw = () => (pwStyle === 'human' ? ['Summer', 'Winter', 'Falcon'][randomBytes(1)[0] % 3] + digits(4) + '!' : r(20));
  const tok = [
    ['github-pat', `Bash(GH_TOKEN=${'ghp_' + r(36)} gh pr list:*)`],
    ['github-fine', `Bash(git push https://x-access-token:${'github_' + 'pat_' + r(22) + '_' + r(59)}@github.com/acme/app.git:*)`],
    ['openai', `Bash(OPENAI_API_KEY=${'sk-' + 'proj-' + r(74, AL + '_-') + 'T3Blbk' + 'FJ' + r(74, AL + '_-')} python eval.py:*)`],
    ['anthropic', `Bash(ANTHROPIC_API_KEY=${'sk-' + 'ant-api03-' + r(93, AL + '_-') + 'AA'} npm run agent:*)`],
    ['aws', `Bash(AWS_ACCESS_KEY_ID=${'AK' + 'IA' + up(16)} AWS_SECRET_ACCESS_KEY=${r(40, AL + '/+')} aws s3 ls:*)`],
    ['stripe', `Bash(curl https://api.stripe.com/v1/charges -u ${'sk_' + 'live_' + r(24)}::*)`],
    ['slack', `Bash(curl -X POST -H \"Authorization: Bearer ${'xo' + 'xb-' + digits(12) + '-' + digits(13) + '-' + r(24)}\" https://slack.com/api/chat.postMessage:*)`],
    ['google', `Bash(curl \"https://maps.googleapis.com/maps/api/geocode/json?key=${'AI' + 'za' + r(35, AL + '_-')}\":*)`],
    ['npm', `Bash(NPM_TOKEN=${'npm' + '_' + r(36)} npm publish:*)`],
    ['huggingface', `Bash(HF_TOKEN=${'hf' + '_' + r(34, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')} huggingface-cli upload:*)`],
    ['gitlab', `Bash(curl --header \"PRIVATE-TOKEN: ${'gl' + 'pat-' + r(20, AL + '_-')}\" https://gitlab.com/api/v4/projects:*)`],
    ['sendgrid', `Bash(SENDGRID_API_KEY=${'S' + 'G.' + r(22, AL + '_-') + '.' + r(43, AL + '_-')} node send.js:*)`],
    ['jwt', `Bash(curl -H \"Authorization: Bearer ${b64u('{"alg":"HS256","typ":"JWT"}')}.${b64u(`{"sub":"${r(8)}","exp":${digits(10)}}`)}.${r(43, AL + '_-')}\" https://api.acme.dev/me:*)`],
    ['pypi', `Bash(twine upload -u __token__ -p ${'pypi-' + 'AgEIcHlwaS5vcmc' + r(70, AL + '_-')} dist/*)`],
  ];
  const plain = [
    ['mysql-p', `Bash(mysql -u root -p${pw()} -e \"SHOW DATABASES\")`],
    ['mysql-password', `Bash(mysql --host=db.acme.dev --user=app --password=${pw()} app:*)`],
    ['pgpassword', `Bash(PGPASSWORD=${pw()} psql -h db.acme.dev -U app -d app:*)`],
    ['postgres-url', `Bash(psql \"postgresql://app:${pw()}@db.acme.dev:5432/app\":*)`],
    ['mongo-url', `Bash(mongosh \"mongodb+srv://app:${pw()}@cluster0.acme.mongodb.net/app\":*)`],
    ['redis-a', `Bash(redis-cli -h cache.acme.dev -a ${pw()} PING)`],
    ['sshpass', `Bash(sshpass -p '${pw()}' ssh deploy@10.0.0.5:*)`],
    ['curl-u', `Bash(curl -u admin:${pw()} https://jenkins.acme.dev/api/json:*)`],
    ['basic-auth', `Bash(curl -H \"Authorization: Basic ${keep(Buffer.from('admin:' + pw()).toString('base64'))}\" https://grafana.acme.dev/api/health)`],
    ['bearer-opaque', `Bash(curl -H \"Authorization: Bearer ${r(40)}\" https://api.acme.dev/v1/users:*)`],
    ['x-api-key', `Bash(curl -H \"X-API-Key: ${r(32)}\" https://api.acme.dev/v2/reports:*)`],
    ['query-key', `Bash(curl \"https://api.weather.acme.dev/v1/forecast?api_key=${r(32)}&q=SF\")`],
    ['docker-login', `Bash(docker login -u deploy -p ${pw()} registry.acme.dev)`],
    ['git-url-cred', `Bash(git clone https://deploy:${r(24)}@git.acme.dev/team/app.git)`],
    ['export-api-key', `Bash(export API_KEY=${r(32)} && npm run sync:*)`],
    ['env-db-password', `Bash(DB_PASSWORD=${pw()} npm run migrate:*)`],
    ['kubectl-token', `Bash(kubectl --token=${r(48)} --server=https://k8s.acme.dev get pods:*)`],
    ['helm-password', `Bash(helm repo add internal https://charts.acme.dev --username ci --password ${pw()})`],
    ['openssl-pass', `Bash(openssl pkcs12 -export -in cert.pem -inkey key.pem -passout pass:${pw()} -out cert.p12)`],
    ['zip-P', `Bash(zip -P ${pw()} backup.zip dump.sql)`],
    ['smbclient', `Bash(smbclient //nas.acme.dev/share -U admin%${pw()}:*)`],
    ['wget-password', `Bash(wget --user=admin --password=${pw()} https://files.acme.dev/release.tgz)`],
    ['az-login', `Bash(az login -u ci@acme.dev -p ${pw()})`],
    ['vercel-token', `Bash(vercel deploy --prod --token ${r(24)})`],
    ['mongodump-uri', `Bash(mongodump --uri \"mongodb://admin:${pw()}@db.acme.dev:27017/app\" --out backup)`],
    ['lftp', `Bash(lftp -u admin,${pw()} ftp.acme.dev:*)`],
    ['npm-config-set-eq', `Bash(npm config set //registry.npmjs.org/:_authToken=${r(36)} --location project)`],
    ['pnpm-config-set', `Bash(pnpm config set --global //npm.pkg.github.com/:_authToken ${'gh' + 'p_' + r(36)})`],
  ];
  const benign = [
    'Bash(npm run test:*)', 'Bash(git push origin main)', 'Bash(curl -s https://api.github.com/repos/acme/app/pulls)',
    'Bash(docker build -t acme/app:latest .)', 'Bash(psql -h localhost -U app -d app:*)', 'Bash(mysql -u root -e \"SHOW DATABASES\")',
    'Bash(kubectl get pods -n default)', 'Bash(export NODE_ENV=production && npm run build)', 'WebFetch(domain:docs.anthropic.com)',
    'Bash(git log --format=%H:*)', 'Bash(redis-cli -h localhost PING)', 'Bash(curl -H \"Accept: application/json\" https://api.acme.dev/health)',
  ];
  return { tok, plain, benign };
}

// Rules that look close to a credential and hold none. allowleak must stay quiet on every one.
export const NEAR_MISSES = [
  'Bash(psql -p 5432 -h localhost -U app)',
  'Bash(ssh -p 2222 deploy@10.0.0.5)',
  'Bash(mysql -u root -p)',
  'Bash(mysql -u root -p:*)',
  'Bash(curl -u $API_USER:$API_PASS https://jenkins.acme.dev/api/json)',
  'Bash(curl -u admin https://jenkins.acme.dev/api/json)',
  'Bash(PGPASSWORD=$PGPASSWORD psql -h db.acme.dev)',
  'Bash(export API_KEY=${API_KEY} && npm run sync)',
  'Bash(docker login -u deploy --password-stdin registry.acme.dev)',
  'Bash(git commit -m \"fix the password reset email\")',
  'Bash(grep -rn token src/)',
  'Bash(curl \"https://api.acme.dev/search?key=name&sort=asc\")',
  'Bash(curl -H \"Authorization: Bearer $TOKEN\" https://api.acme.dev/me)',
  'Bash(curl -H \"Authorization: Bearer ${{ secrets.TOKEN }}\" https://api.acme.dev/me)',
  'Bash(gh auth token)',
  'Bash(npm config get //registry.npmjs.org/:_authToken)',
  'Bash(git log --format=%H -n 1 a3f9c2e17b4d8e6f0a1b2c3d4e5f6a7b8c9d0e1f)',
  'Bash(PASSWORD_FILE=/run/secrets/db npm start)',
  'Bash(AUTH_MODE=oauth npm start)',
  'Bash(BYPASS_CACHE=1 npm test)',
  'Bash(ssh-keygen -t ed25519 -f ~/.ssh/deploy_key -N \"\")',
  'Bash(openssl rand -hex 32)',
  'Bash(aws sts get-caller-identity --profile prod)',
  'Bash(kubectl create secret generic db --from-literal=password=$DB_PASSWORD)',
  'Bash(zip -r out.zip dist)',
  'Bash(helm upgrade app ./chart --set image.tag=v1.2.3)',
  'Bash(http://localhost:3000/api)',
  'WebFetch(domain:docs.anthropic.com)',
  'WebFetch(https://user@example.com/docs)',
  'Read(./src/auth/password.ts)',
  'mcp__github__create_pull_request',
  'Bash(npx -y @modelcontextprotocol/server-github)',
  'Bash(python -m pytest tests/test_token_refresh.py)',
  'Bash(cat ~/.aws/credentials)',
  'Bash(gh secret set DEPLOY_TOKEN --env production)',
  'Bash(gh secret set DEPLOY_TOKEN --body "$TOKEN")',
  'Bash(gh secret set DEPLOY_TOKEN < token.txt)',
];
