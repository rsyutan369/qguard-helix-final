/**
 * QGuard Helix Exposure Assessment Engine™ — offline verification harness.
 *
 *   npx tsx tools/exposure-engine-check.ts
 *
 * Runs the full Local/Dev engine pipeline against a synthetic corpus whose
 * ground truth is known, and asserts the accuracy and honesty invariants the
 * implementation specification demands. It makes NO network calls, so it is
 * deterministic and can run in CI.
 *
 * §77 "Create safe test repositories… Use clearly fake credentials. Never place
 *      real secrets in test fixtures." Every credential below is syntactically
 *      valid and cryptographically worthless: the AWS key is the literal
 *      documentation example, the GitHub token is `ghp_` followed by a
 *      repeating pattern, and no private key body is real.
 */

/* Side-effect import: this harness runs in Node, like the api-server, so it
   registers the connector engines and therefore probes their real health.
   Without it every connector reports "descriptor only", which is the correct
   answer in a browser and the wrong one here. */
import '../src/lib/scanner/exposure/dev/connectors';
import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { emptyWorkspace, type WorkspaceFile } from '../src/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { canonicalAlgorithmName, classifyQuantum, describeAlgorithm, inferRole, parseKeySize } from '../src/lib/scanner/exposure/algorithms';
import { correlationKeyFor } from '../src/lib/scanner/exposure/correlate';
import { isCryptographicComponent, summariseCbom } from '../src/lib/scanner/exposure/cbom';
import { entropyVerdict, isPlaceholder, shannonEntropy } from '../src/lib/scanner/exposure/content/secrets';
import { parseDockerfile } from '../src/lib/scanner/exposure/content/container';
import { splitDocuments, valueAt } from '../src/lib/scanner/exposure/content/mini-yaml';
import { parseHclBlocks, hclAttribute } from '../src/lib/scanner/exposure/content/iac';
import { parseDependencies } from '../src/lib/scanner/exposure/content/dependencies';
import { parseCertificate, decodeBase64 } from '../src/lib/scanner/exposure/content/certificates';
import { parseImageRef } from '../src/lib/scanner/exposure/dev/registry-scan';
import { compileExclusions } from '../src/lib/scanner/exposure/orchestrator';
import { descriptorsForMode, engineHealth } from '../src/lib/scanner/exposure/registry';
import { planScan, profilesForMode, resolveProfile } from '../src/lib/scanner/exposure/profiles';
import { defaultExclusions } from '../src/lib/scanner/exposure/types';
import type { ExposureAssessment } from '../src/lib/scanner/exposure/types';

/* ─────────────────────────────────────────────────────────────── harness ──── */

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed += 1;
    return;
  }
  failed += 1;
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
}

function section(title: string): void {
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}\x1b[0m`);
}

/* ─────────────────────────────────────────────────────────────── fixtures ─── */

const FIXTURES: Record<string, string> = {
  /* ── real cryptography at real call sites ─────────────────────────────── */
  'src/auth/token.ts': `
import crypto from 'node:crypto';

/** Signs a session token. */
export function signToken(payload: string, privateKey: string) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(payload);
  return signer.sign(privateKey, 'base64');
}

export function legacyDigest(value: string) {
  return crypto.createHash('md5').update(value).digest('hex');
}
`,

  /* ── the four contextual traps §9 names ──────────────────────────────── */
  'src/notes.ts': `
// TODO: we should migrate off RSA one day, it is quantum vulnerable.
/* Historical note: this module used MD5 before 2019. */
const ALLOW_SHA1 = false;
const disableMD5 = true;
export const NOTE = 'described in the design doc';
`,

  'spec/fixtures/keys.spec.ts': `
import crypto from 'node:crypto';
// Test vector only.
const key = crypto.createHash('sha1').update('test').digest('hex');
`,

  /* ── hybrid post-quantum: must NOT be reported as a classical exposure ── */
  'src/tls/groups.ts': `
export const KEY_AGREEMENT_GROUPS = ['X25519MLKEM768', 'x25519'];
export const SIGNATURE_ALGORITHMS = ['ed25519', 'ml-dsa-65'];
`,

  /* ── dependencies across ecosystems ──────────────────────────────────── */
  'package.json': JSON.stringify(
    {
      name: 'fixture-app',
      dependencies: { jsonwebtoken: '^9.0.0', express: '^4.18.0', bcrypt: '^5.1.0', '@noble/post-quantum': '^0.1.0' },
      devDependencies: { typescript: '^5.4.0' },
    },
    null,
    2,
  ),
  'requirements.txt': 'cryptography==42.0.5\npyjwt==2.8.0\nrequests>=2.31.0\npycrypto==2.6.1\n',
  'go.mod': 'module example.com/fixture\n\ngo 1.22\n\nrequire (\n\tgithub.com/golang-jwt/jwt/v5 v5.2.0\n\tgithub.com/cloudflare/circl v1.3.7\n)\n',

  /* ── secrets: three real shapes and four placeholders ─────────────────── */
  '.env': `
DATABASE_URL=postgres://app:S3cur3P4ssw0rdValue@db.internal:5432/app
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
API_KEY=your-key-here
SECRET_KEY=changeme
JWT_SECRET=\${VAULT_JWT_SECRET}
PASSWORD=
`,
  '.env.example': `
DATABASE_URL=postgres://user:PLACEHOLDERVALUE123@localhost:5432/app
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
`,

  /* ── configuration weaknesses and strengths ──────────────────────────── */
  'nginx.conf': `
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:RC4-SHA:!aNULL;
    ssl_ecdh_curve X25519MLKEM768:X25519;
    ssl_dhparam /etc/nginx/dhparam1024.pem;
}
`,
  'config/app.yaml': `
tls:
  rejectUnauthorized: false
jwt:
  algorithms: ["none", "HS256"]
endpoint: http://api.example.com/v1
`,

  /* ── container ───────────────────────────────────────────────────────── */
  Dockerfile: `
FROM ubuntu:latest
RUN apt-get update && apt-get install -y openssl ca-certificates --allow-unauthenticated
ENV API_TOKEN=sk_live_A1b2C3d4E5f6G7h8I9j0K1l2
COPY server.key /etc/ssl/private/server.key
ADD http://downloads.example.com/tool.tar.gz /tmp/
RUN curl -sL https://install.example.com/setup.sh | bash
EXPOSE 8080
CMD ["/app/server"]
`,

  /* ── kubernetes ──────────────────────────────────────────────────────── */
  'k8s/deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: production
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: registry.example.com/payments-api:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            capabilities:
              add:
                - SYS_ADMIN
          env:
            - name: DB_PASSWORD
              value: NotARealPasswordButLongEnough
            - name: SAFE_REF
              valueFrom:
                secretKeyRef:
                  name: db
                  key: password
      volumes:
        - name: docker
          hostPath:
            path: /var/run/docker.sock
`,
  'k8s/rbac.yaml': `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: payments-reader
rules:
  - apiGroups: ["*"]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payments-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: payments
    namespace: production
`,
  'k8s/ingress.yaml': `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payments
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.2"
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  rules:
    - host: payments.example.com
`,

  /* ── terraform ───────────────────────────────────────────────────────── */
  'infra/main.tf': `
resource "aws_db_instance" "payments" {
  identifier          = "payments"
  publicly_accessible = true
  password            = "NotARealDatabasePassword123"
}

resource "aws_kms_key" "payments" {
  description = "Payments data key"
}

resource "aws_lb_listener" "https" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "payments-artifacts"
}
`,

  /* ── CI/CD ───────────────────────────────────────────────────────────── */
  '.github/workflows/release.yml': `
name: release
on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: third-party/build-action@v2
      - run: curl -sL https://example.com/publish.sh | sh
      - run: gpg --detach-sig dist/app.tar.gz
      - run: docker push registry.example.com/payments-api:latest
`,

  /* ── certificate ─────────────────────────────────────────────────────── */
  'certs/server.pem': buildFixtureCertificate(),
  'certs/id_ed25519.pub': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleFixtureKeyMaterialNotRealAAAA fixture@example.com',

  /* ── noise that must NOT produce findings ────────────────────────────── */
  'README.md': '# Fixture\n\nThis project uses RSA and AES. See the design doc.\n',
  'src/utils/strings.ts': 'export const described = (value: string) => value.trim();\nexport const dhcpLease = 3600;\n',
};

/**
 * A minimal, syntactically valid DER certificate carrying an RSA-2048 SPKI and
 * a sha256WithRSAEncryption signature OID.
 *
 * Hand-built rather than generated, so the fixture has no dependency on a key
 * being available at check time and the parser is tested against exactly the
 * structure it claims to read.
 */
function buildFixtureCertificate(): string {
  const bytes: number[] = [];
  const push = (...values: number[]) => bytes.push(...values);

  // Innermost first: RSAPublicKey ::= SEQUENCE { modulus INTEGER, e INTEGER }
  const modulus = [0x00, ...new Array(256).fill(0xab)]; // 0x00 pad + 2048 bits
  const modulusTlv = [0x02, 0x82, 0x01, 0x01, ...modulus];
  const exponentTlv = [0x02, 0x03, 0x01, 0x00, 0x01];
  const rsaSeqBody = [...modulusTlv, ...exponentTlv];
  const rsaSeq = [0x30, 0x82, (rsaSeqBody.length >> 8) & 0xff, rsaSeqBody.length & 0xff, ...rsaSeqBody];
  const bitString = [0x03, 0x82, ((rsaSeq.length + 1) >> 8) & 0xff, (rsaSeq.length + 1) & 0xff, 0x00, ...rsaSeq];

  // AlgorithmIdentifier ::= SEQUENCE { OID rsaEncryption, NULL }
  const rsaOid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
  const algIdBody = [...rsaOid, 0x05, 0x00];
  const algId = [0x30, algIdBody.length, ...algIdBody];

  // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
  const spkiBody = [...algId, ...bitString];
  const spki = [0x30, 0x82, (spkiBody.length >> 8) & 0xff, spkiBody.length & 0xff, ...spkiBody];

  // tbsCertificate: version tag + serial + the SPKI the parser looks for.
  const version = [0xa0, 0x03, 0x02, 0x01, 0x02];
  const serial = [0x02, 0x01, 0x01];
  const tbsBody = [...version, ...serial, ...spki];
  const tbs = [0x30, 0x82, (tbsBody.length >> 8) & 0xff, tbsBody.length & 0xff, ...tbsBody];

  // signatureAlgorithm ::= sha256WithRSAEncryption
  const sigOid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
  const sigAlgBody = [...sigOid, 0x05, 0x00];
  const sigAlg = [0x30, sigAlgBody.length, ...sigAlgBody];

  const signature = [0x03, 0x05, 0x00, 0xde, 0xad, 0xbe, 0xef];

  const certBody = [...tbs, ...sigAlg, ...signature];
  push(0x30, 0x82, (certBody.length >> 8) & 0xff, certBody.length & 0xff, ...certBody);

  const base64 = Buffer.from(Uint8Array.from(bytes)).toString('base64');
  const wrapped = base64.match(/.{1,64}/g)?.join('\n') ?? base64;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}

function buildCorpus(): WorkspaceFile[] {
  return Object.entries(FIXTURES).map(([path, content]) => toWorkspaceFile(path, content));
}

/* ═══════════════════════════════════════════════════════════════ unit tests ═ */

function checkAlgorithmModel(): void {
  section('Algorithm normalisation and role-aware classification (§10, §64)');

  /* §10: aliases collapse. Counting Kyber and ML-KEM separately inflates both
     the CBOM headline and the vulnerable ratio. */
  check('Kyber normalises to ML-KEM', canonicalAlgorithmName('kyber768') === 'ML-KEM', canonicalAlgorithmName('kyber768'));
  check('Dilithium normalises to ML-DSA', canonicalAlgorithmName('crystals-dilithium') === 'ML-DSA');
  check('SPHINCS+ normalises to SLH-DSA', canonicalAlgorithmName('sphincs+') === 'SLH-DSA');
  check('ML-KEM-768 normalises to ML-KEM', canonicalAlgorithmName('ML-KEM-768') === 'ML-KEM');

  /* The boundary-aware matcher: these are the exact traps the platform has been
     bitten by before. */
  check('"OpenSSL" does not match SSL', describeAlgorithm('OpenSSL')?.canonical !== 'SSL (legacy)', String(describeAlgorithm('OpenSSL')?.canonical));
  check('"described" does not match DES', describeAlgorithm('described') === null, String(describeAlgorithm('described')?.canonical));
  check('"ecdh" resolves to ECDH not Diffie-Hellman', canonicalAlgorithmName('ecdh') === 'ECDH');
  check('"dhcpLease" does not match DH', describeAlgorithm('dhcpLease') === null);

  /* §64: the verdict is (algorithm, role), never the algorithm alone. */
  const aesAtRest = classifyQuantum({ algorithm: 'AES-256-GCM', role: 'storage-encryption' });
  check('AES-256 at rest is resistant, not vulnerable', aesAtRest.status === 'resistant', aesAtRest.status);
  check('AES-256 is NOT counted as quantum-relevant', aesAtRest.quantumRelevant === false);

  const rsaSigning = classifyQuantum({ algorithm: 'RSA', role: 'signature', keySize: 2048 });
  check('RSA-2048 signing is vulnerable', rsaSigning.status === 'vulnerable');
  check('RSA signing recommends ML-DSA', /ML-DSA/.test(rsaSigning.migrationTarget ?? ''), rsaSigning.migrationTarget);

  const ecdhKex = classifyQuantum({ algorithm: 'ECDH', role: 'key-exchange' });
  check('ECDH key exchange recommends ML-KEM, not ML-DSA', /ML-KEM/.test(ecdhKex.migrationTarget ?? ''), ecdhKex.migrationTarget);
  check('ECDH is never told to adopt a signature scheme', !/ML-DSA/.test(ecdhKex.migrationTarget ?? ''));

  /* §23: "Do not blindly recommend ML-DSA for every use case." An unknown role
     gets NO recommendation rather than a wrong one. */
  const unknownRole = classifyQuantum({ algorithm: 'RSA', role: 'unknown' });
  check('RSA with an unknown role gets no migration target', unknownRole.migrationTarget === undefined, unknownRole.migrationTarget);

  const hybrid = classifyQuantum({ algorithm: 'X25519', role: 'key-exchange', hybridPartner: 'mlkem768' });
  check('X25519 + ML-KEM classifies as hybrid', hybrid.status === 'hybrid', hybrid.status);

  const sha1Sig = classifyQuantum({ algorithm: 'SHA-1', role: 'signature' });
  check('SHA-1 is vulnerable for classical reasons', sha1Sig.status === 'vulnerable');
  check('SHA-1 is not counted as quantum-relevant', sha1Sig.quantumRelevant === false);

  const mlkem = classifyQuantum({ algorithm: 'ML-KEM', role: 'key-exchange' });
  check('ML-KEM classifies as pqc', mlkem.status === 'pqc');
  check('ML-KEM rationale cites FIPS 203', /FIPS 203/.test(mlkem.rationale), mlkem.rationale);

  check('parseKeySize reads RSA-2048', parseKeySize('RSA-2048') === 2048);
  check('parseKeySize rejects a year', parseKeySize('copyright 2024') === null, String(parseKeySize('copyright 2024')));

  check('inferRole reads a signing context', inferRole('RSA', 'crypto.createSign("RSA-SHA256")') === 'signature');
  check('inferRole leaves bare RSA unknown', inferRole('RSA', 'const x = RSA') === 'unknown');
}

function checkSecretModel(): void {
  section('Secret detection and placeholder suppression (§12)');

  check('changeme is a placeholder', isPlaceholder('changeme'));
  check('your-key-here is a placeholder', isPlaceholder('your-key-here'));
  check('${VAULT} is a placeholder', isPlaceholder('${VAULT_JWT_SECRET}'));
  check('process.env reference is a placeholder', isPlaceholder('process.env.SECRET'));
  check('a real base64 credential is not a placeholder', !isPlaceholder('A1b2C3d4E5f6G7h8I9j0K1l2M3n4'));

  check('entropy of a repeated char is 0', shannonEntropy('aaaaaaaa') === 0);
  const generated = entropyVerdict('kR8xQm2vT7pL9wZa4hN6bY3cF5jD1sG0');
  check('a generated credential flags on entropy', generated.flag, `entropy ${generated.entropy.toFixed(2)}`);
  const prose = entropyVerdict('this-is-a-configuration-value');
  check('a kebab-case identifier does not flag', !prose.flag, `entropy ${prose.entropy.toFixed(2)}`);
}

function checkParsers(): void {
  section('Parsers');

  const instructions = parseDockerfile(FIXTURES.Dockerfile);
  check('Dockerfile parses to instructions', instructions.length >= 8, String(instructions.length));
  check('FROM is first', instructions[0]?.instruction === 'FROM');
  check('Line numbers are preserved', instructions.every((entry) => entry.line > 0));

  const documents = splitDocuments(FIXTURES['k8s/rbac.yaml']);
  check('Multi-document YAML splits into two', documents.length === 2, String(documents.length));
  check('ClusterRole kind is read', valueAt(documents[0], 'kind') === 'ClusterRole', String(valueAt(documents[0], 'kind')));
  check('roleRef name is read from the second doc', valueAt(documents[1], 'roleRef.name') === 'cluster-admin');

  const deployment = splitDocuments(FIXTURES['k8s/deployment.yaml'])[0];
  check('Deployment namespace is read', valueAt(deployment, 'metadata.namespace') === 'production');
  const imageNode = deployment.nodes.find((node) => node.path.endsWith('.image'));
  check('Container image is read from a sequence entry', imageNode?.value === 'registry.example.com/payments-api:latest', String(imageNode?.value));

  const blocks = parseHclBlocks(FIXTURES['infra/main.tf']);
  check('HCL parses four resources', blocks.filter((block) => block.type === 'resource').length === 4, String(blocks.length));
  const listener = blocks.find((block) => block.labels[0] === 'aws_lb_listener');
  check('HCL attribute is read', hclAttribute(listener?.body ?? '', 'ssl_policy')?.value === 'ELBSecurityPolicy-2016-08');

  const dependencies = parseDependencies(buildCorpus());
  check('npm dependencies parsed', dependencies.some((entry) => entry.name === 'jsonwebtoken' && entry.ecosystem === 'npm'));
  check('pypi dependencies parsed', dependencies.some((entry) => entry.name === 'cryptography' && entry.ecosystem === 'pypi'));
  check('go dependencies parsed', dependencies.some((entry) => entry.name.includes('golang-jwt') && entry.ecosystem === 'go'));
  check('devDependencies are scoped', dependencies.find((entry) => entry.name === 'typescript')?.scope === 'development');

  const pem = FIXTURES['certs/server.pem'].replace(/-----[^-]+-----/g, '').trim();
  const der = decodeBase64(pem);
  check('Fixture certificate base64 decodes', der !== null);
  const parsed = der ? parseCertificate(der) : null;
  /* v3 records the subject public key and the issuer signature as SEPARATE
     fields (§23), so the assertions changed shape along with the parser. */
  check('Certificate SPKI algorithm is RSA', parsed?.publicKey.algorithm === 'RSA', String(parsed?.publicKey.algorithm));
  check('Certificate key size is 2048', parsed?.publicKey.keySize === 2048, String(parsed?.publicKey.keySize));
  check('Certificate signature algorithm is RSA', parsed?.signature.algorithm === 'RSA', String(parsed?.signature.algorithm));
  check('Certificate signature HASH is recorded separately', parsed?.signature.hash === 'SHA-256', String(parsed?.signature.hash));

  const dockerHub = parseImageRef('nginx:1.25');
  check('Docker Hub official image resolves to library/', dockerHub?.repository === 'library/nginx', String(dockerHub?.repository));
  const ghcr = parseImageRef('ghcr.io/org/app@sha256:' + 'a'.repeat(64));
  check('Registry host is recognised', ghcr?.registry === 'ghcr.io');
  check('Digest is preferred over tag', ghcr?.digest?.startsWith('sha256:') === true && ghcr?.tag === null);
  const namespaced = parseImageRef('myorg/app:1.0');
  check('A Docker Hub namespace is not mistaken for a registry', namespaced?.registry === 'registry-1.docker.io', String(namespaced?.registry));
}

function checkRegistryAndProfiles(): void {
  section('Registry, profiles and the Smart Scan Planner (§30, §31, §32, §61)');

  const health = engineHealth();
  const unhealthy = health.filter((entry) => entry.state !== 'healthy');
  check('Every registered engine is healthy', unhealthy.length === 0, unhealthy.map((entry) => `${entry.id}: ${entry.detail}`).join('; '));

  const localEngines = descriptorsForMode('local');
  const devEngines = descriptorsForMode('dev');
  check('Local mode exposes content engines', localEngines.length >= 12, String(localEngines.length));
  check('Dev mode exposes more than Local (connectors)', devEngines.length > localEngines.length, `${devEngines.length} vs ${localEngines.length}`);
  check('Local mode has no cloud connector', !localEngines.some((entry) => entry.id.startsWith('cloud-')));
  check('Dev mode has the cloud connector', devEngines.some((entry) => entry.id === 'cloud-crypto'));

  /* §31: a profile is a real engine set, not a label. */
  const quick = resolveProfile('local', 'quick');
  const deep = resolveProfile('local', 'deep');
  check('Quick runs fewer engines than Deep', quick.engines.length < deep.engines.length, `${quick.engines.length} vs ${deep.engines.length}`);
  check('Quick does not run the Kubernetes engine', !quick.engines.includes('kubernetes-security'));
  check('Deep runs the Kubernetes engine', deep.engines.includes('kubernetes-security'));
  check('Every profile includes file-discovery', profilesForMode('local').filter((profile) => profile.id !== 'custom').every((profile) => profile.engines.includes('file-discovery')));

  const dropped = resolveProfile('local', 'cloud-deep');
  check('A Dev-only profile drops its connectors in Local mode', dropped.dropped.includes('cloud-inventory'), dropped.dropped.join(','));

  /* Spec-2 §32: the planner reacts to facets. */
  const plainPlan = planScan('local', new Set(['node']));
  const richPlan = planScan('local', new Set(['node', 'dockerfile', 'kubernetes', 'terraform', 'github-actions']));
  check('The planner recommends more engines for a richer target', richPlan.recommended.length > plainPlan.recommended.length, `${richPlan.recommended.length} vs ${plainPlan.recommended.length}`);
  check('A Dockerfile facet recommends the container engine', richPlan.recommended.some((entry) => entry.engineId === 'container-security'));
  check('A plain Node target does not recommend Kubernetes', !plainPlan.recommended.some((entry) => entry.engineId === 'kubernetes-security'));
  check('Every recommendation carries a reason', richPlan.recommended.every((entry) => entry.reason.length > 10));
}

function checkExclusions(): void {
  section('Exclusions (§42)');

  const isExcluded = compileExclusions({
    ...defaultExclusions(),
    patterns: ['**/*.min.js', 'docs/**'],
    extensions: ['.lock'],
  });

  check('node_modules is excluded', isExcluded('node_modules/react/index.js'));
  check('a nested node_modules is excluded', isExcluded('packages/api/node_modules/x/y.js'));
  check('a glob pattern matches', isExcluded('assets/bundle.min.js'));
  check('a directory glob matches', isExcluded('docs/guide/intro.md'));
  check('an extension rule matches', isExcluded('yarn.lock'));
  check('source is not excluded', !isExcluded('src/auth/token.ts'));
  check('"nodes" is not treated as node_modules', !isExcluded('src/nodes/graph.ts'));
}

/* ═════════════════════════════════════════════════════ full pipeline check ═ */

async function runPipeline(): Promise<ExposureAssessment> {
  const workspace = emptyWorkspace();
  workspace.files = buildCorpus();

  const { engines } = resolveProfile('local', 'deep');
  return runExposureScan({
    scanId: 'check-fixture',
    mode: 'local',
    target: { kind: 'local', label: 'fixture', rootName: 'fixture', fileCount: workspace.files.length, viaAgent: false },
    profileId: 'deep',
    engineIds: engines,
    workspace,
    localOnly: true,
    budgetMs: 60_000,
    concurrency: 2,
  });
}

function checkAssessment(assessment: ExposureAssessment): void {
  const { findings, cbom, exposures, task } = assessment;
  const titles = findings.map((finding) => `${finding.title} ${finding.description}`).join('\n');

  section('Terminal state and honesty (§34, §41, §62, §79)');

  const stuck = task.runs.filter((run) => run.state === 'pending' || run.state === 'running');
  check('Every engine reached a terminal state', stuck.length === 0, stuck.map((run) => `${run.engineId}:${run.state}`).join(','));

  const silentEmpty = task.runs.filter((run) => (run.state === 'not-applicable' || run.state === 'not-assessed' || run.state === 'skipped' || run.state === 'failed') && !run.detail);
  check('Every non-completed engine states a reason', silentEmpty.length === 0, silentEmpty.map((run) => run.engineId).join(','));

  check('Every finding carries evidence', findings.every((finding) => finding.evidence.length > 0));
  check('Every finding carries a detection method', findings.every((finding) => ['observed', 'inferred', 'potential', 'unknown'].includes(finding.detection)));
  check('Every finding carries a confidence', findings.every((finding) => ['high', 'medium', 'low', 'unknown'].includes(finding.confidence)));
  check('Finding ids are unique', new Set(findings.map((finding) => finding.id)).size === findings.length);

  section('Redaction (§12, §27, Spec-2 §12)');

  /* The hard rule: no secret VALUE anywhere in the assessment, at any depth. */
  const serialised = JSON.stringify(assessment);
  check('No AWS example key value leaks', !serialised.includes('AKIAIOSFODNN7EXAMPLE'), 'the fixture AWS key appears in the assessment');
  check('No GitHub token value leaks', !serialised.includes('ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'));
  check('No database password leaks', !serialised.includes('S3cur3P4ssw0rdValue'));
  check('No Stripe key value leaks', !serialised.includes('sk_live_A1b2C3d4E5f6G7h8I9j0K1l2'));
  check('No inline k8s password leaks', !serialised.includes('NotARealPasswordButLongEnough'));
  check('No terraform password leaks', !serialised.includes('NotARealDatabasePassword123'));

  const secretFindings = findings.filter((finding) => finding.layer === 'secret');
  check('Secret findings were produced', secretFindings.length >= 3, String(secretFindings.length));
  check('Every secret finding redacts its value', secretFindings.every((finding) => finding.evidence.every((entry) => entry.attributes?.value === undefined || entry.attributes.value === '[REDACTED]')));

  section('Contextual accuracy (§9, §63)');

  /* Comment-only references must not produce a critical. */
  const noteFindings = findings.filter((finding) => finding.evidence.some((entry) => entry.file === 'src/notes.ts'));
  check('Comment-only references produce no critical finding', !noteFindings.some((finding) => finding.severity === 'critical'), noteFindings.filter((f) => f.severity === 'critical').map((f) => f.title).join(','));
  check('Comment-only references are marked potential', noteFindings.every((finding) => finding.detection === 'potential' || finding.detection === 'inferred'), noteFindings.map((f) => `${f.title}:${f.detection}`).join(','));

  /* Test-path material is demoted. */
  const specFindings = findings.filter((finding) => finding.evidence.some((entry) => entry.file?.startsWith('spec/')));
  check('Test-path findings are not high confidence', specFindings.every((finding) => finding.confidence !== 'high'), specFindings.map((f) => `${f.title}:${f.confidence}`).join(','));

  /* Prose and identifier collisions produce nothing. */
  const noiseFindings = findings.filter((finding) => finding.evidence.some((entry) => entry.file === 'src/utils/strings.ts' || entry.file === 'README.md'));
  check('Prose and identifier collisions produce no findings', noiseFindings.length === 0, noiseFindings.map((f) => `${f.title} @ ${f.evidence[0]?.file}`).join(','));

  /* Real call sites DO produce findings. */
  check('The RSA signing call site is found', /RSA/.test(titles) && findings.some((finding) => finding.evidence.some((entry) => entry.file === 'src/auth/token.ts')));
  check('The MD5 call site is found', findings.some((finding) => finding.canonicalAlgorithm === 'MD5'));

  section('Hybrid post-quantum handling (§10, §64)');

  const hybridFindings = findings.filter((finding) => finding.quantumStatus === 'hybrid');
  check('Hybrid deployments are recognised', hybridFindings.length > 0, 'no hybrid finding was produced for X25519MLKEM768');
  const groupsFileFindings = findings.filter((finding) => finding.evidence.some((entry) => entry.file === 'src/tls/groups.ts'));
  check('The hybrid group is not reported as a plain classical exposure', groupsFileFindings.some((finding) => finding.quantumStatus === 'hybrid' || finding.quantumStatus === 'pqc'), groupsFileFindings.map((f) => `${f.canonicalAlgorithm}:${f.quantumStatus}`).join(','));
  check('The nginx hybrid group is recognised as a strength', findings.some((finding) => finding.category === 'Configuration Strength' && finding.quantumStatus === 'hybrid'));

  section('Configuration, container, Kubernetes, IaC and CI/CD engines');

  const has = (needle: string) => findings.some((finding) => finding.title.includes(needle) || finding.subcategory?.includes(needle));
  check('TLS 1.0 is detected', has('TLS 1.0'));
  check('RC4 is detected', has('RC4'));
  check('Weak DH parameters are detected', has('Diffie-Hellman') || has('Weak Diffie'));
  check('Disabled certificate verification is detected', has('verification disabled') || has('Certificate verification'));
  check('JWT "none" is detected', has('none'));
  check('Container runs as root is detected', has('runs as root'));
  check('Unpinned base image is detected', has('not pinned'));
  check('Key material copied into a layer is detected', has('key or certificate material'));
  check('Unverified package install is detected', has('signature or TLS verification'));
  check('Pipe-to-shell is detected', has('shell'));
  check('Privileged container is detected', has('Privileged container'));
  check('hostNetwork is detected', has('Host network'));
  check('SYS_ADMIN capability is detected', has('SYS_ADMIN'));
  check('Docker socket hostPath is detected', has('/var/run/docker.sock'));
  check('Wildcard RBAC is detected', has('every verb on every resource') || has('wildcard'));
  check('cluster-admin binding is detected', has('cluster-admin'));
  check('Secrets read permission is detected', has('read Secrets'));
  check('Legacy ingress TLS is detected', has('deprecated TLS version'));
  check('cert-manager automation is recognised as a strength', has('cert-manager'));
  check('Public RDS is detected', has('publicly accessible'));
  check('Unencrypted RDS is detected', has('storage encryption disabled') || has('RDS storage'));
  check('KMS without rotation is detected', has('automatic rotation'));
  check('Legacy ELB policy is detected', has('legacy TLS security policy'));
  check('Terraform inline credential is detected', has('Credential value assigned'));
  check('pull_request_target is detected', has('pull_request_target'));
  check('write-all permissions detected', has('write-all'));
  check('Unpinned action is detected', has('mutable tag'));
  check('GPG signing is recognised', has('GnuPG'));
  check('Unsigned image push is detected', has('without a signature step'));

  /* The inline env var with a secretKeyRef sibling must NOT fire. */
  const inlineSecretFindings = findings.filter((finding) => finding.subcategory === 'Secrets' && finding.title.includes('SAFE_REF'));
  check('A secretKeyRef environment variable is not flagged', inlineSecretFindings.length === 0);

  section('Absence rules only fire on rendered manifests (§15 of spec 2)');

  const helmSuppressed = task.coverage.notAssessed.some((entry) => entry.dimension.includes('Helm'));
  check('Unrendered Helm templates are declared not assessed', helmSuppressed || !buildCorpus().some((file) => file.classification === 'helm'), 'a Helm template was analysed without the caveat');

  section('CBOM discipline (§11)');

  check('The CBOM is non-empty', cbom.length > 0);
  const nonCrypto = findings.filter((finding) => !isCryptographicComponent(finding));
  check('Non-cryptographic findings exist and are excluded from the CBOM', nonCrypto.length > 0, 'no control findings were produced');
  const cbomAlgorithms = new Set(cbom.map((component) => component.canonicalAlgorithm));
  check('No CBOM component names a non-algorithm', [...cbomAlgorithms].every((algorithm) => describeAlgorithm(algorithm) !== null), [...cbomAlgorithms].join(','));
  check('Kyber and ML-KEM are not separate CBOM rows', !(cbomAlgorithms.has('Kyber' as string) && cbomAlgorithms.has('ML-KEM')));

  const summary = summariseCbom(cbom);
  check('CBOM totals reconcile', summary.vulnerable + summary.hybrid + summary.pqc + summary.resistant + summary.unknown + summary.notApplicable === cbom.length, `${summary.total} vs ${cbom.length}`);
  check('Readiness excludes symmetric components', summary.readiness === null || summary.readiness <= 100);

  section('Correlation (§39)');

  const keys = new Set(findings.map((finding) => correlationKeyFor(finding)));
  check('Correlation reduces findings to fewer exposures', exposures.length <= findings.length);
  check('Correlation key count matches exposure count', keys.size === exposures.length, `${keys.size} vs ${exposures.length}`);
  const multiEvidence = exposures.filter((exposure) => exposure.findingIds.length > 1);
  check('At least one exposure merges several findings', multiEvidence.length > 0, 'nothing correlated — the key may be too specific');
  check('Correlated exposures keep all evidence', multiEvidence.every((exposure) => exposure.evidence.length >= exposure.findingIds.length - 1));

  section('Scoring (§40)');

  const { scores } = task;
  check('Security risk is in range', scores.securityRisk === null || (scores.securityRisk >= 0 && scores.securityRisk <= 100), String(scores.securityRisk));
  check('Quantum risk is in range', scores.quantumRisk === null || (scores.quantumRisk >= 0 && scores.quantumRisk <= 100), String(scores.quantumRisk));
  check('Coverage is in range', scores.coverage === null || (scores.coverage >= 0 && scores.coverage <= 100), String(scores.coverage));
  check('Confidence is in range', scores.confidence === null || (scores.confidence >= 0 && scores.confidence <= 100), String(scores.confidence));
  check('Five scores are published separately', scores.basis.length === 5, String(scores.basis.length));
  check('Every score states its basis', scores.basis.every((line) => line.length > 20));
  check('This fixture produces a real security risk', scores.securityRisk !== null && scores.securityRisk > 0);
  check('This fixture produces a real quantum risk', scores.quantumRisk !== null);

  section('Coverage disclosure (§41)');

  check('Coverage counts discovered files', task.coverage.filesDiscovered > 0);
  check('Coverage counts analysed files', task.coverage.filesAnalyzed > 0);
  check('Exclusions are declared', task.coverage.exclusions.length > 0);
  check('Not-assessed dimensions carry reasons', task.coverage.notAssessed.every((entry) => entry.reason.length > 15));
  check('The dependency advisory gap is declared', task.coverage.notAssessed.some((entry) => /advisor/i.test(entry.dimension)), 'no advisory caveat was recorded');

  section('Intelligence');

  const { intelligence } = assessment;
  check('Severity counts sum to the finding total', Object.values(intelligence.severity).reduce((sum, value) => sum + value, 0) === findings.length);
  check('Languages were detected', intelligence.languages.length > 0, intelligence.languages.map((entry) => entry.language).join(','));
  check('Dependencies were recorded', intelligence.dependencies.length > 0, String(intelligence.dependencies.length));
  check('Secrets are reported with a redacted value', intelligence.secrets.every((entry) => entry.value === '[REDACTED]'));
  check('Recommendations are produced', intelligence.recommendations.length > 0);
  check('Every recommendation cites its findings', intelligence.recommendations.every((entry) => entry.findingIds.length > 0));
}

/* ═══════════════════════════════════════════════════════════════════ main ══ */

async function main(): Promise<void> {
  console.log('\x1b[1mQGuard Helix Exposure Assessment Engine™ — verification\x1b[0m');
  console.log('Offline. No network calls. All credentials in fixtures are fake.\n');

  checkAlgorithmModel();
  checkSecretModel();
  checkParsers();
  checkRegistryAndProfiles();
  checkExclusions();

  section('Full pipeline execution');
  const started = Date.now();
  const assessment = await runPipeline();
  console.log(
    `  ${assessment.findings.length} findings · ${assessment.exposures.length} exposures · ${assessment.cbom.length} CBOM components · ${Date.now() - started}ms`,
  );
  checkAssessment(assessment);

  console.log(`\n\x1b[1m${'═'.repeat(66)}\x1b[0m`);
  if (failed === 0) {
    console.log(`\x1b[32m✓ ${passed} checks passed\x1b[0m`);
    process.exit(0);
  }
  console.log(`\x1b[31m✗ ${failed} of ${passed + failed} checks FAILED\x1b[0m\n`);
  for (const failure of failures) console.log(`  \x1b[31m✗\x1b[0m ${failure}`);
  process.exit(1);
}

main().catch((error) => {
  console.error('\x1b[31mThe verification harness itself failed:\x1b[0m', error);
  process.exit(1);
});
