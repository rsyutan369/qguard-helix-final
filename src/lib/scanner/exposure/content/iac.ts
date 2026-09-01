/**
 * Infrastructure-as-Code Security Engine™ (Spec-2 §17).
 *
 * Terraform / OpenTofu, CloudFormation, Azure Bicep and ARM, Pulumi and
 * Ansible. The findings are deliberately weighted toward the cryptographic
 * questions the platform exists to answer — encryption at rest, key management,
 * TLS policy, certificate issuance — with the classic exposure rules (public
 * storage, open security groups, weak IAM) alongside them because they are what
 * turns a cryptographic weakness into an incident.
 *
 * HCL is read as a resource-block stream rather than fully parsed: the block
 * header gives the resource type and name, and the attributes inside give the
 * settings. That is enough for every rule here, keeps the module isomorphic,
 * and — critically — preserves line numbers.
 */

import type { CryptoRole, FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';

/* ───────────────────────────────────────────────────────────── HCL reading ── */

export interface HclBlock {
  /** `resource`, `data`, `module`, `provider`, `variable`… */
  type: string;
  /** Quoted labels after the type. */
  labels: string[];
  startLine: number;
  endLine: number;
  body: string;
}

/** Split an HCL document into top-level blocks with their line spans. */
export function parseHclBlocks(content: string): HclBlock[] {
  const lines = content.split('\n');
  const blocks: HclBlock[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    const header = line.match(/^\s*([a-z_][a-z0-9_]*)\s*((?:"[^"]*"\s*)*)\{\s*$/i);
    if (!header) {
      index += 1;
      continue;
    }

    const type = header[1];
    const labels = [...header[2].matchAll(/"([^"]*)"/g)].map((match) => match[1]);
    const startLine = index + 1;
    let depth = 1;
    const body: string[] = [];
    index += 1;

    while (index < lines.length && depth > 0) {
      const current = lines[index];
      // Brace counting outside strings and comments is close enough for HCL:
      // a `{` inside a string is rare and only ever ends a block early, which
      // truncates one block rather than corrupting the stream.
      const stripped = current.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/#.*$|\/\/.*$/, '');
      depth += (stripped.match(/\{/g) ?? []).length;
      depth -= (stripped.match(/\}/g) ?? []).length;
      if (depth > 0) body.push(current);
      index += 1;
    }

    blocks.push({ type, labels, startLine, endLine: index, body: body.join('\n') });
  }

  return blocks;
}

/** Read a scalar attribute out of an HCL body, with its line offset. */
export function hclAttribute(body: string, name: string): { value: string; lineOffset: number } | null {
  const lines = body.split('\n');
  const pattern = new RegExp(`^\\s*${name}\\s*=\\s*(.+?)\\s*$`);
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (!match) continue;
    return { value: match[1].replace(/^["']|["'],?$/g, '').trim(), lineOffset: index + 1 };
  }
  return null;
}

/** True when the body contains a nested block of the given name. */
export function hclHasBlock(body: string, name: string): boolean {
  return new RegExp(`^\\s*${name}\\s*(\\{|=\\s*\\{)`, 'm').test(body);
}

/* ────────────────────────────────────────────────────────── Terraform rules ── */

interface IacRule {
  id: string;
  /** Terraform resource types this applies to. `*` = every resource. */
  resources: string[];
  title: string;
  severity: FindingSeverity;
  role: CryptoRole;
  algorithm?: string;
  /** Return a description when the rule fires, otherwise null. */
  evaluate: (block: HclBlock) => { description: string; line: number; snippet?: string } | null;
  recommendation: string;
}

const TERRAFORM_RULES: IacRule[] = [
  {
    id: 'iac-s3-unencrypted',
    resources: ['aws_s3_bucket'],
    title: 'S3 bucket declares no server-side encryption',
    severity: 'high',
    role: 'storage-encryption',
    algorithm: 'AES',
    evaluate: (block) =>
      hclHasBlock(block.body, 'server_side_encryption_configuration')
        ? null
        : {
            description:
              'The bucket resource declares no server_side_encryption_configuration block. S3 has applied SSE-S3 by default since January 2023, so data is very likely encrypted — but the configuration does not STATE it, which means the encryption posture is inherited rather than governed, and a bucket policy change cannot be reviewed against a declared intent.',
            line: block.startLine,
          },
    recommendation: 'Declare an aws_s3_bucket_server_side_encryption_configuration resource with a customer-managed KMS key so the intent is explicit and auditable.',
  },
  {
    id: 'iac-s3-public',
    resources: ['aws_s3_bucket_public_access_block'],
    title: 'S3 public access block is disabled',
    severity: 'critical',
    role: 'unknown',
    evaluate: (block) => {
      const keys = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'];
      const disabled = keys.filter((key) => hclAttribute(block.body, key)?.value === 'false');
      if (disabled.length === 0) return null;
      return {
        description: `The public access block disables ${disabled.join(', ')}, which permits the bucket to be made publicly readable or writable by an ACL or bucket policy.`,
        line: block.startLine + (hclAttribute(block.body, disabled[0])?.lineOffset ?? 0),
      };
    },
    recommendation: 'Set every block_* and restrict_public_buckets attribute to true unless the bucket is a deliberate public asset host.',
  },
  {
    id: 'iac-sg-open-ingress',
    resources: ['aws_security_group', 'aws_security_group_rule', 'aws_vpc_security_group_ingress_rule'],
    title: 'Security group allows ingress from the entire Internet',
    severity: 'high',
    role: 'unknown',
    evaluate: (block) => {
      if (!/0\.0\.0\.0\/0|::\/0/.test(block.body)) return null;
      const lines = block.body.split('\n');
      const lineIndex = lines.findIndex((line) => /0\.0\.0\.0\/0|::\/0/.test(line));
      // An egress-only 0.0.0.0/0 is normal; ingress is the exposure.
      const isIngress = /ingress/.test(block.body) || block.labels.some((label) => /ingress/.test(label)) || /\bfrom_port\b/.test(block.body);
      if (!isIngress) return null;
      const port = hclAttribute(block.body, 'from_port')?.value ?? hclAttribute(block.body, 'to_port')?.value;
      return {
        description: `The security group permits ingress from 0.0.0.0/0${port ? ` on port ${port}` : ''}. Anything listening behind it is reachable from the entire Internet, so its transport cryptography is the only remaining control.`,
        line: block.startLine + lineIndex + 1,
        snippet: lines[lineIndex],
      };
    },
    recommendation: 'Restrict cidr_blocks to the networks that require access, and place Internet-facing services behind a load balancer that terminates TLS.',
  },
  {
    id: 'iac-rds-unencrypted',
    resources: ['aws_db_instance', 'aws_rds_cluster'],
    title: 'RDS storage encryption disabled',
    severity: 'critical',
    role: 'database-encryption',
    algorithm: 'AES',
    evaluate: (block) => {
      const encrypted = hclAttribute(block.body, 'storage_encrypted');
      if (encrypted && encrypted.value !== 'false') return null;
      return {
        description: encrypted
          ? 'storage_encrypted is explicitly false, so the database volume and its snapshots are stored unencrypted.'
          : 'storage_encrypted is not declared. It defaults to false for this resource, so the database volume and every snapshot taken from it are stored unencrypted.',
        line: block.startLine + (encrypted?.lineOffset ?? 0),
      };
    },
    recommendation: 'Set storage_encrypted = true and supply a customer-managed kms_key_id. Encryption cannot be enabled in place — it requires a snapshot-and-restore.',
  },
  {
    id: 'iac-rds-public',
    resources: ['aws_db_instance'],
    title: 'RDS instance is publicly accessible',
    severity: 'critical',
    role: 'unknown',
    evaluate: (block) => {
      const attribute = hclAttribute(block.body, 'publicly_accessible');
      if (attribute?.value !== 'true') return null;
      return {
        description: 'publicly_accessible is true, so the database is assigned a public endpoint reachable from outside the VPC.',
        line: block.startLine + attribute.lineOffset,
      };
    },
    recommendation: 'Set publicly_accessible = false and reach the database through a bastion, VPN or private endpoint.',
  },
  {
    id: 'iac-ebs-unencrypted',
    resources: ['aws_ebs_volume', 'aws_instance'],
    title: 'EBS volume encryption not declared',
    severity: 'high',
    role: 'storage-encryption',
    algorithm: 'AES',
    evaluate: (block) => {
      if (block.labels[0] === 'aws_instance' && !hclHasBlock(block.body, 'root_block_device') && !hclHasBlock(block.body, 'ebs_block_device')) return null;
      const encrypted = hclAttribute(block.body, 'encrypted');
      if (encrypted && encrypted.value !== 'false') return null;
      return {
        description: encrypted
          ? 'encrypted is explicitly false, so the block device is stored unencrypted.'
          : 'No `encrypted` attribute is declared on the block device, so the volume relies on the account-level default rather than a stated policy.',
        line: block.startLine + (encrypted?.lineOffset ?? 0),
      };
    },
    recommendation: 'Set encrypted = true and reference a customer-managed KMS key.',
  },
  {
    id: 'iac-kms-no-rotation',
    resources: ['aws_kms_key'],
    title: 'KMS key does not have automatic rotation enabled',
    severity: 'medium',
    role: 'key-management',
    algorithm: 'AES',
    evaluate: (block) => {
      const rotation = hclAttribute(block.body, 'enable_key_rotation');
      if (rotation?.value === 'true') return null;
      return {
        description:
          'enable_key_rotation is not true, so the key material is never rotated automatically. Long-lived key material increases the volume of data protected by a single key, which is precisely what harvest-now-decrypt-later exploits.',
        line: block.startLine + (rotation?.lineOffset ?? 0),
      };
    },
    recommendation: 'Set enable_key_rotation = true. Rotation is the operational muscle a post-quantum key migration will depend on.',
  },
  {
    id: 'iac-kms-rotation-enabled',
    resources: ['aws_kms_key'],
    title: 'KMS key rotation is enabled',
    severity: 'info',
    role: 'key-management',
    evaluate: (block) => {
      const rotation = hclAttribute(block.body, 'enable_key_rotation');
      if (rotation?.value !== 'true') return null;
      return {
        description: 'Automatic key rotation is enabled, which is the operational capability a post-quantum key migration depends on.',
        line: block.startLine + rotation.lineOffset,
      };
    },
    recommendation: 'Confirm the rotation period matches the data retention requirement for what the key protects.',
  },
  {
    id: 'iac-lb-weak-tls-policy',
    resources: ['aws_lb_listener', 'aws_alb_listener', 'aws_elb'],
    title: 'Load balancer uses a legacy TLS security policy',
    severity: 'high',
    role: 'tls',
    algorithm: 'TLS',
    evaluate: (block) => {
      const policy = hclAttribute(block.body, 'ssl_policy');
      if (!policy) return null;
      const value = policy.value;
      if (!/2015|2016|TLS-1-0|TLS-1-1|ELBSecurityPolicy-2015|ELBSecurityPolicy-2016/i.test(value)) return null;
      return {
        description: `ssl_policy is "${value}", which permits TLS 1.0 or 1.1 and legacy cipher suites. A listener on this policy cannot negotiate a hybrid post-quantum key-agreement group.`,
        line: block.startLine + policy.lineOffset,
        snippet: `ssl_policy = "${value}"`,
      };
    },
    recommendation: 'Move to ELBSecurityPolicy-TLS13-1-2-2021-06 or later, which requires TLS 1.2 and enables TLS 1.3.',
  },
  {
    id: 'iac-lb-plaintext-listener',
    resources: ['aws_lb_listener', 'aws_alb_listener'],
    title: 'Load balancer listener terminates plaintext HTTP',
    severity: 'medium',
    role: 'tls',
    algorithm: 'TLS',
    evaluate: (block) => {
      const protocol = hclAttribute(block.body, 'protocol');
      if (protocol?.value !== 'HTTP') return null;
      // A redirect listener on :80 is the correct pattern, not a finding.
      if (/type\s*=\s*"redirect"/.test(block.body)) return null;
      return {
        description: 'The listener protocol is HTTP with no redirect action, so traffic to it is unencrypted end to end.',
        line: block.startLine + protocol.lineOffset,
      };
    },
    recommendation: 'Change the listener to HTTPS, or add a redirect action to the HTTPS listener.',
  },
  {
    id: 'iac-iam-wildcard',
    resources: ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy'],
    title: 'IAM policy grants wildcard actions on wildcard resources',
    severity: 'critical',
    role: 'unknown',
    evaluate: (block) => {
      const hasWildcardAction = /"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/.test(block.body) || /Action\s*=\s*\[?\s*"\*"/.test(block.body);
      const hasWildcardResource = /"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/.test(block.body) || /Resource\s*=\s*\[?\s*"\*"/.test(block.body);
      if (!hasWildcardAction || !hasWildcardResource) return null;
      const lines = block.body.split('\n');
      const lineIndex = lines.findIndex((line) => /"\*"/.test(line));
      return {
        description: 'The policy grants Action "*" on Resource "*". Any principal holding it can perform every action on every resource in the account, including reading KMS key policies and exfiltrating secrets.',
        line: block.startLine + lineIndex + 1,
      };
    },
    recommendation: 'Enumerate the exact actions and resource ARNs the principal requires.',
  },
  {
    id: 'iac-secret-in-hcl',
    resources: ['*'],
    title: 'Credential value assigned in infrastructure code',
    severity: 'critical',
    role: 'unknown',
    evaluate: (block) => {
      const match = block.body.match(/^\s*(password|secret|access_key|secret_key|private_key|token|api_key|client_secret)\s*=\s*"([^"$][^"]{7,})"\s*$/im);
      if (!match) return null;
      const lines = block.body.split('\n');
      const lineIndex = lines.findIndex((line) => line.includes(match[0].trim()));
      return {
        description: `The attribute "${match[1]}" is assigned a literal value in infrastructure code. Terraform also writes it to state, which is frequently stored in a bucket with broader read access than the repository. The value has been redacted and is not stored.`,
        line: block.startLine + lineIndex + 1,
        snippet: `${match[1]} = "[REDACTED]"`,
      };
    },
    recommendation: 'Reference a secret manager data source (aws_secretsmanager_secret_version, azurerm_key_vault_secret) and mark the variable sensitive.',
  },
  {
    id: 'iac-acm-imported-cert',
    resources: ['aws_acm_certificate'],
    title: 'Certificate managed by ACM',
    severity: 'info',
    role: 'certificate',
    algorithm: 'RSA',
    evaluate: (block) => {
      const algorithm = hclAttribute(block.body, 'key_algorithm');
      const domain = hclAttribute(block.body, 'domain_name');
      return {
        description: `An ACM certificate is declared${domain ? ` for ${domain.value}` : ''}${algorithm ? ` with key algorithm ${algorithm.value}` : ' with the ACM default key algorithm (RSA-2048)'}. Managed issuance is what makes a post-quantum certificate rollover a configuration change rather than a project.`,
        line: block.startLine,
      };
    },
    recommendation: 'Track ACM for ML-DSA certificate support; until then, EC_prime256v1 shortens the chain without changing the quantum position.',
  },
  {
    id: 'iac-azure-storage-insecure',
    resources: ['azurerm_storage_account'],
    title: 'Azure storage account permits plaintext transfer',
    severity: 'high',
    role: 'tls',
    algorithm: 'TLS',
    evaluate: (block) => {
      const https = hclAttribute(block.body, 'enable_https_traffic_only') ?? hclAttribute(block.body, 'https_traffic_only_enabled');
      const minTls = hclAttribute(block.body, 'min_tls_version');
      if (https?.value === 'false') {
        return { description: 'enable_https_traffic_only is false, so the storage account accepts plaintext HTTP requests.', line: block.startLine + https.lineOffset };
      }
      if (minTls && /TLS1_0|TLS1_1/i.test(minTls.value)) {
        return { description: `min_tls_version is ${minTls.value}, which permits a deprecated TLS version.`, line: block.startLine + minTls.lineOffset };
      }
      return null;
    },
    recommendation: 'Set https_traffic_only_enabled = true and min_tls_version = "TLS1_2".',
  },
  {
    id: 'iac-gcp-bucket-public',
    resources: ['google_storage_bucket_iam_member', 'google_storage_bucket_iam_binding'],
    title: 'Cloud Storage bucket granted to allUsers',
    severity: 'critical',
    role: 'unknown',
    evaluate: (block) => {
      if (!/allUsers|allAuthenticatedUsers/.test(block.body)) return null;
      const lines = block.body.split('\n');
      const lineIndex = lines.findIndex((line) => /allUsers|allAuthenticatedUsers/.test(line));
      return {
        description: 'The bucket IAM grant includes allUsers or allAuthenticatedUsers, making its contents readable outside the organisation.',
        line: block.startLine + lineIndex + 1,
      };
    },
    recommendation: 'Remove the public member and grant access to named principals or a service account.',
  },
];

/* ────────────────────────────────────────────────────── CloudFormation etc ── */

const TEXT_RULES: Array<{
  id: string;
  appliesTo: RegExp;
  pattern: RegExp;
  title: string;
  description: string;
  severity: FindingSeverity;
  role: CryptoRole;
  algorithm?: string;
  recommendation: string;
}> = [
  {
    id: 'iac-cfn-unencrypted-bucket',
    appliesTo: /\.(ya?ml|json)$/i,
    pattern: /"?Type"?\s*:?\s*["']?AWS::S3::Bucket["']?(?![\s\S]{0,800}BucketEncryption)/,
    title: 'CloudFormation S3 bucket declares no BucketEncryption',
    description: 'An AWS::S3::Bucket resource is declared with no BucketEncryption property, so its encryption posture is inherited from the account default rather than stated in the template.',
    severity: 'medium',
    role: 'storage-encryption',
    algorithm: 'AES',
    recommendation: 'Add a BucketEncryption property specifying aws:kms with a customer-managed key.',
  },
  {
    id: 'iac-arm-weak-tls',
    appliesTo: /\.(json|bicep)$/i,
    pattern: /minimumTlsVersion['"]?\s*[:=]\s*['"]?(TLS1_0|TLS1_1|1\.0|1\.1)/i,
    title: 'ARM/Bicep resource permits a deprecated TLS version',
    description: 'The resource sets minimumTlsVersion to a deprecated protocol version, so it will negotiate TLS 1.0 or 1.1 with clients that offer nothing better.',
    severity: 'high',
    role: 'tls',
    algorithm: 'TLS',
    recommendation: 'Set minimumTlsVersion to TLS1_2.',
  },
  {
    id: 'iac-ansible-no-validate-certs',
    appliesTo: /\.(ya?ml)$/i,
    pattern: /^\s*validate_certs\s*:\s*(?:no|false)\b/im,
    title: 'Ansible task disables certificate validation',
    description: 'An Ansible task sets validate_certs to false, so the play accepts any certificate presented by the endpoint it contacts.',
    severity: 'high',
    role: 'certificate',
    algorithm: 'TLS',
    recommendation: 'Remove validate_certs: false and install the required CA certificate on the control node.',
  },
  {
    id: 'iac-ansible-plaintext-secret',
    appliesTo: /\.(ya?ml)$/i,
    pattern: /^\s*(ansible_(?:password|become_password|ssh_pass)|vault_password)\s*:\s*(?!\{\{|!vault)\S{6,}/im,
    title: 'Ansible variable carries a plaintext credential',
    description: 'A credential variable is assigned a literal value rather than a vault reference or lookup. The value has been redacted and is not stored.',
    severity: 'critical',
    role: 'unknown',
    recommendation: 'Encrypt the value with ansible-vault, or source it from a secret manager lookup.',
  },
];

/* ────────────────────────────────────────────────────────────── the engine ── */

export const iacEngine: ExposureEngine = {
  descriptor: {
    id: 'iac-security',
    label: 'Infrastructure as Code',
    description: 'Analyses Terraform, OpenTofu, CloudFormation, Bicep, ARM and Ansible for encryption, key-management, TLS and exposure weaknesses.',
    mode: 'local',
    layer: 'iac',
    capability: 'iac',
    dependsOn: ['file-discovery'],
    weight: 12,
  },

  appliesTo(context) {
    return context.workspace.files.some((file) => file.content && file.classification === 'iac')
      ? { applicable: true }
      : { applicable: false, reason: 'No infrastructure-as-code files were found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && file.classification === 'iac',
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    let processed = 0;

    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      context.report(`Analysing ${file.path}`, { done: processed, total: files.length, unit: 'files' });

      const content = file.content as string;

      /* ── HCL ────────────────────────────────────────────────────────── */
      if (file.ext === '.tf' || file.ext === '.hcl' || file.ext === '.tfvars') {
        const blocks = parseHclBlocks(content);
        for (const block of blocks) {
          if (block.type !== 'resource' && block.type !== 'module' && block.type !== 'provider') continue;
          const resourceType = block.labels[0] ?? '';
          for (const rule of TERRAFORM_RULES) {
            if (!rule.resources.includes('*') && !rule.resources.includes(resourceType)) continue;
            const hit = rule.evaluate(block);
            if (!hit) continue;

            const quantum = rule.algorithm
              ? classifyQuantum({ algorithm: rule.algorithm, role: rule.role })
              : { status: 'not-applicable' as const, rationale: 'This is an infrastructure control, not a cryptographic primitive.', quantumRelevant: false };

            findings.push(
              buildFinding({
                scanId: context.scanId,
                engineId: 'iac-security',
                mode: context.mode,
                layer: 'iac',
                category: rule.severity === 'info' ? 'Infrastructure Strength' : 'Infrastructure Weakness',
                subcategory: resourceType || block.type,
                title: `${rule.title} — ${block.labels.join('.') || file.path}`,
                description: hit.description,
                severity: rule.severity,
                confidence: 'high',
                detection: 'observed',
                algorithm: rule.algorithm,
                canonicalAlgorithm: rule.algorithm ? canonicalAlgorithmName(rule.algorithm) : undefined,
                role: rule.role,
                component: block.labels.join('.'),
                quantumStatus: quantum.status,
                quantumRationale: quantum.rationale,
                recommendation: rule.recommendation,
                evidence: [
                  buildEvidence({
                    summary: `${rule.title} at ${file.path}:${hit.line}`,
                    file: file.path,
                    line: hit.line,
                    snippet: hit.snippet,
                    reference: `${block.type} ${block.labels.join('.')}`,
                    ruleId: rule.id,
                    provider: providerOf(resourceType),
                    localOnly: context.mode === 'local',
                  }),
                ],
                identity: `${file.path}|${rule.id}|${block.labels.join('.')}`,
              }),
            );
          }
        }
        continue;
      }

      /* ── text-matched templates ─────────────────────────────────────── */
      for (const rule of TEXT_RULES) {
        if (!rule.appliesTo.test(file.path)) continue;
        if (!rule.pattern.test(content)) continue;
        const lines = content.split('\n');
        const singleLine = new RegExp(rule.pattern.source, rule.pattern.flags.replace('m', ''));
        const lineIndex = lines.findIndex((line) => singleLine.test(line));

        const quantum = rule.algorithm
          ? classifyQuantum({ algorithm: rule.algorithm, role: rule.role })
          : { status: 'not-applicable' as const, rationale: 'This is an infrastructure control, not a cryptographic primitive.', quantumRelevant: false };

        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'iac-security',
            mode: context.mode,
            layer: 'iac',
            category: 'Infrastructure Weakness',
            subcategory: rule.title,
            title: `${rule.title} — ${file.path}`,
            description: rule.description,
            severity: rule.severity,
            confidence: 'medium',
            detection: 'observed',
            algorithm: rule.algorithm,
            canonicalAlgorithm: rule.algorithm ? canonicalAlgorithmName(rule.algorithm) : undefined,
            role: rule.role,
            quantumStatus: quantum.status,
            quantumRationale: quantum.rationale,
            recommendation: rule.recommendation,
            evidence: [
              buildEvidence({
                summary: `${rule.title} in ${file.path}${lineIndex >= 0 ? `:${lineIndex + 1}` : ''}`,
                file: file.path,
                line: lineIndex >= 0 ? lineIndex + 1 : undefined,
                snippet: lineIndex >= 0 ? lines[lineIndex] : undefined,
                ruleId: rule.id,
                localOnly: context.mode === 'local',
              }),
            ],
            identity: `${file.path}|${rule.id}`,
          }),
        );
      }
    }

    for (const finding of findings) context.emit(finding);
    return completed(findings, { iacFiles: files.length });
  },
};

function providerOf(resourceType: string): string | undefined {
  if (resourceType.startsWith('aws_')) return 'aws';
  if (resourceType.startsWith('azurerm_') || resourceType.startsWith('azuread_')) return 'azure';
  if (resourceType.startsWith('google_')) return 'gcp';
  if (resourceType.startsWith('kubernetes_')) return 'kubernetes';
  if (resourceType.startsWith('cloudflare_')) return 'cloudflare';
  return undefined;
}
