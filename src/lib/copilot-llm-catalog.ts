// Sophia — Bring-Your-Own-Key model catalog.
//
// The model providers a tenant may connect to Sophia with their OWN API key.
// Imported by BOTH the Express gateway (src/api-server/copilot-llm.ts) and the
// settings UI, so the providers, endpoints and models a user can pick are the
// exact set the server will call. Keep this file dependency-free.
//
// Endpoints are a closed allowlist: the server only ever calls a URL listed
// here, so a stored provider configuration can never point the gateway at an
// internal address (no SSRF via "custom base URL"). Model ids, by contrast, are
// open — providers ship models faster than any catalog — so a user may enter
// any model id that matches MODEL_ID_PATTERN; the Verify step proves it works.

export type CopilotLlmProviderId = 'anthropic' | 'openai' | 'hermes' | 'kimi' | 'glm' | 'deepseek'

/** Wire protocol the adapter speaks. Everything except Anthropic is OpenAI-compatible chat completions. */
export type CopilotLlmProtocol = 'anthropic' | 'openai'

export interface CopilotLlmModel {
  id: string
  label: string
  /** One-line guidance shown in the picker. */
  note?: string
}

export interface CopilotLlmEndpoint {
  id: string
  label: string
  url: string
  models: CopilotLlmModel[]
}

export interface CopilotLlmProviderSpec {
  id: CopilotLlmProviderId
  label: string
  vendor: string
  protocol: CopilotLlmProtocol
  /** Two-letter monogram for the provider tile (no third-party logos are bundled). */
  monogram: string
  /** Tailwind gradient classes for the tile accent. */
  accent: string
  /** Where the user creates a key. */
  consoleUrl: string
  /** Typical key prefix, shown as a hint only — formats change, so it is never enforced. */
  keyHint: string
  endpoints: CopilotLlmEndpoint[]
  /** Output-token ceiling the narrative request uses for this provider. */
  maxOutputTokens: number
  /** Short positioning line for the tile. */
  tagline: string
}

export const COPILOT_LLM_PROVIDERS: CopilotLlmProviderSpec[] = [
  {
    id: 'anthropic',
    label: 'Anthropic Claude',
    vendor: 'Anthropic',
    protocol: 'anthropic',
    monogram: 'AC',
    accent: 'from-orange-400/30 to-amber-500/10',
    consoleUrl: 'https://console.anthropic.com/settings/keys',
    keyHint: 'sk-ant-…',
    maxOutputTokens: 16000,
    tagline: 'Deep reasoning for migration strategy and executive narrative.',
    endpoints: [
      {
        id: 'global',
        label: 'Anthropic API (api.anthropic.com)',
        url: 'https://api.anthropic.com/v1/messages',
        models: [
          { id: 'claude-opus-5-5', label: 'Claude Opus 5.5', note: 'Most capable Opus — recommended' },
          { id: 'claude-sonnet-5-5', label: 'Claude Sonnet 5.5', note: 'Fast, strong everyday analysis' },
          { id: 'claude-haiku-5-5', label: 'Claude Haiku 5.5', note: 'Lowest latency and cost' },
          { id: 'claude-fable-5-1', label: 'Claude Fable 5.1', note: 'Frontier tier — highest cost' },
        ],
      },
    ],
  },
  {
    id: 'openai',
    label: 'OpenAI ChatGPT',
    vendor: 'OpenAI',
    protocol: 'openai',
    monogram: 'OA',
    accent: 'from-emerald-400/30 to-teal-500/10',
    consoleUrl: 'https://platform.openai.com/api-keys',
    keyHint: 'sk-…',
    maxOutputTokens: 16000,
    tagline: 'GPT models through the OpenAI platform API.',
    endpoints: [
      {
        id: 'global',
        label: 'OpenAI API (api.openai.com)',
        url: 'https://api.openai.com/v1/chat/completions',
        models: [
          { id: 'gpt-5', label: 'GPT-5', note: 'Flagship reasoning model' },
          { id: 'gpt-5-mini', label: 'GPT-5 mini', note: 'Faster, lower cost' },
          { id: 'gpt-4.1', label: 'GPT-4.1', note: 'Non-reasoning, long context' },
          { id: 'gpt-4o', label: 'GPT-4o', note: 'Legacy general model' },
        ],
      },
    ],
  },
  {
    id: 'hermes',
    label: 'Nous Hermes',
    vendor: 'Nous Research',
    protocol: 'openai',
    monogram: 'NH',
    accent: 'from-fuchsia-400/30 to-purple-500/10',
    consoleUrl: 'https://portal.nousresearch.com',
    keyHint: 'Nous Portal or OpenRouter key',
    maxOutputTokens: 8000,
    tagline: 'Open-weight Hermes models via Nous Portal or OpenRouter.',
    endpoints: [
      {
        id: 'nous',
        label: 'Nous Portal (inference-api.nousresearch.com)',
        url: 'https://inference-api.nousresearch.com/v1/chat/completions',
        models: [
          { id: 'Hermes-4-405B', label: 'Hermes 4 405B', note: 'Largest Hermes' },
          { id: 'Hermes-4-70B', label: 'Hermes 4 70B', note: 'Faster, lower cost' },
        ],
      },
      {
        id: 'openrouter',
        label: 'OpenRouter (openrouter.ai)',
        url: 'https://openrouter.ai/api/v1/chat/completions',
        models: [
          { id: 'nousresearch/hermes-4-405b', label: 'Hermes 4 405B' },
          { id: 'nousresearch/hermes-4-70b', label: 'Hermes 4 70B' },
        ],
      },
    ],
  },
  {
    id: 'kimi',
    label: 'Moonshot Kimi',
    vendor: 'Moonshot AI',
    protocol: 'openai',
    monogram: 'KM',
    accent: 'from-sky-400/30 to-indigo-500/10',
    consoleUrl: 'https://platform.moonshot.ai/console/api-keys',
    keyHint: 'sk-…',
    maxOutputTokens: 8000,
    tagline: 'Kimi K2 long-context models from Moonshot AI.',
    endpoints: [
      {
        id: 'global',
        label: 'International (api.moonshot.ai)',
        url: 'https://api.moonshot.ai/v1/chat/completions',
        models: [
          { id: 'kimi-k2-0905-preview', label: 'Kimi K2 (0905)', note: 'General agentic model' },
          { id: 'kimi-k2-turbo-preview', label: 'Kimi K2 Turbo', note: 'Higher throughput' },
          { id: 'kimi-k2-thinking', label: 'Kimi K2 Thinking', note: 'Reasoning variant' },
        ],
      },
      {
        id: 'china',
        label: 'Mainland China (api.moonshot.cn)',
        url: 'https://api.moonshot.cn/v1/chat/completions',
        models: [
          { id: 'kimi-k2-0905-preview', label: 'Kimi K2 (0905)' },
          { id: 'kimi-k2-turbo-preview', label: 'Kimi K2 Turbo' },
          { id: 'kimi-k2-thinking', label: 'Kimi K2 Thinking' },
        ],
      },
    ],
  },
  {
    id: 'glm',
    label: 'Zhipu GLM',
    vendor: 'Z.ai (Zhipu AI)',
    protocol: 'openai',
    monogram: 'GL',
    accent: 'from-blue-400/30 to-cyan-500/10',
    consoleUrl: 'https://z.ai/manage-apikey/apikey-list',
    keyHint: 'Z.ai / BigModel API key',
    maxOutputTokens: 8000,
    tagline: 'GLM models via Z.ai (international) or BigModel (China).',
    endpoints: [
      {
        id: 'global',
        label: 'Z.ai International (api.z.ai)',
        url: 'https://api.z.ai/api/paas/v4/chat/completions',
        models: [
          { id: 'glm-4.6', label: 'GLM-4.6', note: 'Flagship' },
          { id: 'glm-4.5', label: 'GLM-4.5' },
          { id: 'glm-4.5-air', label: 'GLM-4.5 Air', note: 'Lower cost' },
        ],
      },
      {
        id: 'china',
        label: 'BigModel China (open.bigmodel.cn)',
        url: 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
        models: [
          { id: 'glm-4.6', label: 'GLM-4.6' },
          { id: 'glm-4.5', label: 'GLM-4.5' },
          { id: 'glm-4.5-air', label: 'GLM-4.5 Air' },
        ],
      },
    ],
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    vendor: 'DeepSeek',
    protocol: 'openai',
    monogram: 'DS',
    accent: 'from-indigo-400/30 to-blue-600/10',
    consoleUrl: 'https://platform.deepseek.com/api_keys',
    keyHint: 'sk-…',
    maxOutputTokens: 8000,
    tagline: 'DeepSeek chat and reasoner models.',
    endpoints: [
      {
        id: 'global',
        label: 'DeepSeek API (api.deepseek.com)',
        url: 'https://api.deepseek.com/chat/completions',
        models: [
          { id: 'deepseek-chat', label: 'DeepSeek Chat', note: 'General model' },
          { id: 'deepseek-reasoner', label: 'DeepSeek Reasoner', note: 'Reasoning model' },
        ],
      },
    ],
  },
]

/** Model ids are free-form but bounded: letters, digits and . _ : / - only. */
export const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/

/** API keys: printable ASCII, no whitespace, bounded length. Prefixes are not enforced. */
export const API_KEY_PATTERN = /^[\x21-\x7E]{16,512}$/

/** Plan tier BYOK requires — premium feature. */
export const COPILOT_BYOK_MIN_TIER = 'pro' as const

export function providerSpec(id: string): CopilotLlmProviderSpec | undefined {
  return COPILOT_LLM_PROVIDERS.find((p) => p.id === id)
}

export function endpointSpec(provider: CopilotLlmProviderSpec, endpointId: string | null | undefined): CopilotLlmEndpoint {
  return provider.endpoints.find((e) => e.id === endpointId) || provider.endpoints[0]
}

export function isCopilotLlmProviderId(v: unknown): v is CopilotLlmProviderId {
  return typeof v === 'string' && COPILOT_LLM_PROVIDERS.some((p) => p.id === v)
}

/** Public status of one provider connection — never carries the key itself. */
export interface CopilotLlmProviderStatus {
  provider: CopilotLlmProviderId
  configured: boolean
  active: boolean
  model: string | null
  endpoint: string | null
  /** Last four characters of the key, for recognition only. */
  keyHint: string | null
  status: 'verified' | 'unverified' | 'invalid' | 'error' | 'not_configured'
  lastVerifiedAt: string | null
  lastError: string | null
  lastUsedAt: string | null
  requestCount: number
  inputTokens: number
  outputTokens: number
  updatedAt: string | null
}

export interface CopilotLlmSettings {
  providers: CopilotLlmProviderStatus[]
  /** Whether the caller's plan includes BYOK. */
  entitled: boolean
  requiredTier: typeof COPILOT_BYOK_MIN_TIER
  tier: string
  /** Where connections persist: the encrypted table, or process memory until the schema is applied. */
  storage: 'database' | 'memory'
  /**
   *  - `dedicated`   — keys sealed with COPILOT_BYOK_SECRET
   *  - `derived`     — dev fallback: sealing key derived from the service-role key
   *  - `unavailable` — no sealing secret; BYOK is disabled
   */
  encryption: 'dedicated' | 'derived' | 'unavailable'
}
