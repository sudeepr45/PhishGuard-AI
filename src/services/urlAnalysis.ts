export const FEATURE_NAMES = [
  'url_length',
  'hostname_length',
  'hostname_dot_count',
  'subdomain_count',
  'hyphen_count',
  'digit_count',
  'is_ip_hostname',
  'uses_https',
  'authority_has_at_sign',
  'percent_encoding_count',
  'malformed_percent_count',
  'path_length',
  'path_segment_count',
  'path_has_dot_segment',
  'query_length',
  'query_parameter_count',
  'has_fragment',
] as const

export type FeatureName = (typeof FEATURE_NAMES)[number]
export type MeasuredFeatures = Record<FeatureName, number>
export type Prediction = 'phishing' | 'legitimate'
export type ContributionDirection = 'toward_phishing' | 'toward_legitimate' | 'neutral'

export type FeatureContribution = {
  feature_name: FeatureName
  measured_value: number
  standardized_value: number
  coefficient: number
  logit_contribution: number
  direction: ContributionDirection
}

export type LogisticRegressionExplanation = {
  model_version: string
  model_algorithm: 'logistic_regression'
  positive_class: 'phishing'
  intercept: number
  reconstructed_logit: number
  decision_function_logit: number
  reconstruction_error: number
  feature_contributions: FeatureContribution[]
  interpretation: string
}

export type NoveltyDetection = {
  available: boolean
  is_unusual: boolean | null
  anomaly_score: number | null
  threshold: number | null
  detector_version: string | null
  detector: string | null
  interpretation: string
}

export type AnalysisResult = {
  normalized_url: string
  prediction: Prediction
  model_version: string
  model_algorithm: string
  model_scope: string
  phishing_score: number
  legitimate_score: number
  decision_threshold: number
  measured_features: MeasuredFeatures
  explanation: LogisticRegressionExplanation | null
  novelty_detection: NoveltyDetection
  interpretation: string
}

// Legacy fields remain in the backend response for existing frontend consumers.
export type UrlAnalysis = AnalysisResult & { evidence: MeasuredFeatures }

export type EmailLinkAnalysis = Pick<AnalysisResult,
  'normalized_url' | 'prediction' | 'model_version' | 'model_algorithm' |
  'phishing_score' | 'legitimate_score' | 'decision_threshold' | 'measured_features' | 'explanation' | 'novelty_detection'> & {
    sources: string[]
  }

export type EmailAnalysis = {
  headers: Record<'From' | 'Reply-To' | 'Return-Path' | 'Subject' | 'Date', string | null>
  authentication_results: string[]
  authentication_results_warning: string
  received_header_count: number
  extracted_link_count: number
  phishing_link_count: number
  legitimate_link_count: number
  unsupported_links: { value: string; reason: string }[]
  links: EmailLinkAnalysis[]
  truncated: boolean
  mime_parts_examined: number
  triage_summary: string
  limitations: string
}

export type AnalysisHistoryRecord = {
  id: number
  created_at: string
  normalized_url: string
  prediction: Prediction
  phishing_score: number
  legitimate_score: number
  decision_threshold: number
  model_version: string
  model_algorithm: string
  measured_features: MeasuredFeatures
  explanation: LogisticRegressionExplanation | null
  novelty_detection: NoveltyDetection | null
}

export type AnalysisHistoryPage = {
  items: AnalysisHistoryRecord[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

export type DeleteHistoryResult = {
  deleted: boolean
  analysis_id?: number | null
  deleted_count?: number | null
}

export class ApiError extends Error {
  readonly status: number | null

  constructor(message: string, status: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export const FEATURE_DESCRIPTIONS: Record<FeatureName, string> = {
  url_length: 'Total characters in the normalized URL',
  hostname_length: 'Characters in the hostname',
  hostname_dot_count: 'Dots in the hostname',
  subdomain_count: 'Subdomain labels',
  hyphen_count: 'Hyphens in the URL',
  digit_count: 'Digits in the URL',
  is_ip_hostname: 'Hostname is an IP address',
  uses_https: 'Uses HTTPS',
  authority_has_at_sign: 'At sign in the URL authority',
  percent_encoding_count: 'Valid percent-encoded sequences',
  malformed_percent_count: 'Malformed percent sequences',
  path_length: 'Characters in the path',
  path_segment_count: 'Path segments',
  path_has_dot_segment: 'Path contains a dot segment',
  query_length: 'Characters in the query',
  query_parameter_count: 'Query parameters',
  has_fragment: 'URL contains a fragment',
}

export const FEATURE_NOTES: Record<FeatureName, string> = {
  url_length: 'Character count of the normalized URL string.',
  hostname_length: 'Parsed hostname length, excluding user information and port.',
  hostname_dot_count: 'Literal dots in the parsed hostname.',
  subdomain_count: 'Public Suffix List-aware subdomain labels; zero for IP addresses.',
  hyphen_count: 'Literal hyphens across the URL.',
  digit_count: 'Digits occurring across the URL.',
  is_ip_hostname: 'Whether the hostname parses as an IP address.',
  uses_https: 'Whether the scheme is HTTPS; this does not verify live TLS.',
  authority_has_at_sign: 'Whether the parsed authority contains an at sign.',
  percent_encoding_count: 'Percent escapes followed by two hexadecimal digits.',
  malformed_percent_count: 'Percent signs not followed by two hexadecimal digits.',
  path_length: 'Character count of the parsed path.',
  path_segment_count: 'Number of nonempty slash-separated path segments.',
  path_has_dot_segment: 'Whether a path segment is exactly . or ..; encoded forms are not decoded.',
  query_length: 'Character count of the query, excluding the question mark.',
  query_parameter_count: 'Number of nonempty ampersand-separated query components.',
  has_fragment: 'Whether the parsed URL has a nonempty fragment.',
}

const API_BASE = '/api'
const DEFAULT_TIMEOUT_MS = 15_000

export function validateUrlInput(value: string): string | null {
  const input = value.trim()
  if (!input) return 'Enter a URL to analyze.'
  if (Array.from(input).length > 8192) return 'This URL is longer than the service limit of 8,192 characters.'
  if (Array.from(input).some((character) => /\s/.test(character) || character.codePointAt(0)! < 32 || character.codePointAt(0) === 127)) {
    return 'Remove spaces and control characters from the URL.'
  }

  const explicitScheme = /^[a-z][a-z\d+.-]*:/i.test(input)
  const hostAndPort = /^[^:/?#]+:\d+(?:[/?#]|$)/.test(input)
  let candidate = input
  if (explicitScheme && !/^https?:\/\//i.test(input)) {
    if (!hostAndPort) return 'Use an HTTP or HTTPS URL.'
    candidate = `https://${input}`
  } else if (!explicitScheme) {
    candidate = `https://${input}`
  }
  if (Array.from(candidate).length > 8192) return 'This URL is longer than the service limit of 8,192 characters.'

  try {
    const parsed = new URL(candidate)
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
      return 'Enter a valid HTTP or HTTPS URL with a hostname.'
    }
  } catch {
    return 'Enter a valid HTTP or HTTPS URL with a hostname.'
  }
  return null
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseFeatures(value: unknown): MeasuredFeatures {
  if (!isRecord(value) || FEATURE_NAMES.some((name) => typeof value[name] !== 'number' || !Number.isFinite(value[name]))) {
    throw new ApiError('The analysis service returned invalid URL feature measurements.')
  }
  const names = Object.keys(value)
  if (names.length !== FEATURE_NAMES.length || names.some((name) => !FEATURE_NAMES.includes(name as FeatureName))) {
    throw new ApiError('The analysis service returned an unexpected feature schema.')
  }
  return Object.fromEntries(FEATURE_NAMES.map((name) => [name, value[name]])) as MeasuredFeatures
}

function parseExplanation(value: unknown, modelVersion: string): LogisticRegressionExplanation | null {
  if (value === undefined || value === null) return null
  if (!isRecord(value) || value.model_version !== modelVersion ||
    value.model_algorithm !== 'logistic_regression' || value.positive_class !== 'phishing' ||
    !Array.isArray(value.feature_contributions) || value.feature_contributions.length !== FEATURE_NAMES.length ||
    typeof value.interpretation !== 'string') {
    throw new ApiError('The analysis service returned an unexpected model explanation.')
  }
  const scalarFields = ['intercept', 'reconstructed_logit', 'decision_function_logit', 'reconstruction_error'] as const
  if (scalarFields.some((name) => typeof value[name] !== 'number' || !Number.isFinite(value[name]))) {
    throw new ApiError('The analysis service returned non-finite model explanation values.')
  }
  const contributions = value.feature_contributions.map((entry, index): FeatureContribution => {
    const name = FEATURE_NAMES[index]
    if (!isRecord(entry) || entry.feature_name !== name ||
      typeof entry.measured_value !== 'number' || !Number.isFinite(entry.measured_value) ||
      typeof entry.standardized_value !== 'number' || !Number.isFinite(entry.standardized_value) ||
      typeof entry.coefficient !== 'number' || !Number.isFinite(entry.coefficient) ||
      typeof entry.logit_contribution !== 'number' || !Number.isFinite(entry.logit_contribution) ||
      !['toward_phishing', 'toward_legitimate', 'neutral'].includes(String(entry.direction))) {
      throw new ApiError('The analysis service returned an invalid feature contribution.')
    }
    const expectedDirection = entry.logit_contribution > 0
      ? 'toward_phishing'
      : entry.logit_contribution < 0 ? 'toward_legitimate' : 'neutral'
    if (entry.direction !== expectedDirection) {
      throw new ApiError('The analysis service returned a mismatched contribution direction.')
    }
    return {
      feature_name: name,
      measured_value: entry.measured_value,
      standardized_value: entry.standardized_value,
      coefficient: entry.coefficient,
      logit_contribution: entry.logit_contribution,
      direction: expectedDirection,
    }
  })
  const explanation: LogisticRegressionExplanation = {
    model_version: value.model_version,
    model_algorithm: 'logistic_regression',
    positive_class: 'phishing',
    intercept: value.intercept as number,
    reconstructed_logit: value.reconstructed_logit as number,
    decision_function_logit: value.decision_function_logit as number,
    reconstruction_error: value.reconstruction_error as number,
    feature_contributions: contributions,
    interpretation: value.interpretation,
  }
  const reconstructed = explanation.intercept + contributions.reduce((sum, item) => sum + item.logit_contribution, 0)
  const tolerance = 1e-9 * Math.max(1, Math.abs(explanation.decision_function_logit))
  if (Math.abs(reconstructed - explanation.reconstructed_logit) > tolerance ||
    Math.abs(explanation.reconstructed_logit - explanation.decision_function_logit) > tolerance ||
    Math.abs(explanation.reconstruction_error - Math.abs(explanation.reconstructed_logit - explanation.decision_function_logit)) > tolerance) {
    throw new ApiError('The analysis service returned an explanation that does not reconstruct its model logit.')
  }
  return explanation
}

function parseNovelty(value: unknown): NoveltyDetection {
  if (!isRecord(value) || typeof value.available !== 'boolean' || typeof value.interpretation !== 'string') {
    throw new ApiError('The analysis service returned invalid novelty information.')
  }
  if (!value.available) {
    if (value.is_unusual !== null || value.anomaly_score !== null || value.threshold !== null ||
      value.detector_version !== null || value.detector !== null) {
      throw new ApiError('The unavailable novelty result contains a detector value.')
    }
    return { available: false, is_unusual: null, anomaly_score: null, threshold: null,
      detector_version: null, detector: null, interpretation: value.interpretation }
  }
  if (typeof value.is_unusual !== 'boolean' || typeof value.anomaly_score !== 'number' ||
    !Number.isFinite(value.anomaly_score) || typeof value.threshold !== 'number' ||
    !Number.isFinite(value.threshold) || typeof value.detector_version !== 'string' ||
    typeof value.detector !== 'string') {
    throw new ApiError('The available novelty result is incomplete.')
  }
  return {
    available: true, is_unusual: value.is_unusual, anomaly_score: value.anomaly_score,
    threshold: value.threshold, detector_version: value.detector_version,
    detector: value.detector, interpretation: value.interpretation,
  }
}

function parseAnalysis(value: unknown): UrlAnalysis {
  if (!isRecord(value) || (value.prediction !== 'phishing' && value.prediction !== 'legitimate') ||
    typeof value.normalized_url !== 'string' || typeof value.model_version !== 'string' ||
    typeof value.model_algorithm !== 'string' || typeof value.model_scope !== 'string' ||
    typeof value.interpretation !== 'string' || typeof value.phishing_score !== 'number' ||
    typeof value.legitimate_score !== 'number' || typeof value.decision_threshold !== 'number') {
    throw new ApiError('The analysis service returned an unexpected response.')
  }
  const scores = [value.phishing_score, value.legitimate_score, value.decision_threshold]
  if (scores.some((score) => !Number.isFinite(score) || score < 0 || score > 1)) {
    throw new ApiError('The analysis service returned invalid model scores.')
  }
  const measuredFeatures = parseFeatures(value.measured_features)
  const legacyEvidence = parseFeatures(value.evidence)
  const explanation = parseExplanation(value.explanation, value.model_version)
  return {
    normalized_url: value.normalized_url,
    prediction: value.prediction,
    model_version: value.model_version,
    model_algorithm: value.model_algorithm,
    model_scope: value.model_scope,
    phishing_score: value.phishing_score,
    legitimate_score: value.legitimate_score,
    decision_threshold: value.decision_threshold,
    measured_features: measuredFeatures,
    explanation,
    novelty_detection: parseNovelty(value.novelty_detection),
    interpretation: value.interpretation,
    evidence: legacyEvidence,
  }
}

function parseEmailAnalysis(value: unknown): EmailAnalysis {
  if (!isRecord(value)) throw new ApiError('The email analysis service returned an unexpected response.')
  const headerValues = value.headers
  if (!isRecord(headerValues) ||
    !['From', 'Reply-To', 'Return-Path', 'Subject', 'Date'].every((key) =>
      headerValues[key] === null || typeof headerValues[key] === 'string') ||
    !Array.isArray(value.authentication_results) || !value.authentication_results.every((item) => typeof item === 'string') ||
    !Array.isArray(value.unsupported_links) || !Array.isArray(value.links) ||
    typeof value.authentication_results_warning !== 'string' ||
    typeof value.triage_summary !== 'string' || typeof value.limitations !== 'string' ||
    typeof value.truncated !== 'boolean' || typeof value.mime_parts_examined !== 'number' ||
    typeof value.received_header_count !== 'number' || typeof value.extracted_link_count !== 'number' ||
    typeof value.phishing_link_count !== 'number' || typeof value.legitimate_link_count !== 'number') {
    throw new ApiError('The email analysis service returned an unexpected response.')
  }
  const links = value.links.map((item): EmailLinkAnalysis => {
    if (!isRecord(item) || typeof item.normalized_url !== 'string' ||
      (item.prediction !== 'phishing' && item.prediction !== 'legitimate') ||
      typeof item.model_version !== 'string' || typeof item.model_algorithm !== 'string' ||
      typeof item.phishing_score !== 'number' || !Number.isFinite(item.phishing_score) ||
      typeof item.legitimate_score !== 'number' || !Number.isFinite(item.legitimate_score) ||
      typeof item.decision_threshold !== 'number' || !Number.isFinite(item.decision_threshold) ||
      !Array.isArray(item.sources) || !item.sources.every((source) => typeof source === 'string')) {
      throw new ApiError('The email analysis service returned an invalid link result.')
    }
    return {
      normalized_url: item.normalized_url,
      prediction: item.prediction,
      model_version: item.model_version,
      model_algorithm: item.model_algorithm,
      phishing_score: item.phishing_score,
      legitimate_score: item.legitimate_score,
      decision_threshold: item.decision_threshold,
      measured_features: parseFeatures(item.measured_features),
      explanation: parseExplanation(item.explanation, item.model_version),
      novelty_detection: parseNovelty(item.novelty_detection),
      sources: item.sources,
    }
  })
  if (links.length !== value.extracted_link_count ||
    links.filter((link) => link.prediction === 'phishing').length !== value.phishing_link_count ||
    links.filter((link) => link.prediction === 'legitimate').length !== value.legitimate_link_count) {
    throw new ApiError('The email analysis service returned inconsistent link totals.')
  }
  const unsupported = value.unsupported_links.map((item) => {
    if (!isRecord(item) || typeof item.value !== 'string' || typeof item.reason !== 'string') {
      throw new ApiError('The email analysis service returned invalid unsupported-link details.')
    }
    return { value: item.value, reason: item.reason }
  })
  const headers = Object.fromEntries(['From', 'Reply-To', 'Return-Path', 'Subject', 'Date'].map((key) => [key, headerValues[key]])) as EmailAnalysis['headers']
  return {
    headers,
    authentication_results: value.authentication_results,
    authentication_results_warning: value.authentication_results_warning,
    received_header_count: value.received_header_count,
    extracted_link_count: value.extracted_link_count,
    phishing_link_count: value.phishing_link_count,
    legitimate_link_count: value.legitimate_link_count,
    unsupported_links: unsupported,
    links,
    truncated: value.truncated,
    mime_parts_examined: value.mime_parts_examined,
    triage_summary: value.triage_summary,
    limitations: value.limitations,
  }
}

function parseHistoryRecord(value: unknown): AnalysisHistoryRecord {
  if (!isRecord(value) || typeof value.id !== 'number' || !Number.isInteger(value.id) || value.id < 1 ||
    typeof value.created_at !== 'string' || typeof value.normalized_url !== 'string' ||
    (value.prediction !== 'phishing' && value.prediction !== 'legitimate') ||
    typeof value.phishing_score !== 'number' || typeof value.legitimate_score !== 'number' ||
    typeof value.decision_threshold !== 'number' || typeof value.model_version !== 'string' ||
    typeof value.model_algorithm !== 'string') {
    throw new ApiError('The history service returned an unexpected record.')
  }
  const scores = [value.phishing_score, value.legitimate_score, value.decision_threshold]
  if (scores.some((score) => !Number.isFinite(score) || score < 0 || score > 1)) {
    throw new ApiError('The history service returned invalid saved scores.')
  }
  return {
    id: value.id,
    created_at: value.created_at,
    normalized_url: value.normalized_url,
    prediction: value.prediction,
    phishing_score: value.phishing_score,
    legitimate_score: value.legitimate_score,
    decision_threshold: value.decision_threshold,
    model_version: value.model_version,
    model_algorithm: value.model_algorithm,
    measured_features: parseFeatures(value.measured_features),
    explanation: parseExplanation(value.explanation, value.model_version),
    novelty_detection: value.novelty_detection === undefined || value.novelty_detection === null
      ? null : parseNovelty(value.novelty_detection),
  }
}

function responseMessage(status: number, detail?: string): string {
  if (status === 404) return 'That saved analysis no longer exists.'
  if (status === 422) return 'The request was rejected. Check the URL or history page parameters.'
  if (status === 503) return detail || 'The local analysis service or history database is unavailable.'
  if (status >= 500) return 'The local analysis service encountered an error. Try again.'
  return detail || `The analysis service returned HTTP ${status}.`
}

async function requestJson<T>(path: string, init: RequestInit = {}, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController()
  let timedOut = false
  const externalSignal = init.signal
  const abortFromCaller = () => controller.abort()
  if (externalSignal?.aborted) controller.abort()
  externalSignal?.addEventListener('abort', abortFromCaller, { once: true })
  const timeout = window.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)

  try {
    let response: Response
    try {
      response = await fetch(`${API_BASE}${path}`, { ...init, signal: controller.signal })
    } catch (error) {
      if (externalSignal?.aborted) throw error
      if (timedOut) throw new ApiError('The local service timed out. Check that it is running, then try again.')
      throw new ApiError('Could not reach the local analysis service. Start the backend and try again.')
    }

    let body: unknown
    try {
      body = await response.json()
    } catch {
      if (!response.ok) throw new ApiError(responseMessage(response.status), response.status)
      throw new ApiError('The local analysis service returned invalid JSON.', response.status)
    }
    if (!response.ok) {
      const detail = isRecord(body) && typeof body.detail === 'string' ? body.detail : undefined
      throw new ApiError(responseMessage(response.status, detail), response.status)
    }
    return body as T
  } finally {
    window.clearTimeout(timeout)
    externalSignal?.removeEventListener('abort', abortFromCaller)
  }
}

export async function analyzeUrl(url: string, signal?: AbortSignal): Promise<UrlAnalysis> {
  const response = await requestJson<unknown>('/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
    signal,
  })
  return parseAnalysis(response)
}

export async function analyzeEmail(rawEmail: string, signal?: AbortSignal): Promise<EmailAnalysis> {
  const response = await requestJson<unknown>('/analyze-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw_email: rawEmail }),
    signal,
  }, 30_000)
  return parseEmailAnalysis(response)
}

export async function getAnalysisHistory(limit = 20, offset = 0): Promise<AnalysisHistoryPage> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  const response = await requestJson<unknown>(`/history?${query}`)
  if (!isRecord(response) || !Array.isArray(response.items) || typeof response.total !== 'number' ||
    typeof response.limit !== 'number' || typeof response.offset !== 'number' || typeof response.has_more !== 'boolean') {
    throw new ApiError('The history service returned an unexpected page.')
  }
  return {
    items: response.items.map(parseHistoryRecord),
    total: response.total,
    limit: response.limit,
    offset: response.offset,
    has_more: response.has_more,
  }
}

export async function getAnalysisById(id: number): Promise<AnalysisHistoryRecord> {
  if (!Number.isInteger(id) || id < 1) throw new ApiError('Analysis ID must be a positive integer.')
  return parseHistoryRecord(await requestJson<unknown>(`/history/${id}`))
}

export async function deleteAnalysis(id: number): Promise<DeleteHistoryResult> {
  if (!Number.isInteger(id) || id < 1) throw new ApiError('Analysis ID must be a positive integer.')
  return requestJson<DeleteHistoryResult>(`/history/${id}`, { method: 'DELETE' })
}

export async function clearAnalysisHistory(): Promise<DeleteHistoryResult> {
  return requestJson<DeleteHistoryResult>('/history?confirm=true', { method: 'DELETE' })
}
