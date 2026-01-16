/**
 * Argus MCP Server - Model Context Protocol for AI IDEs
 * https://heyargus.ai
 *
 * This MCP server exposes Argus E2E testing capabilities to AI coding assistants:
 * - Claude Code
 * - Cursor
 * - Windsurf
 * - VS Code with MCP extension
 *
 * Tools provided:
 * - argus_discover: Discover interactive elements on a page
 * - argus_test: Run multi-step E2E tests with screenshots
 * - argus_act: Execute browser actions
 * - argus_extract: Extract data from pages
 * - argus_agent: Autonomous task completion
 * - argus_health: Check Argus API status
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Environment types
interface Env {
  AI: Ai;
  SCREENSHOTS: R2Bucket;  // R2 storage for screenshots
  SCREENSHOTS_PUBLIC_URL?: string;  // Public URL for R2 screenshots
  BROWSER_POOL_URL?: string;  // Primary - Vultr VKE browser pool
  BROWSER_POOL_JWT_SECRET?: string;  // JWT secret for pool auth (production)
  BROWSER_POOL_API_KEY?: string;  // Legacy API key (deprecated)
  ARGUS_API_URL: string;  // Fallback - Cloudflare browser automation
  ARGUS_BRAIN_URL: string;  // Brain - intelligence
  API_TOKEN?: string;
  ANTHROPIC_API_KEY?: string;
  MCP_OAUTH: DurableObjectNamespace;
  MCP_OBJECT: DurableObjectNamespace;
}

// =====================================================
// JWT Token Signing for Browser Pool (Production-Grade)
// =====================================================

interface PoolTokenPayload {
  iss: string;      // Issuer: 'argus-mcp'
  sub: string;      // User ID
  aud: string;      // Audience: 'browser-pool'
  exp: number;      // Expiration
  iat: number;      // Issued at
  jti: string;      // Unique token ID
  org_id?: string;  // Organization ID
  email?: string;   // User email (for audit)
  action?: string;  // Action being performed
  ip?: string;      // Client IP
}

function base64UrlEncode(data: string | ArrayBuffer): string {
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : new Uint8Array(data);
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signPoolToken(
  payload: Omit<PoolTokenPayload, 'iat' | 'exp' | 'jti'>,
  secret: string,
  expiresInSeconds: number = 300
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const fullPayload: PoolTokenPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
    jti: crypto.randomUUID(),
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(fullPayload));

  // Sign using Web Crypto API (Cloudflare Workers compatible)
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${headerB64}.${payloadB64}`)
  );

  const signatureB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

// =====================================================
// R2 Screenshot Storage
// =====================================================

// MCP server base URL for screenshot serving
const MCP_SERVER_URL = "https://argus-mcp.samuelvinay-kumar.workers.dev";

// Screenshot URL expiry time (1 hour)
const SCREENSHOT_URL_EXPIRY_MS = 60 * 60 * 1000;

interface ScreenshotUploadResult {
  success: boolean;
  url?: string;
  key?: string;
  error?: string;
}

/**
 * Generate a signed token for screenshot access
 * Token format: base64url(expiry:signature)
 * This combines expiry into the token to avoid URL truncation issues with &
 */
async function generateScreenshotToken(key: string, expiry: number, env: Env): Promise<string> {
  const secret = env.BROWSER_POOL_JWT_SECRET || "default-secret-for-dev";
  const data = `${key}:${expiry}`;

  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(data)
  );

  const sigB64 = base64UrlEncode(signature);
  // Combine expiry and signature into single token: expiry.signature
  return `${expiry}.${sigB64}`;
}

/**
 * Parse and validate a screenshot token
 * Returns { valid: true, expiry } or { valid: false, error }
 */
async function validateScreenshotToken(
  token: string,
  key: string,
  env: Env
): Promise<{ valid: boolean; expiry?: number; error?: string }> {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return { valid: false, error: "Invalid token format" };
  }

  const [expiryStr, signature] = parts;
  const expiry = parseInt(expiryStr, 10);

  if (isNaN(expiry)) {
    return { valid: false, error: "Invalid expiry in token" };
  }

  if (Date.now() > expiry) {
    return { valid: false, error: "Token expired" };
  }

  // Regenerate expected signature
  const secret = env.BROWSER_POOL_JWT_SECRET || "default-secret-for-dev";
  const data = `${key}:${expiry}`;

  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const expectedSig = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(data)
  );

  const expectedSigB64 = base64UrlEncode(expectedSig);

  if (signature !== expectedSigB64) {
    return { valid: false, error: "Invalid signature" };
  }

  return { valid: true, expiry };
}

/**
 * Generate a signed URL for accessing a screenshot
 * URL expires after SCREENSHOT_URL_EXPIRY_MS
 * Uses single token parameter to avoid & truncation issues
 */
async function generateSignedScreenshotUrl(key: string, env: Env): Promise<string> {
  const expiry = Date.now() + SCREENSHOT_URL_EXPIRY_MS;
  const token = await generateScreenshotToken(key, expiry, env);

  // Single parameter URL to avoid & truncation in markdown/terminals
  return `${MCP_SERVER_URL}/screenshot/${encodeURIComponent(key)}?t=${token}`;
}

/**
 * Store a screenshot in R2 and return a signed URL
 */
async function storeScreenshot(
  env: Env,
  screenshotData: unknown,  // Can be string, Buffer object, or serialized Buffer
  sessionId: string,
  identifier: string | number,  // step index or 'final'
  metadata?: Record<string, string>
): Promise<ScreenshotUploadResult> {
  if (!env.SCREENSHOTS) {
    console.warn("[R2] Screenshots bucket not configured");
    return { success: false, error: "R2 storage not configured" };
  }

  try {
    // Generate key: mcp-screenshots/{session_id}/{identifier}.png
    const key = `mcp-screenshots/${sessionId}/${identifier}.png`;

    // Handle different input formats
    let bytes: Uint8Array;

    if (!screenshotData) {
      console.error(`[R2] Screenshot data is null/undefined`);
      return { success: false, error: "Screenshot data is null/undefined" };
    }

    // Case 1: Already a base64 string
    if (typeof screenshotData === "string") {
      console.log(`[R2] Processing base64 string: length=${screenshotData.length}`);

      // Clean and convert base64 to ArrayBuffer
      let cleanBase64 = screenshotData
        .replace(/^data:image\/\w+;base64,/, "")  // Remove data URL prefix if present
        .replace(/[\s\n\r]/g, "")                  // Remove whitespace
        .replace(/-/g, "+")                        // URL-safe base64 to standard
        .replace(/_/g, "/");

      // Add padding if needed
      const paddingNeeded = (4 - (cleanBase64.length % 4)) % 4;
      cleanBase64 += "=".repeat(paddingNeeded);

      const binaryString = atob(cleanBase64);
      bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
    }
    // Case 2: Serialized Node.js Buffer ({ type: 'Buffer', data: [...] })
    else if (
      typeof screenshotData === "object" &&
      screenshotData !== null &&
      "type" in screenshotData &&
      (screenshotData as { type: string }).type === "Buffer" &&
      "data" in screenshotData &&
      Array.isArray((screenshotData as { data: number[] }).data)
    ) {
      const bufferData = (screenshotData as { type: string; data: number[] }).data;
      console.log(`[R2] Processing serialized Buffer: ${bufferData.length} bytes`);
      bytes = new Uint8Array(bufferData);
    }
    // Case 3: ArrayBuffer or Uint8Array
    else if (screenshotData instanceof ArrayBuffer) {
      console.log(`[R2] Processing ArrayBuffer: ${screenshotData.byteLength} bytes`);
      bytes = new Uint8Array(screenshotData);
    }
    else if (screenshotData instanceof Uint8Array) {
      console.log(`[R2] Processing Uint8Array: ${screenshotData.length} bytes`);
      bytes = screenshotData;
    }
    // Unknown format - log details for debugging
    else {
      const objType = typeof screenshotData;
      const objKeys = typeof screenshotData === "object" && screenshotData !== null
        ? Object.keys(screenshotData).slice(0, 5).join(", ")
        : "N/A";
      const objSample = typeof screenshotData === "object" && screenshotData !== null
        ? JSON.stringify(screenshotData).slice(0, 200)
        : String(screenshotData).slice(0, 100);
      console.error(`[R2] Unknown screenshot format: type=${objType}, keys=[${objKeys}], sample=${objSample}`);
      return { success: false, error: `Unknown screenshot format: ${objType}` };
    }

    console.log(`[R2] Uploading ${bytes.length} bytes to ${key}`);

    // Upload to R2 (cast to ArrayBuffer to satisfy TypeScript)
    await env.SCREENSHOTS.put(key, bytes.buffer as ArrayBuffer, {
      httpMetadata: {
        contentType: "image/png",
        cacheControl: "private, max-age=3600",  // 1 hour cache (matches URL expiry)
      },
      customMetadata: {
        sessionId,
        identifier: String(identifier),
        uploadedAt: new Date().toISOString(),
        ...metadata,
      },
    });

    // Generate signed URL (expires in 1 hour)
    const url = await generateSignedScreenshotUrl(key, env);
    console.log(`[R2] Screenshot stored: ${key}`);

    return { success: true, url, key };
  } catch (error) {
    console.error("[R2] Screenshot upload failed:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Upload failed",
    };
  }
}

/**
 * Store multiple screenshots and return URLs
 */
async function storeScreenshots(
  env: Env,
  screenshots: string[],
  sessionId: string,
  startIndex: number = 0
): Promise<string[]> {
  const urls: string[] = [];

  for (let i = 0; i < screenshots.length; i++) {
    const result = await storeScreenshot(
      env,
      screenshots[i],
      sessionId,
      startIndex + i
    );
    if (result.success && result.url) {
      urls.push(result.url);
    }
  }

  return urls;
}

/**
 * Generate a unique session ID for screenshot grouping
 */
function generateSessionId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${timestamp}-${random}`;
}

// User context from MCP session
interface UserContext {
  userId: string;
  orgId?: string;
  email?: string;
  ip?: string;
}

// Brain API Response types
interface BrainHealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

interface BrainTestCreateResponse {
  success: boolean;
  test: {
    id: string;
    name: string;
    description: string;
    steps: Array<{
      action: string;
      target?: string;
      value?: string;
    }>;
    assertions: Array<{
      type: string;
      target?: string;
      expected?: string;
    }>;
  };
  spec?: string;
}

interface BrainQualityStatsResponse {
  stats: {
    total_events: number;
    events_by_status: Record<string, number>;
    events_by_severity: Record<string, number>;
    total_generated_tests: number;
    tests_by_status: Record<string, number>;
    coverage_rate: number;
  };
}

interface BrainQualityScoreResponse {
  quality_score: number;
  risk_level: string;
  test_coverage: number;
  total_events: number;
  total_tests: number;
  approved_tests: number;
}

interface BrainRiskScoresResponse {
  success: boolean;
  risk_scores: Array<{
    entity_type: string;
    entity_identifier: string;
    overall_score: number;
    factors: Record<string, number>;
    error_count: number;
    affected_users: number;
    trend: string;
  }>;
  total_entities: number;
}

// Sync API Response types
interface SyncPushResponse {
  success: boolean;
  events_pushed: number;
  new_version?: number;
  conflicts?: Array<{
    id: string;
    test_id: string;
    path: string[];
    local_value: unknown;
    remote_value: unknown;
  }>;
  error?: string;
}

interface SyncPullResponse {
  success: boolean;
  events: Array<{
    id: string;
    type: string;
    test_id: string;
    content?: Record<string, unknown>;
    timestamp: string;
  }>;
  new_version?: number;
  error?: string;
}

interface SyncStatusResponse {
  success: boolean;
  project_id: string;
  status: string;
  tests: Record<string, {
    test_id: string;
    status: string;
    local_version: number;
    remote_version: number;
    pending_changes: number;
    conflicts: number;
  }>;
  total_pending: number;
  total_conflicts: number;
}

interface SyncResolveResponse {
  success: boolean;
  resolved: boolean;
  conflict_id: string;
  resolved_value?: unknown;
  error?: string;
}

// Export API Response types
interface ExportResponse {
  success: boolean;
  language: string;
  framework: string;
  code: string;
  filename: string;
  imports?: string[];
  error?: string;
}

interface ExportLanguagesResponse {
  languages: Array<{
    id: string;
    name: string;
    frameworks: string[];
  }>;
}

// Recording API Response types
interface RecordingConvertResponse {
  success: boolean;
  test: {
    id: string;
    name: string;
    source: string;
    steps: Array<{
      action: string;
      target?: string;
      value?: string;
    }>;
    assertions: Array<{
      type: string;
      target?: string;
      expected?: string;
    }>;
  };
  recording_id: string;
  duration_ms: number;
  events_processed: number;
  error?: string;
}

// Collaboration API Response types
interface PresenceResponse {
  success: boolean;
  users: Array<{
    user_id: string;
    user_name: string;
    status: string;
    test_id?: string;
    cursor?: {
      step_index?: number;
      field?: string;
    };
    color: string;
    last_active: string;
  }>;
}

// Production Events Response types
interface ProductionEventsResponse {
  events: Array<{
    id: string;
    title: string;
    message?: string;
    severity: string;
    status: string;
    url?: string;
    component?: string;
    occurrence_count: number;
    affected_users: number;
    source: string;
    first_seen_at: string;
    last_seen_at: string;
    ai_analysis?: {
      generated_test_id?: string;
      confidence_score?: number;
    };
  }>;
}

// Generated Tests Response types
interface GeneratedTestsResponse {
  tests: Array<{
    id: string;
    name: string;
    description?: string;
    status: string;
    framework: string;
    test_code?: string;
    test_file_path?: string;
    confidence_score: number;
    production_event_id?: string;
    created_at: string;
    reviewed_at?: string;
  }>;
}

// Healing Config Response types
interface HealingConfigResponse {
  id: string;
  organization_id: string;
  project_id?: string;
  enabled: boolean;
  auto_apply: boolean;
  min_confidence_auto: number;
  min_confidence_suggest: number;
  heal_selectors: boolean;
  heal_timeouts: boolean;
  heal_text_content: boolean;
  learn_from_success: boolean;
  notify_on_heal: boolean;
  require_approval: boolean;
}

// Healing Patterns Response types
interface HealingPatternsResponse {
  patterns: Array<{
    id: string;
    fingerprint: string;
    original_selector: string;
    healed_selector: string;
    error_type: string;
    success_count: number;
    failure_count: number;
    confidence: number;
    project_id?: string;
    created_at: string;
  }>;
}

// Healing Stats Response types
interface HealingStatsResponse {
  total_patterns: number;
  total_heals_applied: number;
  total_heals_suggested: number;
  success_rate: number;
  top_error_types: Record<string, number>;
  heals_last_24h: number;
  heals_last_7d: number;
  avg_confidence: number;
  recent_heals: Array<{
    id: string;
    original: string;
    healed: string;
    error_type: string;
    confidence: number;
  }>;
}

// Projects Response types
interface ProjectsResponse {
  projects: Array<{
    id: string;
    name: string;
    description?: string;
    app_url?: string;
    organization_id: string;
    created_at: string;
    test_count?: number;
    event_count?: number;
  }>;
}

// Test Run History Response types
interface TestRunHistoryResponse {
  runs: Array<{
    id: string;
    test_id: string;
    status: string;
    duration_ms: number;
    passed_steps: number;
    total_steps: number;
    error_message?: string;
    screenshot_url?: string;
    started_at: string;
    completed_at?: string;
  }>;
}

// What To Test Response types
interface WhatToTestResponse {
  recommendations: Array<{
    priority: string;
    entity: string;
    entity_type: string;
    reason: string;
    risk_score: number;
    affected_users: number;
    suggested_test_description: string;
  }>;
  summary: string;
}

// Coverage Gaps Response types
interface CoverageGapsResponse {
  gaps: Array<{
    entity: string;
    entity_type: string;
    error_count: number;
    has_test: boolean;
    risk_score: number;
    suggestion: string;
  }>;
  coverage_percentage: number;
  total_entities: number;
  tested_entities: number;
}

// Flaky Tests Response types
interface FlakyTestsResponse {
  flaky_tests: Array<{
    test_id: string;
    test_name: string;
    flakiness_score: number;
    pass_rate: number;
    total_runs: number;
    recent_failures: number;
    common_failure_reason?: string;
  }>;
  total_flaky: number;
}

// Schedule Response types
interface ScheduleResponse {
  schedules: Array<{
    id: string;
    name: string;
    cron_expression: string;
    test_ids: string[];
    enabled: boolean;
    last_run_at?: string;
    next_run_at?: string;
    created_at: string;
  }>;
}

// AI Ask Response types
interface AskResponse {
  answer: string;
  sources: Array<{
    type: string;
    id: string;
    relevance: number;
  }>;
  suggestions?: string[];
}

interface CommentsResponse {
  success: boolean;
  comments: Array<{
    id: string;
    test_id: string;
    step_index?: number;
    author_id: string;
    author_name: string;
    content: string;
    mentions: string[];
    resolved: boolean;
    created_at: string;
    replies?: Array<{
      id: string;
      author_id: string;
      author_name: string;
      content: string;
      created_at: string;
    }>;
  }>;
}

// Infrastructure & Cost Response types
interface InfraCostOverviewResponse {
  currentMonthCost: number;
  projectedMonthCost: number;
  browserStackEquivalent: number;
  savingsPercentage: number;
  totalNodes: number;
  totalPods: number;
}

interface InfraRecommendation {
  id: string;
  type: "scale_down" | "scale_up" | "optimize" | "alert";
  title: string;
  description: string;
  potential_savings: number;
  confidence: number;
  status: "pending" | "applied" | "dismissed";
  auto_applicable: boolean;
  action?: Record<string, unknown>;
}

interface InfraRecommendationsResponse {
  recommendations: InfraRecommendation[];
  total_potential_savings: number;
}

interface InfraSnapshotResponse {
  selenium: {
    status: string;
    ready_nodes: number;
    queue_length: number;
    active_sessions: number;
    max_sessions: number;
  };
  chrome_nodes: {
    ready: number;
    busy: number;
    total: number;
    utilization: number;
  };
  firefox_nodes: {
    ready: number;
    busy: number;
    total: number;
    utilization: number;
  };
  edge_nodes: {
    ready: number;
    busy: number;
    total: number;
    utilization: number;
  };
  total_pods: number;
  total_nodes: number;
  cluster_cpu_utilization: number;
  cluster_memory_utilization: number;
  timestamp: string;
}

interface LLMUsageResponse {
  models: Array<{
    name: string;
    provider: string;
    input_tokens: number;
    output_tokens: number;
    cost: number;
    requests: number;
  }>;
  features: Array<{
    name: string;
    cost: number;
    percentage: number;
    requests: number;
  }>;
  total_cost: number;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  period: string;
}

interface InfraSavingsResponse {
  total_monthly_savings: number;
  recommendations_applied: number;
  current_monthly_cost: number;
  browserstack_equivalent: number;
  savings_vs_browserstack: number;
  savings_percentage: number;
}

// Argus API Response types
interface ArgusActResponse {
  success: boolean;
  message?: string;
  actions?: Array<{
    action: string;
    selector?: string;
    value?: string;
    success: boolean;
  }>;
  screenshot?: string;
  error?: string;
}

interface ArgusTestResponse {
  success: boolean;
  steps?: Array<{
    instruction: string;
    success: boolean;
    error?: string;
    screenshot?: string;
  }>;
  screenshots?: string[];
  finalScreenshot?: string;
  error?: string;
}

interface ArgusObserveResponse {
  success?: boolean;  // Optional - Cloudflare fallback doesn't include this
  actions?: Array<{
    description: string;
    selector: string;
    type: string;
    confidence: number;
    method?: string;    // Cloudflare format
    arguments?: unknown[];  // Cloudflare format
  }>;
  elements?: Array<{   // Cloudflare fallback format
    tag: string;
    text: string;
    selector: string;
    attributes?: Record<string, string>;
  }>;
  error?: string;
  _backend?: string;   // Cloudflare includes this
}

interface ArgusExtractResponse {
  success: boolean;
  data?: Record<string, unknown>;
  error?: string;
}

interface ArgusAgentResponse {
  success: boolean;
  completed: boolean;
  message?: string;
  actions?: Array<{
    action: string;
    success: boolean;
    screenshot?: string;
  }>;
  screenshots?: string[];
  usage?: {
    inputTokens: number;
    outputTokens: number;
  };
  error?: string;
}

// MCP Content types
type TextContent = {
  type: "text";
  text: string;
};

type ImageContent = {
  type: "image";
  data: string;
  mimeType: string;
};

type McpContent = TextContent | ImageContent;

// Helper to call Browser Pool API (primary) with Cloudflare fallback
// Now with production-grade JWT authentication and user context
async function callWorkerAPI<T>(
  endpoint: string,
  body: Record<string, unknown>,
  env: Env,
  userContext?: UserContext
): Promise<T> {
  // Primary: Vultr VKE Browser Pool (if configured)
  const poolUrl = env.BROWSER_POOL_URL;
  // Fallback: Cloudflare Browser Rendering
  const fallbackUrl = env.ARGUS_API_URL || "https://argus-api.samuelvinay-kumar.workers.dev";

  // Try Browser Pool first if configured
  if (poolUrl) {
    try {
      console.log(`[DEBUG] Attempting Browser Pool: ${poolUrl}${endpoint}`);
      const poolHeaders: Record<string, string> = {
        "Content-Type": "application/json",
      };

      // Production: Sign JWT with user context
      if (env.BROWSER_POOL_JWT_SECRET) {
        console.log(`[DEBUG] Signing JWT with secret (length: ${env.BROWSER_POOL_JWT_SECRET.length})`);
        const token = await signPoolToken({
          iss: "argus-mcp",
          sub: userContext?.userId || "mcp-anonymous",
          aud: "browser-pool",
          org_id: userContext?.orgId,
          email: userContext?.email,
          action: endpoint.replace("/", ""),
          ip: userContext?.ip,
        }, env.BROWSER_POOL_JWT_SECRET);
        poolHeaders["Authorization"] = `Bearer ${token}`;
        console.log(`[DEBUG] JWT signed, token length: ${token.length}`);
      }
      // Legacy fallback: Use static API key (deprecated)
      else if (env.BROWSER_POOL_API_KEY) {
        console.warn("DEPRECATION: Using legacy API key. Configure BROWSER_POOL_JWT_SECRET.");
        poolHeaders["Authorization"] = `Bearer ${env.BROWSER_POOL_API_KEY}`;
      } else {
        console.warn("[DEBUG] No auth configured for Browser Pool!");
      }

      console.log(`[DEBUG] Fetching ${poolUrl}${endpoint}`);
      const response = await fetch(`${poolUrl}${endpoint}`, {
        method: "POST",
        headers: poolHeaders,
        body: JSON.stringify(body),
      });
      console.log(`[DEBUG] Browser Pool response: ${response.status}`);

      if (response.ok) {
        return response.json() as Promise<T>;
      }

      // Pool failed, log and fall through to fallback
      const errorText = await response.text();
      console.warn(`Browser Pool failed (${response.status}): ${errorText}, falling back to Cloudflare`);
    } catch (error) {
      console.warn(`Browser Pool error: ${error}, falling back to Cloudflare`);
    }
  } else {
    console.log(`[DEBUG] No BROWSER_POOL_URL configured, using fallback`);
  }

  // Fallback headers (for Cloudflare/Argus API)
  const fallbackHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (env.API_TOKEN) {
    fallbackHeaders["Authorization"] = `Bearer ${env.API_TOKEN}`;
  }

  // Fallback to Cloudflare Browser Rendering
  const response = await fetch(`${fallbackUrl}${endpoint}`, {
    method: "POST",
    headers: fallbackHeaders,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Browser API error (${response.status}): ${errorText}`);
  }

  return response.json() as Promise<T>;
}

// Helper to call Brain API (intelligence)
async function callBrainAPI<T>(
  endpoint: string,
  method: "GET" | "POST" | "PUT" | "DELETE" = "POST",
  body?: Record<string, unknown>,
  env?: Env,
  accessToken?: string
): Promise<T> {
  const brainUrl = env?.ARGUS_BRAIN_URL || "https://argus-brain-production.up.railway.app";

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Add Authorization header if access token is provided
  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const fetchOptions: RequestInit = {
    method,
    headers,
  };

  if (body && (method === "POST" || method === "PUT")) {
    fetchOptions.body = JSON.stringify(body);
  }

  const response = await fetch(`${brainUrl}${endpoint}`, fetchOptions);

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Brain API error (${response.status}): ${errorText}`);
  }

  return response.json() as Promise<T>;
}

// Helper to register MCP connection with Brain API
async function registerMCPConnection(
  env: Env,
  accessToken: string,
  sessionId: string,
  clientName?: string
): Promise<string | null> {
  try {
    const brainUrl = env?.ARGUS_BRAIN_URL || "https://argus-brain-production.up.railway.app";
    const response = await fetch(`${brainUrl}/api/v1/mcp/connections/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        session_id: sessionId,
        client_id: 'argus-mcp',
        client_name: clientName || 'MCP Client',
        client_type: 'mcp',
      }),
    });

    if (response.ok) {
      const data = await response.json() as { connection_id: string };
      console.log(`[MCP] Connection registered: ${data.connection_id}`);
      return data.connection_id;
    }
    console.warn(`[MCP] Failed to register connection: ${response.status}`);
    return null;
  } catch (error) {
    console.error('[MCP] Connection registration error:', error);
    return null;
  }
}

// Alias for backward compatibility
const callArgusAPI = callWorkerAPI;

// Helper to record MCP activity after tool executions
async function recordMCPActivity(
  env: Env,
  accessToken: string,
  connectionId: string,
  toolName: string,
  options: {
    durationMs?: number;
    success?: boolean;
    errorMessage?: string;
    screenshotKey?: string;
    inputTokens?: number;
    outputTokens?: number;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  try {
    await fetch(`${env.ARGUS_BRAIN_URL}/api/v1/mcp/connections/activity`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        connection_id: connectionId,
        tool_name: toolName,
        request_id: crypto.randomUUID(),
        duration_ms: options.durationMs,
        success: options.success ?? true,
        error_message: options.errorMessage,
        screenshot_key: options.screenshotKey,
        input_tokens: options.inputTokens,
        output_tokens: options.outputTokens,
        metadata: options.metadata,
      }),
    });
  } catch (error) {
    console.error('[MCP] Activity recording error:', error);
    // Don't throw - activity recording should not block tool execution
  }
}

// Interface for KV namespace
interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

// Extend Env to include KV namespace
interface EnvWithKV extends Env {
  AUTH_STATE?: KVNamespace;
}

// Create MCP Server with Argus tools
export class ArgusMcpAgentSQLite extends McpAgent<EnvWithKV> {
  server = new McpServer({
    name: "Argus E2E Testing Agent",
    version: "1.0.0",
  });

  /**
   * Get the stored access token from KV or DO storage
   * Returns undefined if not authenticated or token expired
   */
  async getAccessToken(): Promise<string | undefined> {
    try {
      // First check DO storage for direct auth
      const authStr = await this.ctx.storage.get<string>("auth");
      if (authStr) {
        const auth = JSON.parse(authStr);
        if (auth.access_token && auth.expires_at) {
          if (new Date(auth.expires_at) > new Date()) {
            return auth.access_token;
          }
        }
      }

      // Check for pending auth that might have been completed via KV
      if (this.env.AUTH_STATE) {
        const pendingAuthStr = await this.ctx.storage.get<string>("pending_auth");
        if (pendingAuthStr) {
          const pendingAuth = JSON.parse(pendingAuthStr);
          if (pendingAuth.user_code) {
            const kvAuthStr = await this.env.AUTH_STATE.get(`auth_${pendingAuth.user_code}`);
            if (kvAuthStr) {
              const kvAuth = JSON.parse(kvAuthStr);
              if (kvAuth.status === "completed" && kvAuth.access_token) {
                // Token found in KV, verify expiry
                if (kvAuth.expires_at && new Date(kvAuth.expires_at) > new Date()) {
                  // Save to DO storage for future use
                  await this.ctx.storage.put("auth", JSON.stringify({
                    access_token: kvAuth.access_token,
                    expires_at: kvAuth.expires_at,
                    user_id: kvAuth.user_id,
                  }));
                  return kvAuth.access_token;
                }
              }
            }
          }
        }
      }

      return undefined;
    } catch (error) {
      console.error("Error getting access token:", error);
      return undefined;
    }
  }

  /**
   * Wrapper for callBrainAPI that automatically injects the access token
   * This is the primary method tools should use for Brain API calls
   */
  async callBrainAPIWithAuth<T>(
    endpoint: string,
    method: "GET" | "POST" | "PUT" | "DELETE" = "POST",
    body?: Record<string, unknown>
  ): Promise<T> {
    const accessToken = await this.getAccessToken();
    return callBrainAPI<T>(endpoint, method, body, this.env, accessToken);
  }

  /**
   * Check if user is authenticated, throw helpful error if not
   */
  async requireAuth(): Promise<string> {
    const accessToken = await this.getAccessToken();
    if (!accessToken) {
      throw new Error("AUTH_REQUIRED");
    }
    return accessToken;
  }

  /**
   * Get the stored MCP connection ID from DO storage
   * Returns undefined if not connected
   */
  async getConnectionId(): Promise<string | undefined> {
    try {
      const connectionStr = await this.ctx.storage.get<string>("mcp_connection");
      if (connectionStr) {
        const connection = JSON.parse(connectionStr);
        return connection.connection_id;
      }
      return undefined;
    } catch (error) {
      console.error("Error getting connection ID:", error);
      return undefined;
    }
  }

  /**
   * Record activity for a tool execution (non-blocking)
   */
  async recordActivity(
    toolName: string,
    options: {
      durationMs?: number;
      success?: boolean;
      errorMessage?: string;
      screenshotKey?: string;
      inputTokens?: number;
      outputTokens?: number;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void> {
    const accessToken = await this.getAccessToken();
    const connectionId = await this.getConnectionId();

    if (accessToken && connectionId) {
      // Fire and forget - don't await
      recordMCPActivity(this.env, accessToken, connectionId, toolName, options);
    }
  }

  /**
   * Handle common error patterns including auth requirement
   */
  handleError(error: unknown): { content: Array<{ type: "text"; text: string }>; isError: true } {
    const message = error instanceof Error ? error.message : "Unknown error";
    
    if (message === "AUTH_REQUIRED") {
      return {
        content: [{
          type: "text" as const,
          text: `## Authentication Required\n\nPlease run \`argus_auth\` first to sign in to Argus.\n\n**Steps:**\n1. Run \`argus_auth\` to get a verification code\n2. Open the URL and sign in\n3. Run \`argus_auth_complete\` to finish authentication`,
        }],
        isError: true,
      };
    }

    // Check for 401/403 errors from API
    if (message.includes("401") || message.includes("403") || message.includes("Unauthorized") || message.includes("authentication")) {
      return {
        content: [{
          type: "text" as const,
          text: `## Authentication Error\n\nYour session may have expired. Please run \`argus_auth\` to sign in again.\n\n**Error:** ${message}`,
        }],
        isError: true,
      };
    }

    return {
      content: [{
        type: "text" as const,
        text: `Error: ${message}`,
      }],
      isError: true,
    };
  }

  /**
   * Helper to create an auth required response
   */
  authRequiredResponse() {
    return {
      content: [{
        type: "text" as const,
        text: `## Authentication Required\n\nPlease run \`argus_auth\` first to sign in to Argus.\n\n**Steps:**\n1. Run \`argus_auth\` to get a verification code\n2. Open the URL and sign in\n3. Run \`argus_auth_complete\` to finish authentication`,
      }],
      isError: true,
    };
  }

  async init() {
    // =========================================================================
    // AUTHENTICATION TOOLS - OAuth2 Device Flow
    // =========================================================================

    // Tool: argus_auth - Start authentication flow
    this.server.tool(
      "argus_auth",
      "Authenticate with Argus to access protected features like projects, quality intelligence, and team collaboration. Opens a browser for secure sign-in.",
      {},
      async () => {
        try {
          // Call Brain API to start device auth flow (uses form-urlencoded)
          const response = await fetch(
            `${this.env.ARGUS_BRAIN_URL || "https://argus-brain-production.up.railway.app"}/api/v1/auth/device/authorize`,
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: "argus-mcp-server",
                scope: "read write",
              }).toString(),
            }
          );

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to start auth: ${errorText}`);
          }

          const data = await response.json() as {
            device_code: string;
            user_code: string;
            verification_uri: string;
            verification_uri_complete: string;
            expires_in: number;
          };

          // Store pending auth in DO storage
          await this.ctx.storage.put("pending_auth", JSON.stringify({
            device_code: data.device_code,
            user_code: data.user_code,
            expires_at: new Date(Date.now() + data.expires_in * 1000).toISOString(),
          }));

          // Also store in KV for cross-session access
          if (this.env.AUTH_STATE) {
            await this.env.AUTH_STATE.put(`auth_${data.user_code}`, JSON.stringify({
              device_code: data.device_code,
              status: "pending",
              created_at: new Date().toISOString(),
            }), { expirationTtl: data.expires_in });
          }

          return {
            content: [{
              type: "text" as const,
              text: `## Argus Authentication\n\n**Your verification code:** \`${data.user_code}\`\n\n**Steps to sign in:**\n1. Open this URL in your browser:\n   ${data.verification_uri_complete}\n\n2. Sign in with your Argus account\n\n3. Enter the code if prompted: \`${data.user_code}\`\n\n4. After signing in, run \`argus_auth_complete\` to finish\n\n*Code expires in ${Math.floor(data.expires_in / 60)} minutes*`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error starting authentication: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_auth_complete - Complete authentication flow
    this.server.tool(
      "argus_auth_complete",
      "Complete the authentication flow after signing in via browser. Call this after you've entered the code on the Argus website.",
      {},
      async () => {
        try {
          // Get pending auth from DO storage
          const pendingAuthStr = await this.ctx.storage.get<string>("pending_auth");
          
          let pendingAuth: { device_code: string; user_code: string; expires_at: string } | null = null;
          
          if (pendingAuthStr) {
            pendingAuth = JSON.parse(pendingAuthStr);
          }

          // If not in DO storage, try KV
          if (!pendingAuth && this.env.AUTH_STATE) {
            // We need the user_code to look up in KV, but we don't have it
            // This is a limitation - user needs to start fresh if session was lost
          }

          if (!pendingAuth) {
            return {
              content: [{
                type: "text" as const,
                text: `## No Pending Authentication\n\nPlease run \`argus_auth\` first to start the authentication flow.`,
              }],
              isError: true,
            };
          }

          // Check if expired
          if (new Date(pendingAuth.expires_at) < new Date()) {
            await this.ctx.storage.delete("pending_auth");
            return {
              content: [{
                type: "text" as const,
                text: `## Authentication Expired\n\nYour verification code has expired. Please run \`argus_auth\` again to get a new code.`,
              }],
              isError: true,
            };
          }

          // Poll the token endpoint (uses form-urlencoded)
          const response = await fetch(
            `${this.env.ARGUS_BRAIN_URL || "https://argus-brain-production.up.railway.app"}/api/v1/auth/device/token`,
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: "argus-mcp-server",
                device_code: pendingAuth.device_code,
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
              }).toString(),
            }
          );

          const data = await response.json() as {
            access_token?: string;
            expires_in?: number;
            error?: string;
            error_description?: string;
            user_id?: string;
          };

          if (data.error) {
            if (data.error === "authorization_pending") {
              return {
                content: [{
                  type: "text" as const,
                  text: `## Waiting for Authorization\n\nPlease complete sign-in at the Argus website, then run \`argus_auth_complete\` again.\n\n**Your code:** \`${pendingAuth.user_code}\``,
                }],
              };
            }
            throw new Error(data.error_description || data.error);
          }

          if (!data.access_token) {
            throw new Error("No access token received");
          }

          // Store the auth tokens in DO storage
          const authData = {
            access_token: data.access_token,
            expires_at: new Date(Date.now() + (data.expires_in || 3600) * 1000).toISOString(),
            user_id: data.user_id,
          };
          await this.ctx.storage.put("auth", JSON.stringify(authData));

          // Also update KV
          if (this.env.AUTH_STATE) {
            await this.env.AUTH_STATE.put(`auth_${pendingAuth.user_code}`, JSON.stringify({
              ...authData,
              status: "completed",
            }), { expirationTtl: data.expires_in || 3600 });
          }

          // Clear pending auth
          await this.ctx.storage.delete("pending_auth");

          // Register the MCP connection with the Brain API
          const sessionId = generateSessionId();
          const connectionId = await registerMCPConnection(
            this.env,
            data.access_token,
            sessionId,
            'Claude Code MCP'
          );

          // Store connection_id in DO storage if registration succeeded
          if (connectionId) {
            await this.ctx.storage.put("mcp_connection", JSON.stringify({
              connection_id: connectionId,
              session_id: sessionId,
              registered_at: new Date().toISOString(),
            }));
          }

          return {
            content: [{
              type: "text" as const,
              text: `## Authentication Successful!\n\nYou are now signed in to Argus.\n\n**You can now use:**\n- \`argus_projects\` - List your projects\n- \`argus_events\` - View production errors\n- \`argus_dashboard\` - Get project overview\n- And all other Argus tools!\n\n*Session expires in ${Math.floor((data.expires_in || 3600) / 60)} minutes*`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error completing authentication: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_auth_status - Check authentication status
    this.server.tool(
      "argus_auth_status",
      "Check your current authentication status with Argus.",
      {},
      async () => {
        try {
          const accessToken = await this.getAccessToken();

          if (!accessToken) {
            return {
              content: [{
                type: "text" as const,
                text: `## Not Authenticated\n\nYou are not currently signed in to Argus.\n\nRun \`argus_auth\` to sign in and access protected features.`,
              }],
            };
          }

          // Get auth details
          const authStr = await this.ctx.storage.get<string>("auth");
          const auth = authStr ? JSON.parse(authStr) : {};
          const expiresAt = auth.expires_at ? new Date(auth.expires_at) : null;
          const remainingTime = expiresAt ? Math.floor((expiresAt.getTime() - Date.now()) / 60000) : 0;

          return {
            content: [{
              type: "text" as const,
              text: `## Authenticated\n\nYou are signed in to Argus.\n\n**Session info:**\n- User ID: \`${auth.user_id || "Unknown"}\`\n- Expires in: ${remainingTime} minutes\n\n**Available features:**\n- Projects, Events, Tests, Dashboard\n- Quality Intelligence, Risk Scores\n- Self-Healing, Collaboration tools`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error checking auth status: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_auth_logout - Sign out from Argus
    this.server.tool(
      "argus_auth_logout",
      "Sign out from Argus and clear stored credentials.",
      {},
      async () => {
        try {
          // Clear all auth data from DO storage
          await this.ctx.storage.delete("auth");
          await this.ctx.storage.delete("pending_auth");

          return {
            content: [{
              type: "text" as const,
              text: `## Signed Out\n\nYou have been signed out from Argus.\n\nRun \`argus_auth\` to sign in again.`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error signing out: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // =========================================================================
    // CORE TOOLS - Health and basic operations
    // =========================================================================

    // Tool: argus_health - Check Argus API status
    this.server.tool(
      "argus_health",
      "Check the health and status of the Argus E2E testing API",
      {},
      async () => {
        try {
          const apiUrl = this.env.ARGUS_API_URL || "https://argus-api.samuelvinay-kumar.workers.dev";
          const response = await fetch(`${apiUrl}/health`);
          const data = await response.json();

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(data, null, 2),
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_discover - Discover interactive elements
    this.server.tool(
      "argus_discover",
      "Discover interactive elements and possible actions on a web page. Returns clickable buttons, links, form inputs, and other actionable elements.",
      {
        url: z.string().url().describe("The URL of the page to analyze"),
        instruction: z.string().optional().describe("What to look for (e.g., 'Find all buttons', 'Find the login form')"),
      },
      async ({ url, instruction }) => {
        try {
          const result = await callArgusAPI<ArgusObserveResponse>("/observe", {
            url,
            instruction: instruction || "What actions can I take on this page?",
          }, this.env);

          // Handle both Browser Pool format (success: true) and Cloudflare format (no success field)
          const hasData = result.actions?.length || result.elements?.length;
          if (result.success === false || (!hasData && result.error)) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Discovery failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Format the discovered actions (handle both formats)
          let formattedActions: string;
          if (result.actions?.length) {
            formattedActions = result.actions.map((action, i) =>
              `${i + 1}. ${action.description}\n   Selector: \`${action.selector}\`\n   Type: ${action.type || action.method || 'action'}${action.confidence ? `\n   Confidence: ${(action.confidence * 100).toFixed(0)}%` : ''}`
            ).join("\n\n");
          } else if (result.elements?.length) {
            // Cloudflare fallback format
            formattedActions = result.elements.map((el, i) =>
              `${i + 1}. ${el.text || el.tag}\n   Selector: \`${el.selector}\`\n   Type: ${el.tag}${el.attributes?.href ? `\n   Link: ${el.attributes.href}` : ''}`
            ).join("\n\n");
          } else {
            formattedActions = "No actions discovered";
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Discovered Elements on ${url}\n\n${formattedActions}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_act - Execute browser action
    this.server.tool(
      "argus_act",
      "Execute a browser action like clicking, typing, or navigating. Uses AI to find the right element based on natural language.",
      {
        url: z.string().url().describe("The URL of the page"),
        instruction: z.string().describe("What action to perform (e.g., 'Click the login button', 'Type \"hello\" in the search box')"),
        selfHeal: z.boolean().optional().describe("Enable self-healing selectors (default: true)"),
        screenshot: z.boolean().optional().describe("Capture a screenshot after the action (default: true)"),
      },
      async ({ url, instruction, selfHeal = true, screenshot = true }) => {
        const startTime = Date.now();
        try {
          const sessionId = generateSessionId();

          const result = await callArgusAPI<ArgusActResponse>("/act", {
            url,
            instruction,
            selfHeal,
            screenshot,
          }, this.env);

          if (!result.success) {
            // Record failed activity
            this.recordActivity("argus_act", {
              durationMs: Date.now() - startTime,
              success: false,
              errorMessage: result.error || "Unknown error",
              metadata: { url, instruction },
            });

            return {
              content: [
                {
                  type: "text" as const,
                  text: `Action failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Store screenshot in R2 if available
          let screenshotUrl: string | undefined;
          let screenshotKey: string | undefined;
          if (result.screenshot) {
            const uploaded = await storeScreenshot(
              this.env,
              result.screenshot,
              sessionId,
              "action",
              { instruction, url }
            );
            screenshotUrl = uploaded.url;
            screenshotKey = uploaded.key;
          }

          // Build screenshot section
          const screenshotSection = screenshotUrl
            ? `\n\n### Screenshot:\n[View Screenshot](${screenshotUrl})`
            : "";

          // Record successful activity
          this.recordActivity("argus_act", {
            durationMs: Date.now() - startTime,
            success: true,
            screenshotKey,
            metadata: { url, instruction, sessionId },
          });

          return {
            content: [
              {
                type: "text" as const,
                text: `## Action Result\n\n**Session ID:** ${sessionId}\n\n${result.message || "Action completed successfully"}\n\n### Actions Performed:\n${result.actions?.map(a => `- ${a.action}${a.selector ? ` on \`${a.selector}\`` : ""}${a.value ? ` with value "${a.value}"` : ""}: ${a.success ? "Success" : "Failed"}`).join("\n") || "None"}${screenshotSection}`,
              },
            ],
          };
        } catch (error) {
          // Record error activity
          this.recordActivity("argus_act", {
            durationMs: Date.now() - startTime,
            success: false,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            metadata: { url, instruction },
          });

          return this.handleError(error);
        }
      }
    );

    // Tool: argus_test - Run multi-step E2E test
    this.server.tool(
      "argus_test",
      "Run a multi-step E2E test on a web application. Executes a sequence of test steps and captures screenshots at each step. Returns detailed results including pass/fail status for each step.",
      {
        url: z.string().url().describe("The starting URL for the test"),
        steps: z.array(z.string()).min(1).describe("Array of test step instructions (e.g., ['Click the login button', 'Type \"user@example.com\" in email field', 'Click submit'])"),
        browser: z.enum(["chrome", "firefox", "safari", "edge"]).optional().describe("Browser to use (default: chrome)"),
      },
      async ({ url, steps, browser = "chrome" }) => {
        const startTime = Date.now();
        try {
          const sessionId = generateSessionId();

          const result = await callArgusAPI<ArgusTestResponse>("/test", {
            url,
            steps,
            browser,
            captureScreenshots: true,
          }, this.env);

          // Format step results
          const stepResults = result.steps?.map((step, i) => {
            const status = step.success ? "PASS" : "FAIL";
            const error = step.error ? `\n   Error: ${step.error}` : "";
            return `${i + 1}. [${status}] ${step.instruction}${error}`;
          }).join("\n") || "No steps executed";

          const overallStatus = result.success ? "PASSED" : "FAILED";
          const passedSteps = result.steps?.filter(s => s.success).length || 0;
          const totalSteps = result.steps?.length || 0;

          // Store screenshots in R2 and get URLs
          const screenshotUrls: string[] = [];
          const screenshotKeys: string[] = [];
          let finalScreenshotUrl: string | undefined;
          let finalScreenshotKey: string | undefined;

          // Store step screenshots if available
          if (result.steps) {
            for (let i = 0; i < result.steps.length; i++) {
              const step = result.steps[i];
              if (step.screenshot) {
                const uploaded = await storeScreenshot(
                  this.env,
                  step.screenshot,
                  sessionId,
                  i,
                  { stepName: step.instruction, url }
                );
                if (uploaded.url) {
                  screenshotUrls.push(uploaded.url);
                }
                if (uploaded.key) {
                  screenshotKeys.push(uploaded.key);
                }
              }
            }
          }

          // Store final screenshot
          if (result.finalScreenshot) {
            const uploaded = await storeScreenshot(
              this.env,
              result.finalScreenshot,
              sessionId,
              "final",
              { type: "final", url }
            );
            finalScreenshotUrl = uploaded.url;
            finalScreenshotKey = uploaded.key;
          }

          // Build screenshot section for response
          let screenshotSection = "";
          if (screenshotUrls.length > 0 || finalScreenshotUrl) {
            screenshotSection = "\n\n### Screenshots:";
            screenshotUrls.forEach((screenshotUrl, i) => {
              screenshotSection += `\n${i + 1}. [Step ${i + 1}](${screenshotUrl})`;
            });
            if (finalScreenshotUrl) {
              screenshotSection += `\n- [Final Screenshot](${finalScreenshotUrl})`;
            }
          }

          // Record activity
          this.recordActivity("argus_test", {
            durationMs: Date.now() - startTime,
            success: result.success,
            errorMessage: result.success ? undefined : result.error,
            screenshotKey: finalScreenshotKey || screenshotKeys[screenshotKeys.length - 1],
            metadata: {
              url,
              browser,
              sessionId,
              totalSteps,
              passedSteps,
              stepCount: steps.length,
            },
          });

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test Results: ${overallStatus}\n\n**Session ID:** ${sessionId}\n**Browser:** ${browser}\n**URL:** ${url}\n**Steps:** ${passedSteps}/${totalSteps} passed\n\n### Step Details:\n${stepResults}${screenshotSection}`,
              },
            ],
          };
        } catch (error) {
          // Record error activity
          this.recordActivity("argus_test", {
            durationMs: Date.now() - startTime,
            success: false,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            metadata: { url, browser, stepCount: steps.length },
          });

          return this.handleError(error);
        }
      }
    );

    // Tool: argus_extract - Extract data from page
    this.server.tool(
      "argus_extract",
      "Extract structured data from a web page using AI. Can extract specific information like product details, prices, user information, etc.",
      {
        url: z.string().url().describe("The URL of the page to extract data from"),
        instruction: z.string().describe("What data to extract (e.g., 'Extract all product names and prices', 'Get the user profile information')"),
        schema: z.record(z.string()).optional().describe("Expected data schema as key-value pairs (optional)"),
      },
      async ({ url, instruction, schema }) => {
        try {
          const result = await callArgusAPI<ArgusExtractResponse>("/extract", {
            url,
            instruction,
            schema: schema || {},
          }, this.env);

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Extraction failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Extracted Data from ${url}\n\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_agent - Autonomous task completion
    this.server.tool(
      "argus_agent",
      "Run an autonomous AI agent to complete a complex task on a website. The agent will navigate, click, type, and perform multiple actions to achieve the goal.",
      {
        url: z.string().url().describe("The starting URL"),
        instruction: z.string().describe("The task to complete (e.g., 'Sign up for a new account with email test@example.com', 'Add the first product to cart and proceed to checkout')"),
        maxSteps: z.number().min(1).max(30).optional().describe("Maximum number of steps to take (default: 10)"),
      },
      async ({ url, instruction, maxSteps = 10 }) => {
        const startTime = Date.now();
        try {
          const sessionId = generateSessionId();

          const result = await callArgusAPI<ArgusAgentResponse>("/agent", {
            url,
            instruction,
            maxSteps,
            captureScreenshots: true,
          }, this.env);

          const status = result.success && result.completed ? "COMPLETED" : result.success ? "IN PROGRESS" : "FAILED";

          // Format actions taken
          const actionsList = result.actions?.map((action, i) => {
            const icon = action.success ? "+" : "-";
            return `${i + 1}. [${icon}] ${action.action}`;
          }).join("\n") || "No actions recorded";

          // Store all screenshots in R2
          const screenshotUrls: string[] = [];
          const screenshotKeys: string[] = [];
          if (result.screenshots && result.screenshots.length > 0) {
            for (let i = 0; i < result.screenshots.length; i++) {
              const uploaded = await storeScreenshot(
                this.env,
                result.screenshots[i],
                sessionId,
                i,
                { step: String(i), url }
              );
              if (uploaded.url) {
                screenshotUrls.push(uploaded.url);
              }
              if (uploaded.key) {
                screenshotKeys.push(uploaded.key);
              }
            }
          }

          // Build screenshot section
          let screenshotSection = "";
          if (screenshotUrls.length > 0) {
            screenshotSection = "\n\n### Screenshots:";
            screenshotUrls.forEach((screenshotUrl, i) => {
              screenshotSection += `\n${i + 1}. [Step ${i + 1}](${screenshotUrl})`;
            });
          }

          // Record activity
          this.recordActivity("argus_agent", {
            durationMs: Date.now() - startTime,
            success: result.success,
            errorMessage: result.success ? undefined : result.error,
            screenshotKey: screenshotKeys[screenshotKeys.length - 1],
            inputTokens: result.usage?.inputTokens,
            outputTokens: result.usage?.outputTokens,
            metadata: {
              url,
              instruction,
              sessionId,
              maxSteps,
              actionsTaken: result.actions?.length || 0,
              completed: result.completed,
            },
          });

          return {
            content: [
              {
                type: "text" as const,
                text: `## Agent Task: ${status}\n\n**Session ID:** ${sessionId}\n**Goal:** ${instruction}\n**Starting URL:** ${url}\n**Steps taken:** ${result.actions?.length || 0}/${maxSteps}\n\n### Actions:\n${actionsList}\n\n${result.message ? `**Result:** ${result.message}` : ""}${screenshotSection}`,
              },
            ],
          };
        } catch (error) {
          // Record error activity
          this.recordActivity("argus_agent", {
            durationMs: Date.now() - startTime,
            success: false,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            metadata: { url, instruction, maxSteps },
          });

          return this.handleError(error);
        }
      }
    );

    // Tool: argus_generate_test - Generate test from natural language (Brain)
    this.server.tool(
      "argus_generate_test",
      "Generate E2E test steps from a natural language description. Uses AI Brain service to create a comprehensive test plan with steps and assertions.",
      {
        url: z.string().url().describe("The URL of the application to test"),
        description: z.string().describe("Description of what the test should verify (e.g., 'Verify user can log in with valid credentials', 'Test the checkout flow with a product')"),
      },
      async ({ url, description }) => {
        try {
          await this.requireAuth();
          // Call Brain to generate test from natural language
          const result = await this.callBrainAPIWithAuth<BrainTestCreateResponse>(
            "/api/v1/tests/create",
            "POST",
            {
              description,
              app_url: url,
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Could not generate test. Try using argus_discover first to understand the page.`,
                },
              ],
              isError: true,
            };
          }

          // Format the generated test
          const stepsText = result.test.steps.map((s, i) =>
            `${i + 1}. ${s.action}${s.target ? ` on "${s.target}"` : ""}${s.value ? ` with "${s.value}"` : ""}`
          ).join("\n");

          const assertionsText = result.test.assertions.map((a, i) =>
            `${i + 1}. ${a.type}${a.target ? ` "${a.target}"` : ""}${a.expected ? ` = "${a.expected}"` : ""}`
          ).join("\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Generated Test: ${result.test.name}\n\n**Target:** ${url}\n**Description:** ${result.test.description}\n\n### Test Steps:\n${stepsText}\n\n### Assertions:\n${assertionsText}\n\n**Tip:** Use \`argus_test\` with these steps to run the test.`,
              },
            ],
          };
        } catch (error) {
          // Fall back to Worker-based discovery if Brain fails
          try {
            const observeResult = await callArgusAPI<ArgusObserveResponse>("/observe", {
              url,
              instruction: "List all interactive elements and their purposes",
            }, this.env);

            const pageContext = observeResult.actions?.map(a => `- ${a.description} (${a.type})`).join("\n") || "No elements found";

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Test Plan (Discovery Mode)\n\n**Target:** ${url}\n**Objective:** ${description}\n\n### Discovered Page Elements:\n${pageContext}\n\n### Suggested Test Steps:\n1. Navigate to the page\n2. [Create steps based on the discovered elements]\n\n**Note:** Brain service unavailable. Use \`argus_test\` to run manually created steps.`,
                },
              ],
            };
          } catch (fallbackError) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Error generating test: ${error instanceof Error ? error.message : "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }
        }
      }
    );

    // Tool: argus_quality_score - Get quality score for a project (Brain)
    this.server.tool(
      "argus_quality_score",
      "Get the overall quality score and metrics for a project. Shows test coverage, risk level, and production error statistics.",
      {
        project_id: z.string().describe("The project UUID to get quality score for"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<BrainQualityScoreResponse>(
            `/api/v1/quality/score?project_id=${project_id}`,
            "GET",
            
          );

          const riskEmoji = result.risk_level === "high" ? "🔴" : result.risk_level === "medium" ? "🟡" : "🟢";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Quality Score: ${result.quality_score}/100\n\n**Risk Level:** ${riskEmoji} ${result.risk_level.toUpperCase()}\n**Test Coverage:** ${result.test_coverage}%\n\n### Metrics:\n- Total Production Events: ${result.total_events}\n- Generated Tests: ${result.total_tests}\n- Approved Tests: ${result.approved_tests}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_quality_stats - Get detailed quality statistics (Brain)
    this.server.tool(
      "argus_quality_stats",
      "Get detailed quality intelligence statistics including event counts by status, severity breakdown, and test coverage metrics.",
      {
        project_id: z.string().describe("The project UUID to get statistics for"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
            `/api/v1/quality/stats?project_id=${project_id}`,
            "GET",
            
          );

          const stats = result.stats;

          const statusBreakdown = Object.entries(stats.events_by_status)
            .map(([status, count]) => `- ${status}: ${count}`)
            .join("\n");

          const severityBreakdown = Object.entries(stats.events_by_severity)
            .map(([sev, count]) => `- ${sev}: ${count}`)
            .join("\n");

          const testsBreakdown = Object.entries(stats.tests_by_status)
            .map(([status, count]) => `- ${status}: ${count}`)
            .join("\n") || "No tests generated yet";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Quality Intelligence Statistics\n\n### Production Events: ${stats.total_events}\n\n**By Status:**\n${statusBreakdown}\n\n**By Severity:**\n${severityBreakdown}\n\n### Generated Tests: ${stats.total_generated_tests}\n\n**By Status:**\n${testsBreakdown}\n\n**Coverage Rate:** ${stats.coverage_rate}%`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_risk_scores - Calculate and get risk scores (Brain)
    this.server.tool(
      "argus_risk_scores",
      "Calculate risk scores for components and pages based on production errors. Identifies high-risk areas that need more testing.",
      {
        project_id: z.string().describe("The project UUID to calculate risk scores for"),
        calculate: z.boolean().optional().describe("If true, recalculate scores (default: false, just retrieve)"),
      },
      async ({ project_id, calculate = false }) => {
        try {
          await this.requireAuth();
          let result: BrainRiskScoresResponse;

          if (calculate) {
            // Recalculate risk scores
            result = await this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              "/api/v1/quality/calculate-risk",
              "POST",
              { project_id }
            );
          } else {
            // Just retrieve existing scores
            const response = await this.callBrainAPIWithAuth<{ risk_scores: BrainRiskScoresResponse["risk_scores"] }>(
              `/api/v1/quality/risk-scores?project_id=${project_id}`,
              "GET",
              
            );
            result = { success: true, risk_scores: response.risk_scores, total_entities: response.risk_scores.length };
          }

          if (!result.risk_scores || result.risk_scores.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Risk Scores\n\nNo risk data available yet. Production events need to be ingested via webhooks first.`,
                },
              ],
            };
          }

          const scoresText = result.risk_scores.slice(0, 10).map((score, i) => {
            const emoji = score.overall_score > 70 ? "🔴" : score.overall_score > 40 ? "🟡" : "🟢";
            return `${i + 1}. ${emoji} **${score.entity_identifier}** (${score.entity_type})\n   Score: ${score.overall_score}/100 | Errors: ${score.error_count} | Users affected: ${score.affected_users}`;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Risk Scores (Top ${Math.min(10, result.risk_scores.length)} of ${result.total_entities})\n\n${scoresText}\n\n**Legend:** 🔴 High Risk (>70) | 🟡 Medium Risk (40-70) | 🟢 Low Risk (<40)`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // SYNC TOOLS - Two-way IDE synchronization
    // =========================================================================

    // Tool: argus_sync_push - Push local test changes to Argus
    this.server.tool(
      "argus_sync_push",
      "Push local test changes to Argus cloud. Syncs test specifications from your IDE to the Argus platform for team collaboration and cloud execution.",
      {
        project_id: z.string().describe("The project UUID"),
        test_id: z.string().describe("The test UUID to push"),
        content: z.object({
          id: z.string(),
          name: z.string(),
          description: z.string().optional(),
          steps: z.array(z.object({
            action: z.string(),
            target: z.string().optional(),
            value: z.string().optional(),
          })),
          assertions: z.array(z.object({
            type: z.string(),
            target: z.string().optional(),
            expected: z.string().optional(),
          })).optional(),
          metadata: z.record(z.unknown()).optional(),
        }).describe("The test specification to push"),
        local_version: z.number().describe("Local version number for conflict detection"),
      },
      async ({ project_id, test_id, content, local_version }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<SyncPushResponse>(
            "/api/v1/sync/push",
            "POST",
            {
              project_id,
              test_id,
              content,
              local_version,
              source: "mcp",
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Push failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Check for conflicts
          if (result.conflicts && result.conflicts.length > 0) {
            const conflictsList = result.conflicts.map((c, i) =>
              `${i + 1}. Test: ${c.test_id}\n   Path: ${c.path.join(".")}\n   Local: ${JSON.stringify(c.local_value)}\n   Remote: ${JSON.stringify(c.remote_value)}`
            ).join("\n\n");

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Sync Conflicts Detected\n\nPushed ${result.events_pushed} events but ${result.conflicts.length} conflicts need resolution:\n\n${conflictsList}\n\n**Use \`argus_sync_resolve\` to resolve conflicts.**`,
                },
              ],
            };
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Push Successful\n\n**Test:** ${test_id}\n**Events pushed:** ${result.events_pushed}\n**New version:** ${result.new_version || "N/A"}\n\nTest is now synced with Argus cloud.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_sync_pull - Pull remote test changes
    this.server.tool(
      "argus_sync_pull",
      "Pull test changes from Argus cloud to your local IDE. Fetches the latest test specifications and updates from team members.",
      {
        project_id: z.string().describe("The project UUID to pull tests from"),
        since_version: z.number().optional().describe("Only pull changes since this version (default: 0 for all)"),
        test_id: z.string().optional().describe("Pull specific test only (optional)"),
      },
      async ({ project_id, since_version = 0, test_id }) => {
        try {
          await this.requireAuth();
          const queryParams = new URLSearchParams({
            project_id,
            since_version: since_version.toString(),
          });
          if (test_id) {
            queryParams.set("test_id", test_id);
          }

          const result = await this.callBrainAPIWithAuth<SyncPullResponse>(
            `/api/v1/sync/pull?${queryParams}`,
            "GET"
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Pull failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          if (result.events.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## No New Changes\n\nYour local tests are up to date with Argus cloud.`,
                },
              ],
            };
          }

          // Format events
          const eventsList = result.events.map((e, i) => {
            const icon = e.type.includes("created") ? "+" : e.type.includes("deleted") ? "-" : "~";
            return `${i + 1}. [${icon}] ${e.type} - Test: ${e.test_id}\n   Time: ${e.timestamp}`;
          }).join("\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Pulled ${result.events.length} Changes\n\n**New version:** ${result.new_version || "N/A"}\n\n### Changes:\n${eventsList}\n\n\`\`\`json\n${JSON.stringify(result.events, null, 2)}\n\`\`\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_sync_status - Get sync status
    this.server.tool(
      "argus_sync_status",
      "Get the synchronization status for a project. Shows pending changes, conflicts, and sync state for all tests.",
      {
        project_id: z.string().describe("The project UUID to check status for"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<SyncStatusResponse>(
            `/api/v1/sync/status/${project_id}`,
            "GET",
            
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Could not get sync status. The project may not exist or sync is not initialized.`,
                },
              ],
              isError: true,
            };
          }

          const statusEmoji = result.status === "synced" ? "✅" : result.status === "pending" ? "🔄" : result.status === "conflict" ? "⚠️" : "❌";

          // Format test statuses
          const testsStatus = Object.values(result.tests).map(t => {
            const icon = t.status === "synced" ? "✅" : t.status === "pending" ? "🔄" : "⚠️";
            return `- ${icon} ${t.test_id}: v${t.local_version} (local) / v${t.remote_version} (remote)${t.pending_changes > 0 ? ` - ${t.pending_changes} pending` : ""}${t.conflicts > 0 ? ` - ${t.conflicts} conflicts` : ""}`;
          }).join("\n") || "No tests tracked";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Sync Status: ${statusEmoji} ${result.status.toUpperCase()}\n\n**Project:** ${project_id}\n**Pending changes:** ${result.total_pending}\n**Conflicts:** ${result.total_conflicts}\n\n### Tests:\n${testsStatus}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_sync_resolve - Resolve sync conflicts
    this.server.tool(
      "argus_sync_resolve",
      "Resolve a synchronization conflict between local and remote test versions. Choose to keep local, keep remote, or provide a custom resolution.",
      {
        project_id: z.string().describe("The project UUID"),
        conflict_id: z.string().describe("The conflict ID to resolve"),
        strategy: z.enum(["keep_local", "keep_remote", "merge", "manual"]).describe("Resolution strategy"),
        manual_value: z.unknown().optional().describe("Custom value for manual resolution"),
      },
      async ({ project_id, conflict_id, strategy, manual_value }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<SyncResolveResponse>(
            "/api/v1/sync/resolve",
            "POST",
            {
              project_id,
              conflict_id,
              strategy,
              manual_value,
            }
          );

          if (!result.success || !result.resolved) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Resolution failed: ${result.error || "Could not resolve conflict"}`,
                },
              ],
              isError: true,
            };
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Conflict Resolved ✅\n\n**Conflict ID:** ${result.conflict_id}\n**Strategy:** ${strategy}\n**Resolved Value:**\n\`\`\`json\n${JSON.stringify(result.resolved_value, null, 2)}\n\`\`\`\n\nRun \`argus_sync_push\` to sync the resolved changes.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // EXPORT TOOLS - Multi-language test export
    // =========================================================================

    // Tool: argus_export - Export test to multiple languages
    this.server.tool(
      "argus_export",
      "Export an Argus test to executable code in multiple programming languages and frameworks. Supports Python, TypeScript, Java, C#, Ruby, and Go with various testing frameworks.",
      {
        test_id: z.string().describe("The test UUID to export"),
        language: z.enum(["python", "typescript", "java", "csharp", "ruby", "go"]).describe("Target programming language"),
        framework: z.string().describe("Testing framework (e.g., 'playwright', 'selenium', 'cypress', 'puppeteer', 'capybara', 'rod')"),
        options: z.object({
          include_comments: z.boolean().optional().describe("Include explanatory comments"),
          include_assertions: z.boolean().optional().describe("Include assertion code"),
          base_url_variable: z.string().optional().describe("Variable name for base URL"),
          class_name: z.string().optional().describe("Custom test class name"),
        }).optional().describe("Export options"),
      },
      async ({ test_id, language, framework, options = {} }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<ExportResponse>(
            "/api/v1/export/generate",
            "POST",
            {
              test_id,
              language,
              framework,
              options: {
                include_comments: options.include_comments ?? true,
                include_assertions: options.include_assertions ?? true,
                base_url_variable: options.base_url_variable ?? "BASE_URL",
                class_name: options.class_name,
              },
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Export failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          const importsSection = result.imports && result.imports.length > 0
            ? `### Required Imports/Dependencies:\n\`\`\`\n${result.imports.join("\n")}\n\`\`\`\n\n`
            : "";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Exported Test: ${result.filename}\n\n**Language:** ${result.language}\n**Framework:** ${result.framework}\n\n${importsSection}### Generated Code:\n\`\`\`${result.language}\n${result.code}\n\`\`\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_export_languages - List supported export languages
    this.server.tool(
      "argus_export_languages",
      "List all supported programming languages and testing frameworks for test export.",
      {},
      async () => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<ExportLanguagesResponse>(
            "/api/v1/export/languages",
            "GET",
            
          );

          const languagesList = result.languages.map(l =>
            `### ${l.name} (\`${l.id}\`)\nFrameworks: ${l.frameworks.join(", ")}`
          ).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Supported Export Languages\n\n${languagesList}\n\n**Usage:** \`argus_export(test_id, language, framework)\``,
              },
            ],
          };
        } catch (error) {
          // Return static list if API fails
          return {
            content: [
              {
                type: "text" as const,
                text: `## Supported Export Languages\n\n### Python (\`python\`)\nFrameworks: playwright, selenium\n\n### TypeScript (\`typescript\`)\nFrameworks: playwright, puppeteer, cypress\n\n### Java (\`java\`)\nFrameworks: selenium\n\n### C# (\`csharp\`)\nFrameworks: selenium, playwright\n\n### Ruby (\`ruby\`)\nFrameworks: capybara, selenium\n\n### Go (\`go\`)\nFrameworks: rod\n\n**Usage:** \`argus_export(test_id, language, framework)\``,
              },
            ],
          };
        }
      }
    );

    // =========================================================================
    // RECORDING TOOLS - Browser recording to test conversion
    // =========================================================================

    // Tool: argus_recording_to_test - Convert browser recording to test
    this.server.tool(
      "argus_recording_to_test",
      "Convert a browser recording (rrweb format) to an Argus test. Analyzes DOM events from recorded sessions and generates executable test steps. Zero AI cost - pure DOM event parsing.",
      {
        recording: z.object({
          events: z.array(z.object({
            type: z.number(),
            data: z.record(z.unknown()),
            timestamp: z.number(),
          })).describe("rrweb event array"),
          metadata: z.object({
            duration: z.number().optional(),
            startTime: z.string().optional(),
            url: z.string().optional(),
          }).optional(),
        }).describe("The rrweb recording data"),
        options: z.object({
          name: z.string().optional().describe("Test name (auto-generated if not provided)"),
          filter_actions: z.array(z.string()).optional().describe("Only include these action types"),
          min_confidence: z.number().optional().describe("Minimum selector confidence (0-1)"),
          deduplicate: z.boolean().optional().describe("Remove duplicate consecutive actions"),
        }).optional(),
      },
      async ({ recording, options = {} }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<RecordingConvertResponse>(
            "/api/v1/recording/convert",
            "POST",
            {
              recording,
              options: {
                name: options.name,
                filter_actions: options.filter_actions,
                min_confidence: options.min_confidence ?? 0.7,
                deduplicate: options.deduplicate ?? true,
              },
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Conversion failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Format steps
          const stepsText = result.test.steps.map((s, i) =>
            `${i + 1}. ${s.action}${s.target ? ` on "${s.target}"` : ""}${s.value ? ` with "${s.value}"` : ""}`
          ).join("\n");

          const assertionsText = result.test.assertions?.map((a, i) =>
            `${i + 1}. ${a.type}${a.target ? ` "${a.target}"` : ""}${a.expected ? ` = "${a.expected}"` : ""}`
          ).join("\n") || "None generated";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test Generated from Recording ✨\n\n**Test ID:** ${result.test.id}\n**Name:** ${result.test.name}\n**Source:** ${result.test.source}\n**Recording ID:** ${result.recording_id}\n**Duration:** ${(result.duration_ms / 1000).toFixed(1)}s\n**Events processed:** ${result.events_processed}\n\n### Test Steps (${result.test.steps.length}):\n${stepsText}\n\n### Auto-Generated Assertions:\n${assertionsText}\n\n**Tip:** Use \`argus_test\` to run this test or \`argus_export\` to convert to code.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_recording_snippet - Get recorder snippet for websites
    this.server.tool(
      "argus_recording_snippet",
      "Generate a JavaScript snippet to record user sessions on any website. The snippet uses rrweb for DOM-based recording that can be converted to tests.",
      {
        project_id: z.string().describe("The project UUID to associate recordings with"),
        options: z.object({
          mask_inputs: z.boolean().optional().describe("Mask sensitive input fields"),
          record_canvas: z.boolean().optional().describe("Record canvas elements"),
          sample_rate: z.number().optional().describe("Sampling rate for mouse movements"),
        }).optional(),
      },
      async ({ project_id, options = {} }) => {
        const snippet = `<!-- Argus Session Recorder -->
<script src="https://cdn.jsdelivr.net/npm/rrweb@latest/dist/rrweb.min.js"></script>
<script>
(function() {
  const events = [];
  const projectId = "${project_id}";

  // Start recording
  rrweb.record({
    emit(event) {
      events.push(event);
    },
    maskAllInputs: ${options.mask_inputs ?? true},
    recordCanvas: ${options.record_canvas ?? false},
    sampling: {
      mousemove: ${options.sample_rate ?? 50}
    }
  });

  // Upload recording on page unload or after 5 minutes
  const uploadRecording = () => {
    if (events.length > 0) {
      navigator.sendBeacon(
        "https://argus-brain-production.up.railway.app/api/v1/recording/upload",
        JSON.stringify({
          project_id: projectId,
          recording: { events, metadata: { url: window.location.href } }
        })
      );
    }
  };

  window.addEventListener("beforeunload", uploadRecording);
  setTimeout(uploadRecording, 300000); // 5 min max

  // Export for manual control
  window.ArgusRecorder = {
    stop: uploadRecording,
    getEvents: () => events
  };
})();
</script>`;

        return {
          content: [
            {
              type: "text" as const,
              text: `## Argus Recording Snippet\n\nAdd this snippet to your website to record user sessions:\n\n\`\`\`html\n${snippet}\n\`\`\`\n\n### Usage:\n1. Add the snippet before \`</body>\`\n2. User sessions are auto-recorded\n3. Use \`argus_recording_to_test\` to convert to tests\n\n### Manual Control:\n- \`window.ArgusRecorder.stop()\` - Stop and upload\n- \`window.ArgusRecorder.getEvents()\` - Get events array`,
            },
          ],
        };
      }
    );

    // =========================================================================
    // COLLABORATION TOOLS - Real-time team collaboration
    // =========================================================================

    // Tool: argus_presence - Get/update user presence
    this.server.tool(
      "argus_presence",
      "Get or update user presence information for real-time collaboration. See who else is viewing or editing tests in your workspace.",
      {
        workspace_id: z.string().describe("The workspace UUID"),
        action: z.enum(["get", "join", "leave", "update"]).describe("Presence action"),
        user_id: z.string().optional().describe("User ID (required for join/leave/update)"),
        user_name: z.string().optional().describe("User display name (required for join)"),
        test_id: z.string().optional().describe("Currently viewed test ID"),
        cursor: z.object({
          step_index: z.number().optional(),
          field: z.string().optional(),
        }).optional().describe("Current cursor position"),
      },
      async ({ workspace_id, action, user_id, user_name, test_id, cursor }) => {
        try {
          await this.requireAuth();
          if (action === "get") {
            const result = await this.callBrainAPIWithAuth<PresenceResponse>(
              `/api/v1/collaboration/presence/${workspace_id}`,
              "GET",
              
            );

            if (result.users.length === 0) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `## Workspace Presence\n\nNo other users currently online in this workspace.`,
                  },
                ],
              };
            }

            const usersList = result.users.map(u => {
              const statusIcon = u.status === "online" ? "🟢" : u.status === "idle" ? "🟡" : "⚫";
              const location = u.test_id ? `viewing ${u.test_id}` : "in workspace";
              return `${statusIcon} **${u.user_name}** - ${location}`;
            }).join("\n");

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Workspace Presence (${result.users.length} online)\n\n${usersList}`,
                },
              ],
            };
          }

          // Join/Leave/Update actions
          const result = await this.callBrainAPIWithAuth<{ success: boolean }>(
            "/api/v1/collaboration/presence",
            "POST",
            {
              workspace_id,
              action,
              user_id,
              user_name,
              test_id,
              cursor,
            }
          );

          const actionText = action === "join" ? "joined" : action === "leave" ? "left" : "updated presence in";

          return {
            content: [
              {
                type: "text" as const,
                text: `Successfully ${actionText} workspace.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_comments - Manage test comments
    this.server.tool(
      "argus_comments",
      "Get or add comments on tests for team collaboration. Support for threaded discussions, @mentions, and resolution tracking.",
      {
        test_id: z.string().describe("The test UUID"),
        action: z.enum(["get", "add", "reply", "resolve"]).describe("Comment action"),
        comment_id: z.string().optional().describe("Comment ID (for reply/resolve)"),
        content: z.string().optional().describe("Comment content (for add/reply)"),
        step_index: z.number().optional().describe("Step index to attach comment to"),
        mentions: z.array(z.string()).optional().describe("User IDs to mention"),
      },
      async ({ test_id, action, comment_id, content, step_index, mentions }) => {
        try {
          await this.requireAuth();
          if (action === "get") {
            const result = await this.callBrainAPIWithAuth<CommentsResponse>(
              `/api/v1/collaboration/comments/${test_id}`,
              "GET",
              
            );

            if (result.comments.length === 0) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `## Test Comments\n\nNo comments on this test yet. Use \`argus_comments\` with action "add" to start a discussion.`,
                  },
                ],
              };
            }

            const commentsList = result.comments.map(c => {
              const resolved = c.resolved ? " ✅" : "";
              const stepRef = c.step_index !== undefined ? ` (Step ${c.step_index + 1})` : "";
              const replies = c.replies && c.replies.length > 0
                ? `\n  └─ ${c.replies.length} replies`
                : "";
              return `- **${c.author_name}**${stepRef}${resolved}: ${c.content}${replies}`;
            }).join("\n");

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Test Comments (${result.comments.length})\n\n${commentsList}`,
                },
              ],
            };
          }

          // Add/Reply/Resolve actions
          const result = await this.callBrainAPIWithAuth<{ success: boolean; comment_id?: string }>(
            "/api/v1/collaboration/comments",
            "POST",
            {
              test_id,
              action,
              comment_id,
              content,
              step_index,
              mentions,
            }
          );

          const actionText = action === "add" ? "Comment added" : action === "reply" ? "Reply added" : "Comment resolved";

          return {
            content: [
              {
                type: "text" as const,
                text: `${actionText} successfully.${result.comment_id ? ` (ID: ${result.comment_id})` : ""}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // PRODUCTION EVENTS - Query and manage production errors
    // =========================================================================

    // Tool: argus_events - List and filter production events
    this.server.tool(
      "argus_events",
      "List production errors and events that need test coverage. Filter by severity, status, or time range to find what needs attention. This is your window into what's breaking in production.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.enum(["new", "analyzing", "test_pending_review", "test_generated", "ignored"]).optional().describe("Filter by status"),
        severity: z.enum(["fatal", "error", "warning"]).optional().describe("Filter by severity"),
        source: z.string().optional().describe("Filter by source (sentry, datadog, etc.)"),
        limit: z.number().min(1).max(100).optional().describe("Max results (default: 20)"),
      },
      async ({ project_id, status, severity, source, limit = 20 }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id, limit: limit.toString() });
          if (status) params.set("status", status);
          if (severity) params.set("severity", severity);
          if (source) params.set("source", source);

          const result = await this.callBrainAPIWithAuth<ProductionEventsResponse>(
            `/api/v1/quality/events?${params}`,
            "GET"
          );

          if (!result.events || result.events.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Production Events\n\nNo events found matching your criteria. Your app is running clean! 🎉\n\n**Tip:** Set up webhooks from Sentry/Datadog to start capturing production errors.`,
                },
              ],
            };
          }

          const eventsList = result.events.map((e, i) => {
            const severityIcon = e.severity === "fatal" ? "🔴" : e.severity === "error" ? "🟠" : "🟡";
            const statusIcon = e.status === "test_generated" ? "✅" : e.status === "test_pending_review" ? "⏳" : "❌";
            return `${i + 1}. ${severityIcon} **${e.title}**\n   Status: ${statusIcon} ${e.status} | Occurrences: ${e.occurrence_count} | Users: ${e.affected_users}\n   Component: ${e.component || "Unknown"} | Source: ${e.source}\n   ID: \`${e.id}\``;
          }).join("\n\n");

          const newCount = result.events.filter(e => e.status === "new").length;
          const summary = newCount > 0 
            ? `⚠️ **${newCount} events need tests!** Use \`argus_test_from_event\` to generate tests.`
            : "All events have been processed.";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Production Events (${result.events.length} found)\n\n${summary}\n\n${eventsList}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_test_from_event - Generate test from production error
    this.server.tool(
      "argus_test_from_event",
      "Generate an E2E test from a specific production error. The AI analyzes the error context, stack trace, and user action to create a comprehensive test that prevents regression.",
      {
        event_id: z.string().describe("The production event UUID to generate test from"),
        project_id: z.string().describe("The project UUID"),
        framework: z.enum(["playwright", "cypress", "jest"]).optional().describe("Test framework (default: playwright)"),
      },
      async ({ event_id, project_id, framework = "playwright" }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            message: string;
            generated_test?: {
              id: string;
              name: string;
              file_path: string;
              confidence_score: number;
            };
            test_code?: string;
          }>(
            "/api/v1/quality/generate-test",
            "POST",
            {
              production_event_id: event_id,
              project_id,
              framework,
            }
          );

          if (!result.success || !result.generated_test) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Test Generation Failed\n\n${result.message || "Could not generate test from this event."}\n\n**Tip:** Make sure the event has enough context (URL, stack trace, component).`,
                },
              ],
              isError: true,
            };
          }

          const confidenceEmoji = result.generated_test.confidence_score > 0.8 ? "🟢" : result.generated_test.confidence_score > 0.6 ? "🟡" : "🔴";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test Generated Successfully! 🎉\n\n**Name:** ${result.generated_test.name}\n**File:** \`${result.generated_test.file_path}\`\n**Confidence:** ${confidenceEmoji} ${(result.generated_test.confidence_score * 100).toFixed(0)}%\n**Framework:** ${framework}\n\n### Generated Code:\n\`\`\`typescript\n${result.test_code || "// Code available in the dashboard"}\n\`\`\`\n\n**Next Steps:**\n1. Review the test with \`argus_tests\`\n2. Approve with \`argus_test_review\`\n3. Export to your repo with \`argus_export\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_event_triage - AI-powered event triage
    this.server.tool(
      "argus_event_triage",
      "Get AI-powered triage recommendations for production events. Identifies which errors are most critical, suggests groupings, and recommends test priorities.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().min(1).max(50).optional().describe("Max events to analyze (default: 10)"),
      },
      async ({ project_id, limit = 10 }) => {
        try {
          await this.requireAuth();
          // Get events and risk scores to provide triage recommendations
          const [eventsResult, riskResult] = await Promise.all([
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&status=new&limit=${limit}`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              `/api/v1/quality/risk-scores?project_id=${project_id}&limit=10`,
              "GET"
            ),
          ]);

          const events = eventsResult.events || [];
          const riskScores = riskResult.risk_scores || [];

          if (events.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Event Triage\n\n✅ **No untriaged events!** All production errors have been processed.\n\nYour test coverage is keeping production stable.`,
                },
              ],
            };
          }

          // Group events by severity and component
          const fatalEvents = events.filter(e => e.severity === "fatal");
          const errorEvents = events.filter(e => e.severity === "error");
          const warningEvents = events.filter(e => e.severity === "warning");

          // Create triage recommendations
          let triageText = `## Event Triage Report\n\n`;
          triageText += `**${events.length} events need attention**\n\n`;

          if (fatalEvents.length > 0) {
            triageText += `### 🔴 CRITICAL (${fatalEvents.length})\nThese are crashing your app for users!\n`;
            fatalEvents.forEach(e => {
              triageText += `- **${e.title}** - ${e.affected_users} users affected\n  \`${e.id}\`\n`;
            });
            triageText += "\n";
          }

          if (errorEvents.length > 0) {
            triageText += `### 🟠 HIGH PRIORITY (${errorEvents.length})\nThese are causing errors but not crashes.\n`;
            errorEvents.slice(0, 5).forEach(e => {
              triageText += `- **${e.title}** - ${e.occurrence_count} occurrences\n`;
            });
            triageText += "\n";
          }

          if (warningEvents.length > 0) {
            triageText += `### 🟡 MEDIUM PRIORITY (${warningEvents.length})\nWarnings that might become errors.\n`;
          }

          // Add risk context
          if (riskScores.length > 0) {
            const topRisk = riskScores[0];
            triageText += `\n### 🎯 Recommended Focus\nHighest risk area: **${topRisk.entity_identifier}** (Risk: ${topRisk.overall_score}/100)\n`;
          }

          triageText += `\n**Quick Actions:**\n`;
          triageText += `- Generate tests: \`argus_test_from_event(event_id, project_id)\`\n`;
          triageText += `- Batch generate: \`argus_batch_generate(project_id)\`\n`;

          return {
            content: [
              {
                type: "text" as const,
                text: triageText,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // SELF-HEALING - Configuration and pattern management
    // =========================================================================

    // Tool: argus_healing_config - Get/update self-healing configuration
    this.server.tool(
      "argus_healing_config",
      "View or update self-healing configuration. Control how Argus automatically fixes broken selectors, handles timeouts, and learns from patterns.",
      {
        organization_id: z.string().describe("The organization UUID"),
        project_id: z.string().optional().describe("Project-specific config (optional)"),
        action: z.enum(["get", "update"]).describe("Get or update configuration"),
        config: z.object({
          enabled: z.boolean().optional(),
          auto_apply: z.boolean().optional(),
          min_confidence_auto: z.number().optional(),
          heal_selectors: z.boolean().optional(),
          heal_timeouts: z.boolean().optional(),
          learn_from_success: z.boolean().optional(),
          notify_on_heal: z.boolean().optional(),
          require_approval: z.boolean().optional(),
        }).optional().describe("Configuration updates (for update action)"),
      },
      async ({ organization_id, project_id, action, config }) => {
        try {
          await this.requireAuth();
          if (action === "get") {
            const params = project_id ? `?project_id=${project_id}` : "";
            const result = await this.callBrainAPIWithAuth<HealingConfigResponse>(
              `/api/v1/healing/organizations/${organization_id}/config${params}`,
              "GET"
            );

            const statusEmoji = result.enabled ? "🟢 Enabled" : "🔴 Disabled";
            const autoApplyEmoji = result.auto_apply ? "✅ Auto" : "👤 Manual";

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Self-Healing Configuration\n\n**Status:** ${statusEmoji}\n**Application:** ${autoApplyEmoji}\n\n### Settings:\n- Min confidence (auto): ${(result.min_confidence_auto * 100).toFixed(0)}%\n- Min confidence (suggest): ${(result.min_confidence_suggest * 100).toFixed(0)}%\n- Heal selectors: ${result.heal_selectors ? "Yes" : "No"}\n- Heal timeouts: ${result.heal_timeouts ? "Yes" : "No"}\n- Heal text content: ${result.heal_text_content ? "Yes" : "No"}\n- Learn from success: ${result.learn_from_success ? "Yes" : "No"}\n\n### Notifications:\n- Notify on heal: ${result.notify_on_heal ? "Yes" : "No"}\n- Require approval: ${result.require_approval ? "Yes" : "No"}`,
                },
              ],
            };
          }

          // Update config - Backend uses PUT method
          const result = await this.callBrainAPIWithAuth<HealingConfigResponse>(
            `/api/v1/healing/organizations/${organization_id}/config${project_id ? `?project_id=${project_id}` : ""}`,
            "PUT",
            config || {}
          );

          return {
            content: [
              {
                type: "text" as const,
                text: `## Configuration Updated ✅\n\nSelf-healing is now ${result.enabled ? "enabled" : "disabled"}.\n\nChanges will take effect immediately for new test runs.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_healing_patterns - List learned healing patterns
    this.server.tool(
      "argus_healing_patterns",
      "View learned self-healing patterns. These are selector fixes that Argus has learned from past test runs and can apply automatically.",
      {
        organization_id: z.string().describe("The organization UUID"),
        project_id: z.string().optional().describe("Filter by project"),
        min_confidence: z.number().min(0).max(1).optional().describe("Minimum confidence filter (default: 0.5)"),
        limit: z.number().min(1).max(100).optional().describe("Max patterns (default: 20)"),
      },
      async ({ organization_id, project_id, min_confidence = 0.5, limit = 20 }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({
            min_confidence: min_confidence.toString(),
            limit: limit.toString(),
          });
          if (project_id) params.set("project_id", project_id);

          // Backend returns array directly, not wrapped
          const result = await this.callBrainAPIWithAuth<HealingPatternsResponse["patterns"]>(
            `/api/v1/healing/organizations/${organization_id}/patterns?${params}`,
            "GET"
          );

          // Handle both array response and wrapped response
          const patterns = Array.isArray(result) ? result : (result as unknown as { patterns: HealingPatternsResponse["patterns"] }).patterns || [];

          if (patterns.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Healing Patterns\n\nNo patterns learned yet. As tests run and selectors break, Argus will learn how to fix them automatically.\n\n**Tip:** Run tests with self-healing enabled to start building patterns.`,
                },
              ],
            };
          }

          const patternsList = patterns.map((p, i) => {
            const confidenceEmoji = p.confidence > 0.9 ? "🟢" : p.confidence > 0.7 ? "🟡" : "🔴";
            const successRate = p.success_count / (p.success_count + p.failure_count) * 100;
            return `${i + 1}. ${confidenceEmoji} **${p.error_type}** (${(p.confidence * 100).toFixed(0)}% confident)\n   From: \`${p.original_selector.slice(0, 40)}...\`\n   To: \`${p.healed_selector.slice(0, 40)}...\`\n   Success: ${successRate.toFixed(0)}% (${p.success_count}/${p.success_count + p.failure_count})`;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Healing Patterns (${patterns.length} learned)\n\n${patternsList}\n\n**Legend:** 🟢 High confidence | 🟡 Medium | 🔴 Low`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_healing_stats - Get healing statistics
    this.server.tool(
      "argus_healing_stats",
      "Get comprehensive self-healing statistics. See how many tests have been healed, success rates, and trends over time.",
      {
        organization_id: z.string().describe("The organization UUID"),
        project_id: z.string().optional().describe("Filter by project"),
      },
      async ({ organization_id, project_id }) => {
        try {
          await this.requireAuth();
          const params = project_id ? `?project_id=${project_id}` : "";
          const result = await this.callBrainAPIWithAuth<HealingStatsResponse>(
            `/api/v1/healing/organizations/${organization_id}/stats${params}`,
            "GET"
          );

          const successEmoji = result.success_rate > 80 ? "🟢" : result.success_rate > 50 ? "🟡" : "🔴";

          let errorTypesText = "";
          if (Object.keys(result.top_error_types).length > 0) {
            errorTypesText = "\n### Top Error Types:\n" +
              Object.entries(result.top_error_types)
                .map(([type, count]) => `- ${type}: ${count}`)
                .join("\n");
          }

          let recentHealsText = "";
          if (result.recent_heals && result.recent_heals.length > 0) {
            recentHealsText = "\n### Recent Heals:\n" +
              result.recent_heals.slice(0, 5)
                .map(h => `- ${h.error_type}: \`${h.original.slice(0, 30)}...\` → \`${h.healed.slice(0, 30)}...\``)
                .join("\n");
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Self-Healing Statistics\n\n### Overview:\n- **Total Patterns:** ${result.total_patterns}\n- **Total Heals Applied:** ${result.total_heals_applied}\n- **Success Rate:** ${successEmoji} ${result.success_rate.toFixed(1)}%\n- **Avg Confidence:** ${(result.avg_confidence * 100).toFixed(0)}%\n\n### Activity:\n- Last 24 hours: ${result.heals_last_24h} heals\n- Last 7 days: ${result.heals_last_7d} heals${errorTypesText}${recentHealsText}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_healing_review - Approve or reject healing suggestions
    this.server.tool(
      "argus_healing_review",
      "Review and approve/reject healing suggestions. When require_approval is enabled, heals wait for human review before being applied.",
      {
        organization_id: z.string().describe("The organization UUID"),
        pattern_id: z.string().describe("The pattern UUID to review"),
        action: z.enum(["approve", "reject"]).describe("Approve or reject the healing"),
      },
      async ({ organization_id, pattern_id, action }) => {
        try {
          const endpoint = action === "approve" ? "approve" : "reject";
          const result = await this.callBrainAPIWithAuth<{ success: boolean; message: string }>(
            `/api/v1/healing/organizations/${organization_id}/${endpoint}/${pattern_id}`,
            "POST",
            {}
          );

          const emoji = action === "approve" ? "✅" : "❌";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Healing ${action === "approve" ? "Approved" : "Rejected"} ${emoji}\n\n${result.message}\n\n${action === "approve" 
                  ? "This pattern will now be applied automatically in future test runs."
                  : "This pattern has been marked as unreliable and won't be used."}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // PROJECT MANAGEMENT - List and switch contexts
    // =========================================================================

    // Tool: argus_projects - List all projects
    this.server.tool(
      "argus_projects",
      "List all projects you have access to. Projects organize tests, events, and configurations for different applications.",
      {
        organization_id: z.string().optional().describe("Filter by organization (optional)"),
      },
      async ({ organization_id }) => {
        try {
          await this.requireAuth();
          const params = organization_id ? `?organization_id=${organization_id}` : "";
          // Backend returns array directly, not wrapped in { projects: [...] }
          const result = await this.callBrainAPIWithAuth<ProjectsResponse["projects"]>(
            `/api/v1/projects${params}`,
            "GET"
          );

          // Handle both array response and wrapped response
          const projects = Array.isArray(result) ? result : (result as unknown as ProjectsResponse).projects || [];

          if (projects.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Projects\n\nNo projects found. Create a project in the Argus dashboard to get started.\n\n**Tip:** Each project typically maps to one application or microservice.`,
                },
              ],
            };
          }

          const projectsList = projects.map((p, i) => {
            return `${i + 1}. **${p.name}**\n   ${p.description || "No description"}\n   URL: ${p.app_url || "Not set"}\n   Tests: ${p.test_count || 0} | Events: ${p.event_count || 0}\n   ID: \`${p.id}\``;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Your Projects (${projects.length})\n\n${projectsList}\n\n**Tip:** Use the project ID with other commands like \`argus_events\`, \`argus_tests\`, etc.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // TEST MANAGEMENT - List, review, and manage tests
    // =========================================================================

    // Tool: argus_tests - List tests with filters
    this.server.tool(
      "argus_tests",
      "List generated tests for a project. Filter by status to find tests pending review, approved tests, or rejected ones.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.enum(["pending", "approved", "rejected", "modified"]).optional().describe("Filter by review status"),
        limit: z.number().min(1).max(100).optional().describe("Max results (default: 20)"),
      },
      async ({ project_id, status, limit = 20 }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id, limit: limit.toString() });
          if (status) params.set("status", status);

          const result = await this.callBrainAPIWithAuth<GeneratedTestsResponse>(
            `/api/v1/quality/generated-tests?${params}`,
            "GET",
            
          );

          const tests = result.tests || [];

          if (tests.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Generated Tests\n\nNo tests found${status ? ` with status "${status}"` : ""}.\n\n**Tip:** Use \`argus_test_from_event\` or \`argus_generate_test\` to create tests from production errors.`,
                },
              ],
            };
          }

          const pendingCount = tests.filter(t => t.status === "pending").length;
          const statusBanner = pendingCount > 0 
            ? `⚠️ **${pendingCount} tests need review!**\n\n`
            : "";

          const testsList = tests.map((t, i) => {
            const statusIcon = t.status === "approved" ? "✅" : t.status === "pending" ? "⏳" : t.status === "rejected" ? "❌" : "✏️";
            const confidenceEmoji = t.confidence_score > 0.8 ? "🟢" : t.confidence_score > 0.6 ? "🟡" : "🔴";
            return `${i + 1}. ${statusIcon} **${t.name}**\n   Confidence: ${confidenceEmoji} ${(t.confidence_score * 100).toFixed(0)}% | Framework: ${t.framework}\n   File: \`${t.test_file_path || "Not generated"}\`\n   ID: \`${t.id}\``;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Generated Tests (${tests.length})\n\n${statusBanner}${testsList}\n\n**Actions:**\n- Review: \`argus_test_review(test_id, action)\`\n- Export: \`argus_export(test_id, language, framework)\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_test_review - Approve/reject/modify generated tests
    this.server.tool(
      "argus_test_review",
      "Review a generated test - approve it for use, reject it, or modify the code. Approved tests can be exported and run in CI.",
      {
        test_id: z.string().describe("The generated test UUID"),
        action: z.enum(["approve", "reject", "modify"]).describe("Review action"),
        review_notes: z.string().optional().describe("Notes about your review decision"),
        modified_code: z.string().optional().describe("Modified test code (for modify action)"),
      },
      async ({ test_id, action, review_notes, modified_code }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ success: boolean; message: string }>(
            "/api/v1/quality/update-test",
            "POST",
            {
              test_id,
              action,
              review_notes,
              modified_code,
            }
          );

          const emoji = action === "approve" ? "✅" : action === "reject" ? "❌" : "✏️";
          const actionText = action === "approve" ? "approved" : action === "reject" ? "rejected" : "modified";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test ${actionText.charAt(0).toUpperCase() + actionText.slice(1)} ${emoji}\n\n${result.message}\n\n${action === "approve" 
                  ? "**Next:** Export this test with `argus_export` to add it to your test suite."
                  : action === "modify"
                  ? "Your changes have been saved. Review again when ready to approve."
                  : "This test won't be used. Consider regenerating with more context."}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // SMART INSIGHTS - AI-powered recommendations
    // =========================================================================

    // Tool: argus_what_to_test - AI recommendations on what to test
    this.server.tool(
      "argus_what_to_test",
      "Get AI-powered recommendations on what to test next. Analyzes risk scores, recent errors, and coverage gaps to prioritize testing efforts.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          // Gather data for recommendations
          const [eventsResult, riskResult, statsResult] = await Promise.all([
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&status=new&limit=10`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              `/api/v1/quality/risk-scores?project_id=${project_id}&limit=5`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
              `/api/v1/quality/stats?project_id=${project_id}`,
              "GET"
            ),
          ]);

          const events = eventsResult.events || [];
          const riskScores = riskResult.risk_scores || [];
          const stats = statsResult.stats;

          let recommendations = `## What to Test Next 🎯\n\n`;

          // Priority 1: High-risk areas without tests
          if (riskScores.length > 0) {
            const highRisk = riskScores.filter(r => r.overall_score > 70);
            if (highRisk.length > 0) {
              recommendations += `### 🔴 Critical Priority\nHigh-risk areas that need immediate test coverage:\n\n`;
              highRisk.forEach(r => {
                recommendations += `- **${r.entity_identifier}** (${r.entity_type})\n  Risk: ${r.overall_score}/100 | Errors: ${r.error_count} | Users: ${r.affected_users}\n`;
              });
              recommendations += "\n";
            }
          }

          // Priority 2: Recent production errors
          if (events.length > 0) {
            const fatalErrors = events.filter(e => e.severity === "fatal");
            const recentErrors = events.slice(0, 5);
            
            if (fatalErrors.length > 0) {
              recommendations += `### 🟠 Fatal Errors (${fatalErrors.length})\nThese are crashing your app:\n\n`;
              fatalErrors.forEach(e => {
                recommendations += `- **${e.title}**\n  ${e.affected_users} users affected | \`${e.id}\`\n`;
              });
              recommendations += "\n";
            } else if (recentErrors.length > 0) {
              recommendations += `### 🟡 Recent Errors (${recentErrors.length})\nNew errors that need test coverage:\n\n`;
              recentErrors.forEach(e => {
                recommendations += `- **${e.title}** (${e.severity})\n`;
              });
              recommendations += "\n";
            }
          }

          // Summary with action items
          recommendations += `### 📊 Coverage Summary\n`;
          recommendations += `- Total events: ${stats.total_events}\n`;
          recommendations += `- Tests generated: ${stats.total_generated_tests}\n`;
          recommendations += `- Coverage rate: ${stats.coverage_rate}%\n\n`;

          recommendations += `### 💡 Quick Actions\n`;
          if (events.length > 0) {
            recommendations += `- Generate tests for all new events: Use \`argus_batch_generate\`\n`;
          }
          if (stats.coverage_rate < 50) {
            recommendations += `- Low coverage! Focus on high-risk areas first\n`;
          }
          if (stats.tests_by_status && stats.tests_by_status["pending"] > 0) {
            recommendations += `- Review ${stats.tests_by_status["pending"]} pending tests with \`argus_tests\`\n`;
          }

          return {
            content: [
              {
                type: "text" as const,
                text: recommendations,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_coverage_gaps - Find untested areas
    this.server.tool(
      "argus_coverage_gaps",
      "Identify areas of your application that have production errors but no test coverage. These are your blind spots.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const [eventsResult, testsResult] = await Promise.all([
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&limit=100`,
              "GET"
            ),
            this.callBrainAPIWithAuth<GeneratedTestsResponse>(
              `/api/v1/quality/generated-tests?project_id=${project_id}&status=approved&limit=100`,
              "GET"
            ),
          ]);

          const events = eventsResult.events || [];
          const tests = testsResult.tests || [];

          // Find components with errors but no tests
          const testedEventIds = new Set(tests.map(t => t.production_event_id).filter(Boolean));
          const untestedEvents = events.filter(e => !testedEventIds.has(e.id));

          // Group by component
          const componentGaps: Record<string, { errors: number; severity: string }> = {};
          untestedEvents.forEach(e => {
            const component = e.component || e.url || "Unknown";
            if (!componentGaps[component]) {
              componentGaps[component] = { errors: 0, severity: "warning" };
            }
            componentGaps[component].errors++;
            if (e.severity === "fatal" || (e.severity === "error" && componentGaps[component].severity === "warning")) {
              componentGaps[component].severity = e.severity;
            }
          });

          const coveragePercent = events.length > 0 
            ? ((events.length - untestedEvents.length) / events.length * 100).toFixed(1)
            : "100";

          if (Object.keys(componentGaps).length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Coverage Gaps\n\n✅ **No gaps found!** All known production errors have test coverage.\n\nCoverage: ${coveragePercent}%`,
                },
              ],
            };
          }

          const gapsList = Object.entries(componentGaps)
            .sort((a, b) => b[1].errors - a[1].errors)
            .map(([component, data], i) => {
              const icon = data.severity === "fatal" ? "🔴" : data.severity === "error" ? "🟠" : "🟡";
              return `${i + 1}. ${icon} **${component}**\n   ${data.errors} untested error${data.errors > 1 ? "s" : ""} (${data.severity})`;
            })
            .join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Coverage Gaps Found! ⚠️\n\n**Coverage:** ${coveragePercent}% (${events.length - untestedEvents.length}/${events.length} events)\n\n### Untested Areas:\n\n${gapsList}\n\n**Action:** Generate tests with \`argus_test_from_event\` for critical gaps.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_batch_generate - Generate tests for multiple events
    this.server.tool(
      "argus_batch_generate",
      "Generate tests for multiple production events at once. Perfect for catching up on test coverage after connecting a new error source.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.enum(["new", "analyzing"]).optional().describe("Process events with this status (default: new)"),
        limit: z.number().min(1).max(50).optional().describe("Max events to process (default: 10)"),
        framework: z.enum(["playwright", "cypress", "jest"]).optional().describe("Test framework (default: playwright)"),
      },
      async ({ project_id, status = "new", limit = 10, framework = "playwright" }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            message: string;
            job_id: string;
            results: Array<{
              event_id: string;
              success: boolean;
              test_id?: string;
              error?: string;
            }>;
          }>(
            "/api/v1/quality/batch-generate",
            "POST",
            {
              project_id,
              status,
              limit,
              framework,
            }
          );

          const successCount = result.results.filter(r => r.success).length;
          const failCount = result.results.filter(r => !r.success).length;

          let resultText = `## Batch Generation Complete\n\n`;
          resultText += `**Generated:** ${successCount}/${result.results.length} tests\n`;
          resultText += `**Framework:** ${framework}\n`;
          resultText += `**Job ID:** \`${result.job_id}\`\n\n`;

          if (successCount > 0) {
            resultText += `### ✅ Successful (${successCount})\n`;
            result.results.filter(r => r.success).slice(0, 5).forEach(r => {
              resultText += `- Event \`${r.event_id.slice(0, 8)}...\` → Test \`${r.test_id?.slice(0, 8)}...\`\n`;
            });
            if (successCount > 5) resultText += `- ... and ${successCount - 5} more\n`;
            resultText += "\n";
          }

          if (failCount > 0) {
            resultText += `### ❌ Failed (${failCount})\n`;
            result.results.filter(r => !r.success).slice(0, 3).forEach(r => {
              resultText += `- Event \`${r.event_id.slice(0, 8)}...\`: ${r.error}\n`;
            });
            resultText += "\n";
          }

          resultText += `**Next:** Review generated tests with \`argus_tests(project_id, status="pending")\``;

          return {
            content: [
              {
                type: "text" as const,
                text: resultText,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_ask - Conversational AI for testing questions
    this.server.tool(
      "argus_ask",
      "Ask any question about your tests, errors, or testing strategy. The AI will analyze your data and provide insights.",
      {
        question: z.string().describe("Your question about testing"),
        project_id: z.string().optional().describe("Project context (optional)"),
      },
      async ({ question, project_id }) => {
        try {
          await this.requireAuth();
          // Gather context if project is specified
          let context = "";
          if (project_id) {
            const [statsResult, eventsResult] = await Promise.all([
              this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
                `/api/v1/quality/stats?project_id=${project_id}`,
                "GET"
              ),
              this.callBrainAPIWithAuth<ProductionEventsResponse>(
                `/api/v1/quality/events?project_id=${project_id}&limit=5`,
                "GET"
              ),
            ]);

            context = `
Project Stats:
- Total events: ${statsResult.stats.total_events}
- Coverage rate: ${statsResult.stats.coverage_rate}%
- Tests generated: ${statsResult.stats.total_generated_tests}

Recent events: ${eventsResult.events?.map(e => e.title).join(", ") || "None"}
`;
          }

          // For now, provide helpful responses based on common questions
          const lowerQuestion = question.toLowerCase();
          let answer = "";

          if (lowerQuestion.includes("start") || lowerQuestion.includes("begin") || lowerQuestion.includes("how to")) {
            answer = `## Getting Started with Argus\n\n1. **Connect error sources** - Set up webhooks from Sentry, Datadog, etc.\n2. **View events** - Use \`argus_events(project_id)\` to see production errors\n3. **Generate tests** - Use \`argus_test_from_event\` or \`argus_batch_generate\`\n4. **Review & approve** - Use \`argus_tests\` and \`argus_test_review\`\n5. **Export** - Use \`argus_export\` to add tests to your repo`;
          } else if (lowerQuestion.includes("coverage") || lowerQuestion.includes("gap")) {
            answer = `## Test Coverage\n\nUse \`argus_coverage_gaps(project_id)\` to find untested areas.\n\n${context ? `Your current coverage: ${context}` : "Specify a project_id for specific coverage data."}`;
          } else if (lowerQuestion.includes("heal") || lowerQuestion.includes("self-healing") || lowerQuestion.includes("selector")) {
            answer = `## Self-Healing\n\nArgus automatically learns to fix broken selectors.\n\n- View config: \`argus_healing_config(org_id, "get")\`\n- See patterns: \`argus_healing_patterns(org_id)\`\n- View stats: \`argus_healing_stats(org_id)\``;
          } else if (lowerQuestion.includes("export") || lowerQuestion.includes("playwright") || lowerQuestion.includes("cypress")) {
            answer = `## Exporting Tests\n\nExport generated tests to code:\n\n\`\`\`\nargus_export(test_id, "typescript", "playwright")\nargus_export(test_id, "python", "selenium")\n\`\`\`\n\nSupported: Python, TypeScript, Java, C#, Ruby, Go`;
          } else if (lowerQuestion.includes("risk") || lowerQuestion.includes("priorit")) {
            answer = `## Risk Prioritization\n\nArgus calculates risk scores based on:\n- Error frequency & severity\n- User impact\n- Test coverage\n- Recency\n\nUse \`argus_risk_scores(project_id)\` to see high-risk areas.\nUse \`argus_what_to_test(project_id)\` for prioritized recommendations.`;
          } else {
            answer = `## Argus Help\n\nHere are some things I can help with:\n\n**Production Events:**\n- \`argus_events\` - View errors\n- \`argus_event_triage\` - AI triage\n- \`argus_test_from_event\` - Generate test\n\n**Test Management:**\n- \`argus_tests\` - List tests\n- \`argus_test_review\` - Approve/reject\n- \`argus_export\` - Export to code\n\n**Insights:**\n- \`argus_what_to_test\` - Recommendations\n- \`argus_coverage_gaps\` - Find gaps\n- \`argus_risk_scores\` - Risk analysis\n\n**Self-Healing:**\n- \`argus_healing_config\` - Configuration\n- \`argus_healing_patterns\` - Learned fixes\n- \`argus_healing_stats\` - Statistics`;
          }

          return {
            content: [
              {
                type: "text" as const,
                text: answer,
              },
            ],
          };
        } catch (error) {
          return {
            content: [
              {
                type: "text" as const,
                text: `I encountered an error processing your question. Please try rephrasing or use specific tool commands.`,
              },
            ],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_dashboard - Get a quick overview of everything
    this.server.tool(
      "argus_dashboard",
      "Get a comprehensive dashboard view of your testing status. Shows quality score, recent events, pending tests, and actionable insights all in one place.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          // Fetch all relevant data in parallel
          const [scoreResult, statsResult, eventsResult, testsResult, riskResult] = await Promise.all([
            this.callBrainAPIWithAuth<BrainQualityScoreResponse>(
              `/api/v1/quality/score?project_id=${project_id}`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
              `/api/v1/quality/stats?project_id=${project_id}`,
              "GET"
            ),
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&limit=5`,
              "GET"
            ),
            this.callBrainAPIWithAuth<GeneratedTestsResponse>(
              `/api/v1/quality/generated-tests?project_id=${project_id}&status=pending&limit=5`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              `/api/v1/quality/risk-scores?project_id=${project_id}&limit=3`,
              "GET"
            ),
          ]);

          const stats = statsResult.stats;
          const events = eventsResult.events || [];
          const tests = testsResult.tests || [];
          const risks = riskResult.risk_scores || [];

          // Build dashboard
          const scoreEmoji = scoreResult.quality_score >= 80 ? "🟢" : scoreResult.quality_score >= 50 ? "🟡" : "🔴";
          const riskEmoji = scoreResult.risk_level === "low" ? "🟢" : scoreResult.risk_level === "medium" ? "🟡" : "🔴";

          let dashboard = `# Argus Dashboard 📊\n\n`;
          
          // Quality Score Section
          dashboard += `## Quality Score: ${scoreEmoji} ${scoreResult.quality_score}/100\n\n`;
          dashboard += `| Metric | Value |\n|--------|-------|\n`;
          dashboard += `| Risk Level | ${riskEmoji} ${scoreResult.risk_level.toUpperCase()} |\n`;
          dashboard += `| Test Coverage | ${scoreResult.test_coverage}% |\n`;
          dashboard += `| Production Events | ${scoreResult.total_events} |\n`;
          dashboard += `| Generated Tests | ${scoreResult.total_tests} |\n`;
          dashboard += `| Approved Tests | ${scoreResult.approved_tests} |\n\n`;

          // Alerts Section
          const newEvents = events.filter(e => e.status === "new").length;
          const pendingTests = tests.length;
          
          if (newEvents > 0 || pendingTests > 0) {
            dashboard += `## ⚠️ Needs Attention\n\n`;
            if (newEvents > 0) {
              dashboard += `- **${newEvents} new production errors** need tests\n`;
            }
            if (pendingTests > 0) {
              dashboard += `- **${pendingTests} tests pending review**\n`;
            }
            dashboard += "\n";
          }

          // High Risk Areas
          if (risks.length > 0) {
            dashboard += `## 🎯 High Risk Areas\n\n`;
            risks.forEach(r => {
              const emoji = r.overall_score > 70 ? "🔴" : r.overall_score > 40 ? "🟡" : "🟢";
              dashboard += `- ${emoji} **${r.entity_identifier}**: ${r.overall_score}/100 risk\n`;
            });
            dashboard += "\n";
          }

          // Recent Events
          if (events.length > 0) {
            dashboard += `## 📋 Recent Events\n\n`;
            events.slice(0, 3).forEach(e => {
              const icon = e.severity === "fatal" ? "🔴" : e.severity === "error" ? "🟠" : "🟡";
              dashboard += `- ${icon} ${e.title}\n`;
            });
            dashboard += "\n";
          }

          // Quick Actions
          dashboard += `## ⚡ Quick Actions\n\n`;
          dashboard += `\`\`\`\n`;
          dashboard += `argus_events("${project_id}")           # View all events\n`;
          dashboard += `argus_what_to_test("${project_id}")     # Get recommendations\n`;
          dashboard += `argus_batch_generate("${project_id}")   # Generate tests\n`;
          dashboard += `argus_tests("${project_id}")            # Review tests\n`;
          dashboard += `\`\`\``;

          return {
            content: [
              {
                type: "text" as const,
                text: dashboard,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =====================================================
    // INFRASTRUCTURE & COST MANAGEMENT TOOLS
    // =====================================================

    // Tool: argus_infra_overview - Get infrastructure cost overview
    this.server.tool(
      "argus_infra_overview",
      "Get a comprehensive overview of infrastructure costs including current spend, projected costs, and comparison to BrowserStack pricing. Shows total savings achieved by self-hosting.",
      {
        days: z.number().optional().default(30).describe("Number of days to analyze (7, 30, or 90)"),
      },
      async ({ days }) => {
        try {
          await this.requireAuth();

          const [costReport, snapshot, savings] = await Promise.all([
            this.callBrainAPIWithAuth<{
              total_cost: number;
              projected_monthly: number;
              comparison_to_browserstack: number;
              savings_percentage: number;
            }>(`/api/v1/infra/cost-report?days=${days}`, "GET"),
            this.callBrainAPIWithAuth<InfraSnapshotResponse>("/api/v1/infra/snapshot", "GET"),
            this.callBrainAPIWithAuth<InfraSavingsResponse>("/api/v1/infra/savings-summary", "GET"),
          ]);

          const savingsEmoji = savings.savings_percentage > 80 ? "🟢" : savings.savings_percentage > 50 ? "🟡" : "🔴";

          let output = `# Infrastructure Cost Overview 💰\n\n`;
          output += `## Current Period (${days} days)\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Current Spend | $${costReport.total_cost.toFixed(2)} |\n`;
          output += `| Projected Monthly | $${costReport.projected_monthly.toFixed(2)} |\n`;
          output += `| BrowserStack Equivalent | $${costReport.comparison_to_browserstack.toFixed(2)} |\n`;
          output += `| ${savingsEmoji} Savings | ${savings.savings_percentage.toFixed(0)}% |\n\n`;

          output += `## Browser Pool Status\n\n`;
          output += `| Resource | Count | Utilization |\n|----------|-------|-------------|\n`;
          output += `| Total Nodes | ${snapshot.total_nodes} | ${snapshot.cluster_cpu_utilization.toFixed(0)}% CPU |\n`;
          output += `| Total Pods | ${snapshot.total_pods} | ${snapshot.cluster_memory_utilization.toFixed(0)}% Memory |\n`;
          output += `| Chrome | ${snapshot.chrome_nodes.total} | ${snapshot.chrome_nodes.utilization.toFixed(0)}% |\n`;
          output += `| Firefox | ${snapshot.firefox_nodes.total} | ${snapshot.firefox_nodes.utilization.toFixed(0)}% |\n`;
          output += `| Edge | ${snapshot.edge_nodes.total} | ${snapshot.edge_nodes.utilization.toFixed(0)}% |\n\n`;

          output += `## Savings Summary\n\n`;
          output += `- **Monthly Savings**: $${savings.savings_vs_browserstack.toFixed(2)} vs BrowserStack\n`;
          output += `- **Recommendations Applied**: ${savings.recommendations_applied}\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_infra_recommendations - Get AI-powered cost optimization recommendations
    this.server.tool(
      "argus_infra_recommendations",
      "Get AI-powered recommendations for optimizing infrastructure costs. Analyzes usage patterns and suggests scaling changes, resource optimizations, and cost-saving opportunities.",
      {},
      async () => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<InfraRecommendationsResponse>(
            "/api/v1/infra/recommendations",
            "GET"
          );

          if (!result.recommendations || result.recommendations.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: "# Infrastructure Recommendations 🤖\n\n✅ No optimization recommendations at this time. Your infrastructure is running efficiently!",
              }],
            };
          }

          let output = `# Infrastructure Recommendations 🤖\n\n`;
          output += `**Total Potential Savings**: $${result.total_potential_savings.toFixed(2)}/month\n\n`;

          result.recommendations.forEach((rec, index) => {
            const typeEmoji = {
              scale_down: "📉",
              scale_up: "📈",
              optimize: "⚡",
              alert: "⚠️",
            }[rec.type] || "💡";

            const confidenceEmoji = rec.confidence > 0.8 ? "🟢" : rec.confidence > 0.5 ? "🟡" : "🟠";

            output += `## ${index + 1}. ${typeEmoji} ${rec.title}\n\n`;
            output += `${rec.description}\n\n`;
            output += `- **Potential Savings**: $${rec.potential_savings.toFixed(2)}/month\n`;
            output += `- **Confidence**: ${confidenceEmoji} ${(rec.confidence * 100).toFixed(0)}%\n`;
            output += `- **Status**: ${rec.status}\n`;
            output += `- **Auto-applicable**: ${rec.auto_applicable ? "Yes ✅" : "No (requires approval)"}\n`;
            output += `- **ID**: \`${rec.id}\`\n\n`;
          });

          output += `---\n\n`;
          output += `To apply a recommendation: \`argus_infra_apply("recommendation_id")\`\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_infra_apply - Apply an infrastructure recommendation
    this.server.tool(
      "argus_infra_apply",
      "Apply an infrastructure optimization recommendation. Can be set to auto-apply (for safe changes) or require manual confirmation.",
      {
        recommendation_id: z.string().describe("The recommendation ID to apply"),
        auto: z.boolean().optional().default(false).describe("Whether to auto-apply without confirmation"),
      },
      async ({ recommendation_id, auto }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            action_applied?: Record<string, unknown>;
            status?: string;
            error?: string;
          }>(
            `/api/v1/infra/recommendations/${recommendation_id}/apply`,
            "POST",
            { auto }
          );

          if (result.success) {
            let output = `# Recommendation Applied ✅\n\n`;
            output += `The recommendation has been successfully applied.\n\n`;
            if (result.action_applied) {
              output += `**Action taken**: ${JSON.stringify(result.action_applied, null, 2)}\n`;
            }
            return {
              content: [{ type: "text" as const, text: output }],
            };
          } else {
            return {
              content: [{
                type: "text" as const,
                text: `# Failed to Apply Recommendation ❌\n\n${result.error || "Unknown error occurred"}`,
              }],
              isError: true,
            };
          }
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_llm_usage - Get LLM/AI usage and costs
    this.server.tool(
      "argus_llm_usage",
      "Get detailed breakdown of LLM/AI usage and costs. Shows which models are being used, token consumption, and costs per feature (test generation, self-healing, etc.).",
      {
        period: z.string().optional().default("30d").describe("Period to analyze (7d, 30d, or 90d)"),
      },
      async ({ period }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<LLMUsageResponse>(
            `/api/v1/ai/usage?period=${period}`,
            "GET"
          );

          let output = `# AI / LLM Usage Report 🤖\n\n`;
          output += `**Period**: ${result.period}\n`;
          output += `**Total Cost**: $${result.total_cost.toFixed(2)}\n`;
          output += `**Total Requests**: ${result.total_requests.toLocaleString()}\n\n`;

          output += `## Usage by Model\n\n`;
          output += `| Model | Provider | Requests | Tokens (in/out) | Cost |\n`;
          output += `|-------|----------|----------|-----------------|------|\n`;

          result.models.forEach(model => {
            const tokensIn = (model.input_tokens / 1_000_000).toFixed(1) + "M";
            const tokensOut = (model.output_tokens / 1_000_000).toFixed(1) + "M";
            output += `| ${model.name} | ${model.provider} | ${model.requests.toLocaleString()} | ${tokensIn} / ${tokensOut} | $${model.cost.toFixed(2)} |\n`;
          });

          output += `\n## Usage by Feature\n\n`;
          output += `| Feature | Requests | Cost | % of Total |\n`;
          output += `|---------|----------|------|------------|\n`;

          result.features.forEach(feature => {
            output += `| ${feature.name} | ${feature.requests.toLocaleString()} | $${feature.cost.toFixed(2)} | ${feature.percentage}% |\n`;
          });

          output += `\n## Cost Optimization Tips 💡\n\n`;
          output += `- **DeepSeek** for code analysis ($0.14/1M tokens) - 90% cheaper than Claude\n`;
          output += `- **DeepSeek R1** for reasoning tasks - 10% cost of o1\n`;
          output += `- **Claude** only for Computer Use (browser automation)\n`;
          output += `- All models via **OpenRouter** - single API key, best pricing\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_browser_pool - Get real-time browser pool status
    this.server.tool(
      "argus_browser_pool",
      "Get real-time status of the Selenium Grid browser pool. Shows node status, active sessions, queue length, and utilization metrics.",
      {},
      async () => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<InfraSnapshotResponse>(
            "/api/v1/infra/snapshot",
            "GET"
          );

          const statusEmoji = result.selenium.status === "healthy" ? "🟢" : result.selenium.status === "degraded" ? "🟡" : "🔴";

          let output = `# Browser Pool Status ${statusEmoji}\n\n`;
          output += `**Status**: ${result.selenium.status.toUpperCase()}\n`;
          output += `**Timestamp**: ${result.timestamp}\n\n`;

          output += `## Selenium Grid\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Ready Nodes | ${result.selenium.ready_nodes} |\n`;
          output += `| Active Sessions | ${result.selenium.active_sessions} |\n`;
          output += `| Max Sessions | ${result.selenium.max_sessions} |\n`;
          output += `| Queue Length | ${result.selenium.queue_length} |\n\n`;

          output += `## Browser Nodes\n\n`;
          output += `| Browser | Ready | Busy | Total | Utilization |\n`;
          output += `|---------|-------|------|-------|-------------|\n`;
          output += `| 🟠 Chrome | ${result.chrome_nodes.ready} | ${result.chrome_nodes.busy} | ${result.chrome_nodes.total} | ${result.chrome_nodes.utilization.toFixed(0)}% |\n`;
          output += `| 🟠 Firefox | ${result.firefox_nodes.ready} | ${result.firefox_nodes.busy} | ${result.firefox_nodes.total} | ${result.firefox_nodes.utilization.toFixed(0)}% |\n`;
          output += `| 🔵 Edge | ${result.edge_nodes.ready} | ${result.edge_nodes.busy} | ${result.edge_nodes.total} | ${result.edge_nodes.utilization.toFixed(0)}% |\n\n`;

          output += `## Cluster Resources\n\n`;
          output += `- **CPU Utilization**: ${result.cluster_cpu_utilization.toFixed(0)}%\n`;
          output += `- **Memory Utilization**: ${result.cluster_memory_utilization.toFixed(0)}%\n`;
          output += `- **Total Pods**: ${result.total_pods}\n`;
          output += `- **Total Nodes**: ${result.total_nodes}\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );
  }
}

// OAuth Durable Object for state management
export class MCPOAuth {
  state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/store") {
      const { key, value } = await request.json() as { key: string; value: unknown };
      await this.state.storage.put(key, value);
      return new Response("OK");
    }

    if (url.pathname === "/get") {
      const { key } = await request.json() as { key: string };
      const value = await this.state.storage.get(key);
      return Response.json({ value });
    }

    return new Response("Not found", { status: 404 });
  }
}

// Legacy class stub for migration (will be deleted in v6 migration)
export class ArgusMcpAgent extends McpAgent<EnvWithKV> {
  server = new McpServer({
    name: "Legacy Argus MCP Agent",
    version: "0.0.0",
  });
  async init() {}
}

// Export the Argus MCP Agent
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Handle the SSE endpoint for MCP (deprecated SSE protocol)
    if (url.pathname === "/sse" || url.pathname === "/sse/message") {
      return ArgusMcpAgentSQLite.serveSSE("/sse").fetch(request, env, ctx);
    }

    // Handle the Streamable-HTTP endpoint for MCP (new protocol)
    if (url.pathname === "/mcp") {
      return ArgusMcpAgentSQLite.serve("/mcp").fetch(request, env, ctx);
    }

    // Root endpoint - show info
    if (url.pathname === "/") {
      return Response.json({
        name: "Argus MCP Server",
        version: "3.0.0",
        description: "Model Context Protocol server for Argus E2E Testing Agent - Full IDE Integration with Next-Gen AI Testing Intelligence",
        endpoint: "/sse",
        tools: {
          authentication: [
            "argus_auth",
            "argus_auth_complete",
            "argus_auth_status",
            "argus_auth_logout",
          ],
          core: [
            "argus_health",
            "argus_discover",
            "argus_act",
            "argus_test",
            "argus_extract",
            "argus_agent",
            "argus_generate_test",
          ],
          quality_intelligence: [
            "argus_quality_score",
            "argus_quality_stats",
            "argus_risk_scores",
          ],
          production_events: [
            "argus_events",
            "argus_event_triage",
            "argus_test_from_event",
            "argus_batch_generate",
          ],
          test_management: [
            "argus_tests",
            "argus_test_review",
          ],
          self_healing: [
            "argus_healing_config",
            "argus_healing_patterns",
            "argus_healing_stats",
            "argus_healing_review",
          ],
          smart_insights: [
            "argus_what_to_test",
            "argus_coverage_gaps",
            "argus_dashboard",
            "argus_ask",
          ],
          projects: [
            "argus_projects",
          ],
          sync: [
            "argus_sync_push",
            "argus_sync_pull",
            "argus_sync_status",
            "argus_sync_resolve",
          ],
          export: [
            "argus_export",
            "argus_export_languages",
          ],
          recording: [
            "argus_recording_to_test",
            "argus_recording_snippet",
          ],
          collaboration: [
            "argus_presence",
            "argus_comments",
          ],
        },
        total_tools: 36,
        documentation: "https://github.com/raphaenterprises-ai/argus-e2e-testing-agent",
      });
    }

    // Screenshot serving endpoint (authenticated via signed token)
    // URL format: /screenshot/{key}?t={expiry.signature}
    // Single parameter to avoid & truncation in markdown/terminals
    if (url.pathname.startsWith("/screenshot/")) {
      const key = decodeURIComponent(url.pathname.slice("/screenshot/".length));
      // Support both new format (?t=) and legacy format (?token=&exp=)
      const newToken = url.searchParams.get("t");
      const legacyToken = url.searchParams.get("token");
      const legacyExp = url.searchParams.get("exp");

      let validation: { valid: boolean; expiry?: number; error?: string };

      if (newToken) {
        // New single-parameter format: ?t=expiry.signature
        validation = await validateScreenshotToken(newToken, key, env);
      } else if (legacyToken && legacyExp) {
        // Legacy format: ?token=signature&exp=expiry
        const expiry = parseInt(legacyExp, 10);
        if (isNaN(expiry) || Date.now() > expiry) {
          validation = { valid: false, error: "Token expired" };
        } else {
          // Reconstruct and validate legacy token
          const expectedToken = `${expiry}.${legacyToken}`;
          validation = await validateScreenshotToken(expectedToken, key, env);
        }
      } else {
        return new Response("Missing token parameter. Use ?t=token", { status: 401 });
      }

      if (!validation.valid) {
        const status = validation.error === "Token expired" ? 403 : 401;
        return new Response(validation.error || "Invalid token", { status });
      }

      // Fetch from R2
      try {
        const object = await env.SCREENSHOTS.get(key);
        if (!object) {
          return new Response("Screenshot not found", { status: 404 });
        }

        const data = await object.arrayBuffer();
        return new Response(data, {
          headers: {
            "Content-Type": "image/png",
            "Cache-Control": "private, max-age=3600",
            "X-Screenshot-Key": key,
          },
        });
      } catch (error) {
        console.error("[Screenshot] Fetch error:", error);
        return new Response("Failed to fetch screenshot", { status: 500 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
