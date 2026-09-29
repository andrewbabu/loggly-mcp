import {
  McpServer,
  ResourceTemplate
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { rdapLookup, greyNoiseLookup, abuseIpdbLookup } from "./ip-intel.js";

function loadDotEnv() {
  const envPath = resolve(process.cwd(), ".env");
  if (!existsSync(envPath)) {
    return;
  }

  const text = readFileSync(envPath, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const eq = line.indexOf("=");
    if (eq <= 0) {
      continue;
    }

    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();

    if (
      (value.startsWith("\"") && value.endsWith("\"")) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

loadDotEnv();

export const LOG_LEVELS = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3
};

function normalizeLogLevel(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw || LOG_LEVELS[raw] === undefined) {
    return "info";
  }
  return raw;
}

function parseNonNegativeInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return fallback;
  }

  return parsed;
}

function normalizeSubdomain(value) {
  if (!value || !String(value).trim()) {
    return undefined;
  }

  const raw = String(value).trim();
  let host = raw;

  if (/^https?:\/\//i.test(raw)) {
    try {
      host = new URL(raw).hostname;
    } catch {
      return undefined;
    }
  } else if (raw.includes("/")) {
    host = raw.split("/")[0];
  }

  host = host.toLowerCase().replace(/\.$/, "");

  if (host.endsWith(".loggly.com")) {
    host = host.slice(0, -".loggly.com".length);
  }

  if (host.includes(":")) {
    host = host.split(":")[0];
  }

  if (!/^[a-z0-9-]+$/.test(host)) {
    return undefined;
  }

  return host;
}

function parseAccountsFromEnv() {
  const raw = process.env.LOGGLY_ACCOUNTS;

  if (raw && raw.trim()) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(
        `Invalid LOGGLY_ACCOUNTS JSON: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(
        "LOGGLY_ACCOUNTS must decode to a JSON object of {name: {subdomain, token, authMode?}}."
      );
    }

    const accounts = new Map();
    for (const [name, value] of Object.entries(parsed)) {
      if (!value || typeof value !== "object") {
        continue;
      }

      accounts.set(name, {
        name,
        subdomainRaw: value.subdomain,
        subdomain: normalizeSubdomain(value.subdomain),
        token: value.token,
        authMode: String(value.authMode || value.auth_mode || "bearer").toLowerCase()
      });
    }
    return accounts;
  }

  const accounts = new Map();
  accounts.set("default", {
    name: "default",
    subdomainRaw: process.env.LOGGLY_SUBDOMAIN,
    subdomain: normalizeSubdomain(process.env.LOGGLY_SUBDOMAIN),
    token: process.env.LOGGLY_TOKEN,
    authMode: (process.env.LOGGLY_AUTH_MODE || "bearer").toLowerCase()
  });
  return accounts;
}

const ACCOUNTS = parseAccountsFromEnv();
const DEFAULT_ACCOUNT_NAME =
  process.env.LOGGLY_DEFAULT_ACCOUNT ||
  (ACCOUNTS.size === 1 ? [...ACCOUNTS.keys()][0] : "default");

function envField(name, fallback) {
  const value = process.env[name];
  return value && String(value).trim() ? String(value).trim() : fallback;
}

const settings = {
  maxRetries: parseNonNegativeInt(process.env.LOGGLY_MAX_RETRIES, 2),
  requestTimeoutMs: parseNonNegativeInt(process.env.LOGGLY_REQUEST_TIMEOUT_MS, 15000),
  logLevel: normalizeLogLevel(process.env.LOGGLY_LOG_LEVEL || "info"),
  // Caps concurrent in-flight requests per account. The aggregation tools fan out several
  // requests per call (facets + timeline buckets + sample) via Promise.all; this keeps that
  // fan-out from hammering Loggly's per-account rate limit all at once.
  maxConcurrentRequests: Math.max(1, parseNonNegativeInt(process.env.LOGGLY_MAX_CONCURRENT_REQUESTS, 4)),
  // Parsed-field names used by the aggregation/traffic tools below. These depend on how each
  // Loggly source parses its logs (JSON field names, IIS/W3C fields, etc.) — verify with
  // `list_fields` against real data and override here or per-call if the defaults don't match.
  fields: {
    ip: envField("LOGGLY_FIELD_IP", "ip"),
    host: envField("LOGGLY_FIELD_HOST", "host"),
    path: envField("LOGGLY_FIELD_PATH", "path"),
    status: envField("LOGGLY_FIELD_STATUS", "status"),
    userAgent: envField("LOGGLY_FIELD_USER_AGENT", "user_agent")
  }
};

function resolveAccount(name) {
  const accountName = name && String(name).trim() ? String(name).trim() : DEFAULT_ACCOUNT_NAME;
  const account = ACCOUNTS.get(accountName);

  if (!account) {
    const available = [...ACCOUNTS.keys()].join(", ") || "(none configured)";
    throw new Error(
      `Unknown Loggly account "${accountName}". Available accounts: ${available}. ` +
        "Pass `account` matching one of these, or set LOGGLY_DEFAULT_ACCOUNT."
    );
  }

  if (!account.subdomainRaw || !account.token) {
    throw new Error(
      `Account "${accountName}" is missing subdomain/token. Set LOGGLY_SUBDOMAIN/LOGGLY_TOKEN ` +
        "or fill in its entry in LOGGLY_ACCOUNTS."
    );
  }

  if (!account.subdomain) {
    throw new Error(
      `Invalid subdomain for account "${accountName}": "${account.subdomainRaw}". Use just the ` +
        'subdomain (for example "acme") or a *.loggly.com URL.'
    );
  }

  return account;
}

function resolveAccountForUrl(rawUrl) {
  let host;
  try {
    host = new URL(rawUrl).host.toLowerCase();
  } catch {
    throw new Error("Invalid `next_url`: unable to parse URL.");
  }

  const matches = [...ACCOUNTS.values()].filter(
    (account) => account.subdomain && `${account.subdomain}.loggly.com` === host
  );

  if (matches.length === 1) {
    return resolveAccount(matches[0].name);
  }

  if (matches.length === 0) {
    throw new Error(
      `No configured account matches host "${host}". Pass \`account\` explicitly.`
    );
  }

  throw new Error(
    `Multiple accounts match host "${host}" (${matches.map((a) => a.name).join(", ")}). ` +
      "Pass `account` explicitly."
  );
}

export function log(level, message, meta) {
  const rank = LOG_LEVELS[level];
  if (rank === undefined || rank > LOG_LEVELS[settings.logLevel]) {
    return;
  }

  const parts = ["[loggly-mcp]", level.toUpperCase(), message];
  if (meta !== undefined) {
    try {
      parts.push(JSON.stringify(meta));
    } catch {
      parts.push(String(meta));
    }
  }
  console.error(parts.join(" "));
}

function buildHeaders(account) {
  if (account.authMode === "basic") {
    const basic = Buffer.from(`${account.token}:`).toString("base64");
    return { Authorization: `Basic ${basic}` };
  }

  return { Authorization: `Bearer ${account.token}` };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stringifyBody(body) {
  if (typeof body === "string") {
    return body;
  }

  try {
    return JSON.stringify(body);
  } catch {
    return String(body);
  }
}

function bodyLooksLikeTimeout(body) {
  if (typeof body === "string") {
    return /timeout/i.test(body);
  }

  if (!body || typeof body !== "object") {
    return false;
  }

  const maybeText = [
    body.description,
    body.message,
    body.error,
    body.reason,
    body.detail
  ];

  return maybeText.some((value) => typeof value === "string" && /timeout/i.test(value));
}

function shouldRetry(statusCode, body) {
  if (statusCode === 429) {
    return true;
  }

  if (statusCode === 503 || statusCode === 504) {
    return true;
  }

  if (statusCode === 500 && bodyLooksLikeTimeout(body)) {
    return true;
  }

  return false;
}

function computeBackoffMs(attempt, statusCode, retryAfterHeader) {
  if (statusCode === 429 && retryAfterHeader) {
    const seconds = Number(retryAfterHeader);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, 30000);
    }
    const dateMs = Date.parse(retryAfterHeader);
    if (!Number.isNaN(dateMs)) {
      return Math.max(0, Math.min(dateMs - Date.now(), 30000));
    }
  }

  return 300 * 2 ** attempt;
}

// Caps concurrent in-flight requests per Loggly account. Tools like traffic_by_ip/search_logs
// fan out several requests at once (facets + a bucketed timeline + a sample) via Promise.all —
// without this cap that fan-out hits Loggly's per-account rate limit (429) directly, since
// Promise.all fires every request simultaneously with zero pacing.
class Semaphore {
  constructor(maxConcurrent) {
    this.maxConcurrent = maxConcurrent;
    this.current = 0;
    this.queue = [];
  }

  acquire() {
    if (this.current < this.maxConcurrent) {
      this.current += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.queue.push(resolve)).then(() => {
      this.current += 1;
    });
  }

  release() {
    this.current -= 1;
    const next = this.queue.shift();
    if (next) {
      next();
    }
  }

  async run(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

const accountSemaphores = new Map();

function getAccountSemaphore(accountName) {
  let semaphore = accountSemaphores.get(accountName);
  if (!semaphore) {
    semaphore = new Semaphore(settings.maxConcurrentRequests);
    accountSemaphores.set(accountName, semaphore);
  }
  return semaphore;
}

async function parseResponseBody(response) {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch {
      return await response.text();
    }
  }

  return await response.text();
}

function buildUrl(account, path, params = {}) {
  assertReadOnlyPath(path);
  const url = new URL(`https://${account.subdomain}.loggly.com${path}`);

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null && item !== "") {
          url.searchParams.append(key, String(item));
        }
      }
      continue;
    }

    url.searchParams.set(key, String(value));
  }

  return url;
}

function assertReadOnlyPath(path) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new Error("Loggly path must be an absolute API path starting with `/`.");
  }

  if (!path.startsWith("/apiv2/") && path !== "/apiv2") {
    throw new Error("Only read-only `/apiv2/*` endpoints are allowed.");
  }
}

function shouldRetryNetworkError(error) {
  if (!error || typeof error !== "object") {
    return false;
  }

  const message = error instanceof Error ? error.message : String(error);
  const causeCode =
    typeof error.cause === "object" && error.cause
      ? error.cause.code
      : undefined;

  if (
    causeCode &&
    [
      "ECONNRESET",
      "ETIMEDOUT",
      "ECONNREFUSED",
      "EAI_AGAIN",
      "ENETUNREACH",
      "UND_ERR_CONNECT_TIMEOUT",
      "UND_ERR_HEADERS_TIMEOUT",
      "UND_ERR_BODY_TIMEOUT",
      "UND_ERR_SOCKET"
    ].includes(causeCode)
  ) {
    return true;
  }

  if (error instanceof Error && error.name === "AbortError") {
    return true;
  }

  return /(fetch failed|network|timeout|socket|dns|temporary failure)/i.test(message);
}

function formatNetworkError(account, url, error) {
  const message = error instanceof Error ? error.message : String(error);
  const causeCode =
    typeof error === "object" &&
    error &&
    typeof error.cause === "object" &&
    error.cause &&
    typeof error.cause.code === "string"
      ? error.cause.code
      : null;

  const details = [
    `Loggly network request failed for ${url.pathname}${url.search}`,
    `account=${account.name}`,
    `subdomain=${account.subdomain}`,
    `timeout_ms=${settings.requestTimeoutMs}`
  ];

  if (causeCode) {
    details.push(`code=${causeCode}`);
  }

  details.push(`message=${message}`);
  return details.join(" | ");
}

function ensureTrustedIterateUrl(account, rawUrl) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid `next_url`: unable to parse URL.");
  }

  const expectedHost = `${account.subdomain}.loggly.com`;
  if (url.protocol !== "https:" || url.host !== expectedHost) {
    throw new Error(
      `Refusing next_url outside expected Loggly host (${expectedHost}).`
    );
  }

  if (!url.pathname.startsWith("/apiv2/events/iterate")) {
    throw new Error(
      "Refusing next_url that does not target /apiv2/events/iterate."
    );
  }

  return url;
}

async function fetchWithRetry(account, url, options = {}) {
  return getAccountSemaphore(account.name).run(() => fetchWithRetryInner(account, url, options));
}

async function fetchWithRetryInner(account, url, options = {}) {
  const retryTransient = options.retryTransient !== false;
  const maxRetries = Number.isInteger(options.maxRetries)
    ? options.maxRetries
    : settings.maxRetries;

  for (let attempt = 0; ; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), settings.requestTimeoutMs);
    let response;
    try {
      response = await fetch(url, { headers: buildHeaders(account), signal: controller.signal });
    } catch (error) {
      if (retryTransient && attempt < maxRetries && shouldRetryNetworkError(error)) {
        log("warn", "Retrying Loggly request after network error.", {
          account: account.name,
          attempt: attempt + 1,
          max_retries: maxRetries,
          path: url.pathname
        });
        await sleep(computeBackoffMs(attempt, null, null));
        continue;
      }

      throw new Error(formatNetworkError(account, url, error));
    } finally {
      clearTimeout(timeout);
    }

    const body = await parseResponseBody(response);

    if (response.ok) {
      return body;
    }

    if (retryTransient && attempt < maxRetries && shouldRetry(response.status, body)) {
      const backoffMs = computeBackoffMs(attempt, response.status, response.headers.get("retry-after"));
      log("warn", "Retrying Loggly request after transient response.", {
        account: account.name,
        attempt: attempt + 1,
        max_retries: maxRetries,
        status: response.status,
        backoff_ms: backoffMs,
        path: url.pathname
      });
      await sleep(backoffMs);
      continue;
    }

    throw new Error(
      `Loggly request failed (${response.status} ${response.statusText}) for ${url.pathname}: ${stringifyBody(body)}`
    );
  }
}

async function logglyGet(account, path, params = {}, options = {}) {
  const url = buildUrl(account, path, params);
  return fetchWithRetry(account, url, options);
}

async function logglyGetAbsolute(account, url, options = {}) {
  return fetchWithRetry(account, url, options);
}

const RELATIVE_TIME_RE = /^-(\d+)([smhdw])$/i;
const TIME_UNIT_MS = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 };

// Resolves a Loggly-style time boundary (relative offset, "now", epoch, or ISO timestamp) to an
// epoch-ms number, purely for client-side bucketing math — the original string is still what
// gets sent to Loggly for the overall query.
function resolveTimeBoundary(value, nowMs) {
  const raw = String(value ?? "").trim();
  if (!raw) {
    return null;
  }

  if (/^now$/i.test(raw)) {
    return nowMs;
  }

  const relative = RELATIVE_TIME_RE.exec(raw);
  if (relative) {
    const amount = Number(relative[1]);
    const unitMs = TIME_UNIT_MS[relative[2].toLowerCase()];
    return nowMs - amount * unitMs;
  }

  if (/^\d+$/.test(raw)) {
    const asNumber = Number(raw);
    return asNumber > 1e12 ? asNumber : asNumber * 1000;
  }

  const parsed = Date.parse(raw);
  return Number.isNaN(parsed) ? null : parsed;
}

async function computeTimeline(account, query, from, until, bucketCount) {
  const nowMs = Date.now();
  const fromMs = resolveTimeBoundary(from, nowMs);
  const untilMs = resolveTimeBoundary(until, nowMs);

  if (fromMs === null || untilMs === null || untilMs <= fromMs) {
    return {
      buckets: null,
      note:
        "Could not compute a timeline: `from`/`until` must be a relative offset (e.g. -1h), " +
        '"now", or an ISO timestamp.'
    };
  }

  const span = untilMs - fromMs;
  const step = span / bucketCount;

  const bucketPromises = [];
  for (let i = 0; i < bucketCount; i += 1) {
    const bucketStart = fromMs + step * i;
    const bucketEnd = i === bucketCount - 1 ? untilMs : fromMs + step * (i + 1);

    bucketPromises.push(
      logglyGet(account, "/apiv2/events/count", {
        q: query,
        from: new Date(bucketStart).toISOString(),
        until: new Date(bucketEnd).toISOString()
      }).then((result) => ({
        start: new Date(bucketStart).toISOString(),
        end: new Date(bucketEnd).toISOString(),
        count: typeof result?.count === "number" ? result.count : null
      }))
    );
  }

  const buckets = await Promise.all(bucketPromises);
  return { buckets, note: null };
}

// Best-effort count of terms in a /apiv2/fields/<field>/ facet response. Loggly's documented
// shape varies by API version, so this doesn't assume one exact structure — it's a convenience
// on top of the raw facet payload, which is always returned alongside it.
function bestEffortTermCount(facetResponse) {
  if (!facetResponse || typeof facetResponse !== "object") {
    return null;
  }

  for (const value of Object.values(facetResponse)) {
    if (Array.isArray(value)) {
      return value.length;
    }
    if (value && typeof value === "object" && Array.isArray(value.terms)) {
      return value.terms.length;
    }
  }

  return null;
}

function numberOrNull(value) {
  return typeof value === "number" ? value : null;
}

const FIELD_NAME_NOTE =
  "Facet field names are configurable (LOGGLY_FIELD_HOST/PATH/STATUS/USER_AGENT/IP env vars, " +
  "or per-call *_field arguments). If counts/facets look empty, run `list_fields` to find the " +
  "actual parsed field names for this Loggly source.";

// Different Loggly sources (and even different tags within the same account) parse logs into
// different field names — e.g. one account nests fields under `json.payload.message.*`, another
// uses flat PascalCase `json.ClientIp`. A single static field name per role can't cover every
// source, so field resolution is discovery-first: look at what fields actually exist for this
// query, match them against these role patterns, and only fall back to the static settings/env
// default when discovery finds nothing. Patterns match the field's last dotted segment.
const FIELD_ROLE_PATTERNS = {
  ip: [/(^|\.)clientip$/i, /(^|\.)client_ip$/i, /(^|\.)remoteaddr$/i, /(^|\.)ip$/i],
  host: [/(^|\.)host$/i, /(^|\.)hostname$/i],
  path: [/(^|\.)path$/i, /(^|\.)route$/i],
  status: [/(^|\.)responsestatuscode$/i, /(^|\.)statuscode$/i, /(^|\.)status$/i],
  userAgent: [/(^|\.)user-agent$/i, /(^|\.)useragent$/i, /(^|\.)user_agent$/i]
};

const FIELD_ROLES = Object.keys(FIELD_ROLE_PATTERNS);

// Fetches parsed field names for a query, tolerating Loggly's eventually-consistent /apiv2/fields/
// response (it can come back PENDING with an empty `fields` array on the first call for a query
// that hasn't been searched before) with a short bounded poll rather than failing discovery outright.
async function listParsedFieldNames(account, query) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let result;
    try {
      result = await logglyGet(account, "/apiv2/fields/", {
        q: query,
        from: "-24h",
        until: "now",
        facet_size: 300
      });
    } catch {
      return [];
    }

    const names = Array.isArray(result?.fields)
      ? result.fields.map((field) => field?.name).filter((name) => typeof name === "string" && name)
      : [];

    if (names.length > 0 || result?.rsid?.status !== "PENDING") {
      return names;
    }

    await sleep(400 * (attempt + 1));
  }

  return [];
}

// Discovery-first field resolution. Explicit per-call overrides always win outright (no discovery
// needed for those roles). For every other role, this looks at the fields actually present for
// `query` on `account` and matches them against FIELD_ROLE_PATTERNS:
//   - exactly one candidate  -> use it, and report it under `discovered`
//   - zero candidates        -> fall back to the static settings/env default
//   - 2+ candidates          -> ambiguous (e.g. a source with both ClientIp and CustIP); don't
//                               guess which one is semantically right — fall back to the static
//                               default and report every candidate under `ambiguous` so the caller
//                               can pick the correct one via an explicit *_field override.
async function discoverFieldNames(account, query, overrides = {}, roles = FIELD_ROLES) {
  const resolved = {};
  const rolesNeedingDiscovery = [];

  for (const role of roles) {
    if (overrides[role]) {
      resolved[role] = overrides[role];
    } else {
      rolesNeedingDiscovery.push(role);
    }
  }

  const discovered = {};
  const ambiguous = {};

  if (rolesNeedingDiscovery.length === 0) {
    return { fields: resolved, discovered, ambiguous };
  }

  const fieldList = await listParsedFieldNames(account, query);

  for (const role of rolesNeedingDiscovery) {
    if (fieldList.length === 0) {
      resolved[role] = settings.fields[role];
      continue;
    }

    const patterns = FIELD_ROLE_PATTERNS[role];
    const matches = [...new Set(fieldList.filter((name) => patterns.some((re) => re.test(name))))];

    if (matches.length === 1) {
      resolved[role] = matches[0];
      discovered[role] = matches[0];
    } else if (matches.length > 1) {
      resolved[role] = settings.fields[role];
      ambiguous[role] = matches;
    } else {
      resolved[role] = settings.fields[role];
    }
  }

  return { fields: resolved, discovered, ambiguous };
}

function fieldResolutionNote(discovered, ambiguous) {
  const parts = [FIELD_NAME_NOTE];

  const discoveredEntries = Object.entries(discovered);
  if (discoveredEntries.length > 0) {
    const summary = discoveredEntries.map(([role, name]) => `${role}=${name}`).join(", ");
    parts.push(`Auto-discovered from this source's actual fields: ${summary}.`);
  }

  const ambiguousEntries = Object.entries(ambiguous);
  if (ambiguousEntries.length > 0) {
    const summary = ambiguousEntries
      .map(([role, names]) => `${role} could be ${names.join(" or ")}`)
      .join("; ");
    parts.push(
      `Ambiguous field(s), fell back to the configured default rather than guessing: ${summary}. ` +
        "Pass the correct one explicitly via the matching *_field argument."
    );
  }

  return parts.join(" ");
}

// For traffic_by_ip/host/path, the scoping field (which field to filter *on*) has to be resolved
// before the query can even be built — discovery here uses the literal value itself (the IP,
// hostname, or path) as free-text search context, which is exactly how this same field was found
// manually: search for the literal value, then look at what field actually held it.
async function resolveScopingField(account, role, literalValue, override) {
  const resolution = await discoverFieldNames(account, literalValue, { [role]: override }, [role]);
  return {
    field: resolution.fields[role],
    discovered: resolution.discovered,
    ambiguous: resolution.ambiguous
  };
}

// Merges a pre-resolved scoping field's discovery/ambiguity info into an aggregateTraffic()
// result and rebuilds its note, so the caller sees one coherent picture of every field this call
// resolved (the scoping field plus whatever aggregateTraffic itself discovered for the rest).
function mergeScopingResolution(result, scoping) {
  result.discovered_fields = { ...scoping.discovered, ...result.discovered_fields };
  result.ambiguous_fields = { ...scoping.ambiguous, ...result.ambiguous_fields };
  result.note = fieldResolutionNote(result.discovered_fields, result.ambiguous_fields);
  return result;
}

// Aggregation-first traffic summary: total + faceted breakdowns + a bucketed timeline + a small
// representative sample, instead of raw event dumps. This is the shape callers (like the bot
// traffic triage skill) should consume by default.
async function aggregateTraffic(account, options) {
  const {
    query,
    from,
    until,
    top_n = 10,
    sample_size = 15,
    bucket_count = 12,
    fields = {}
  } = options;

  const { fields: fieldNames, discovered, ambiguous } = await discoverFieldNames(account, query, fields);

  const [countResult, hostFacets, pathFacets, statusFacets, uaFacets, timelineResult, sampleResult] =
    await Promise.all([
      logglyGet(account, "/apiv2/events/count", { q: query, from, until }),
      logglyGet(account, `/apiv2/fields/${encodeURIComponent(fieldNames.host)}/`, {
        q: query,
        from,
        until,
        facet_size: top_n
      }),
      logglyGet(account, `/apiv2/fields/${encodeURIComponent(fieldNames.path)}/`, {
        q: query,
        from,
        until,
        facet_size: top_n
      }),
      logglyGet(account, `/apiv2/fields/${encodeURIComponent(fieldNames.status)}/`, {
        q: query,
        from,
        until,
        facet_size: top_n
      }),
      logglyGet(account, `/apiv2/fields/${encodeURIComponent(fieldNames.userAgent)}/`, {
        q: query,
        from,
        until,
        facet_size: top_n
      }),
      computeTimeline(account, query, from, until, bucket_count),
      logglyGet(account, "/apiv2/events/iterate", { q: query, from, until, size: sample_size, order: "desc" })
    ]);

  return {
    account: account.name,
    query,
    from,
    until,
    total_requests: numberOrNull(countResult?.count),
    unique_hosts: bestEffortTermCount(hostFacets),
    unique_paths: bestEffortTermCount(pathFacets),
    unique_user_agents: bestEffortTermCount(uaFacets),
    top_hosts: hostFacets,
    top_paths: pathFacets,
    status_codes: statusFacets,
    top_user_agents: uaFacets,
    timeline: timelineResult.buckets,
    timeline_note: timelineResult.note,
    sample_events: Array.isArray(sampleResult?.events) ? sampleResult.events.slice(0, sample_size) : [],
    field_mapping: fieldNames,
    discovered_fields: discovered,
    ambiguous_fields: ambiguous,
    note: fieldResolutionNote(discovered, ambiguous)
  };
}

// Per-account IP profile matching the shape a bot-traffic investigation actually wants: fixed
// 1h/24h/30d counts, first/last seen, and the hosts/paths this IP touched. Field resolution is
// per-account and two-phase, same reasoning as traffic_by_ip: the ip field has to be discovered
// first (via the literal IP as free-text search context) before the query can be built, then
// host/path fields are discovered against that same scoped query.
async function buildIpLogglyProfile(account, ip, overrides = {}) {
  const ipResolution = await discoverFieldNames(account, ip, { ip: overrides.ip }, ["ip"]);
  const ipField = ipResolution.fields.ip;
  const query = `${ipField}:"${ip}"`;

  const hostPathResolution = await discoverFieldNames(
    account,
    query,
    { host: overrides.host, path: overrides.path },
    ["host", "path"]
  );
  const fieldNames = { ip: ipField, host: hostPathResolution.fields.host, path: hostPathResolution.fields.path };
  const discovered = { ...ipResolution.discovered, ...hostPathResolution.discovered };
  const ambiguous = { ...ipResolution.ambiguous, ...hostPathResolution.ambiguous };

  const [requests1h, requests24h, requests30d, hostFacets, pathFacets, oldest, newest] = await Promise.all([
    logglyGet(account, "/apiv2/events/count", { q: query, from: "-1h", until: "now" }),
    logglyGet(account, "/apiv2/events/count", { q: query, from: "-24h", until: "now" }),
    logglyGet(account, "/apiv2/events/count", { q: query, from: "-30d", until: "now" }),
    logglyGet(account, `/apiv2/fields/${encodeURIComponent(fieldNames.host)}/`, {
      q: query,
      from: "-30d",
      until: "now",
      facet_size: 10
    }),
    logglyGet(account, `/apiv2/fields/${encodeURIComponent(fieldNames.path)}/`, {
      q: query,
      from: "-30d",
      until: "now",
      facet_size: 10
    }),
    logglyGet(account, "/apiv2/events/iterate", { q: query, from: "-30d", until: "now", size: 1, order: "asc" }),
    logglyGet(account, "/apiv2/events/iterate", { q: query, from: "-30d", until: "now", size: 1, order: "desc" })
  ]);

  return {
    account: account.name,
    requests_1h: numberOrNull(requests1h?.count),
    requests_24h: numberOrNull(requests24h?.count),
    requests_30d: numberOrNull(requests30d?.count),
    first_seen: oldest?.events?.[0]?.timestamp || null,
    last_seen: newest?.events?.[0]?.timestamp || null,
    hosts: hostFacets,
    top_paths: pathFacets,
    field_mapping: fieldNames,
    discovered_fields: discovered,
    ambiguous_fields: ambiguous
  };
}

async function getIpContext({ ip, account, ip_field, host_field, path_field }) {
  // Resolved per-account inside the loop below, not once here — different accounts can (and do)
  // parse logs into completely different field names, so a single shared resolution would be
  // wrong for every account except the one it happened to be discovered against.
  const fieldOverrides = { ip: ip_field, host: host_field, path: path_field };

  const [rdap, greynoise, abuseipdb] = await Promise.all([
    rdapLookup(ip).catch((error) => ({ available: false, error: error.message })),
    greyNoiseLookup(ip).catch((error) => ({ available: false, error: error.message })),
    abuseIpdbLookup(ip).catch((error) => ({ available: false, error: error.message }))
  ]);

  const accountsToQuery = account
    ? [resolveAccount(account)]
    : [...ACCOUNTS.keys()]
        .map((name) => {
          try {
            return resolveAccount(name);
          } catch {
            return null;
          }
        })
        .filter(Boolean);

  const loggly = {};
  for (const acct of accountsToQuery) {
    try {
      loggly[acct.name] = await buildIpLogglyProfile(acct, ip, fieldOverrides);
    } catch (error) {
      loggly[acct.name] = { error: error instanceof Error ? error.message : String(error) };
    }
  }

  const accountsWithActivity = Object.entries(loggly)
    .filter(([, profile]) => typeof profile.requests_30d === "number" && profile.requests_30d > 0)
    .map(([name]) => name);

  return {
    ip,
    rdap,
    threat_intel: { greynoise, abuseipdb },
    loggly,
    // Per the bot-traffic-triage skill: the same source hitting multiple distinct client
    // domains/accounts is a materially stronger signal than volume on any single domain.
    cross_domain_correlation: accountsWithActivity.length > 1,
    accounts_with_activity: accountsWithActivity
  };
}

function formatToolResult(data) {
  if (typeof data === "string") {
    return {
      content: [
        {
          type: "text",
          text: data
        }
      ]
    };
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

function getRsidId(searchResponse) {
  const rsid = searchResponse?.rsid;

  if (!rsid) {
    return null;
  }

  if (typeof rsid === "string") {
    return rsid;
  }

  if (typeof rsid === "object" && typeof rsid.id === "string") {
    return rsid.id;
  }

  return null;
}

function eventCountFromResponse(result) {
  return Array.isArray(result?.events) ? result.events.length : 0;
}

const RESOURCE_MIME_TYPE = "application/json";
export const SERVER_VERSION = "1.3.0";

/**
 * Builds a fresh McpServer with all Loggly tools/resources registered.
 * Called once for the stdio entrypoint, and once per request for the
 * stateless HTTP entrypoint.
 */
export function createServer() {
  const toolRegistry = new Map();

  const server = new McpServer({
    name: "loggly-api-mcp",
    version: SERVER_VERSION
  });

  function registerToolWithResource(name, config, handler) {
    toolRegistry.set(name, {
      name,
      title: config?.title || name,
      description: config?.description || "",
      inputSchema: config?.inputSchema || null,
      handler
    });

    return server.registerTool(name, config, handler);
  }

  const RESOURCE_TEMPLATES = [
    {
      name: "tool",
      title: "Loggly Tool",
      uriTemplate: "loggly://tool/{name}",
      description: "Metadata for a Loggly MCP tool.",
      mimeType: RESOURCE_MIME_TYPE
    },
    {
      name: "tool-call",
      title: "Loggly Tool Call",
      uriTemplate: "loggly://tool/{name}/call{?arguments_json}",
      description:
        "Call a Loggly MCP tool through resources/read. arguments_json must be a JSON-encoded object.",
      mimeType: RESOURCE_MIME_TYPE
    }
  ];

  registerToolWithResource(
    "connection_test",
    {
      title: "Connection Test",
      description:
        "Validates Loggly credentials by creating a small search and returning the RSID.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-15m"),
        until: z.string().default("now"),
        size: z.number().int().min(1).max(5000).default(1),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, size, account }) => {
      const acct = resolveAccount(account);
      const data = await logglyGet(acct, "/apiv2/search", {
        q: query,
        from,
        until,
        size
      });

      return formatToolResult({
        ok: true,
        account: acct.name,
        subdomain: acct.subdomain,
        authMode: acct.authMode,
        available_accounts: [...ACCOUNTS.keys()],
        rsid_id: getRsidId(data),
        search_response: data
      });
    }
  );

  registerToolWithResource(
    "create_search",
    {
      title: "Create Search",
      description: "Creates a Loggly search and returns its RSID metadata.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        order: z.enum(["asc", "desc"]).default("desc"),
        size: z.number().int().min(1).max(5000).default(50),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, order, size, account }) => {
      const acct = resolveAccount(account);
      const search = await logglyGet(acct, "/apiv2/search", {
        q: query,
        from,
        until,
        order,
        size
      });

      return formatToolResult({
        account: acct.name,
        query,
        from,
        until,
        order,
        size,
        rsid_id: getRsidId(search),
        search
      });
    }
  );

  registerToolWithResource(
    "get_events",
    {
      title: "Get Events",
      description:
        "Retrieves event results for a previously-created RSID from /apiv2/events.",
      inputSchema: {
        rsid: z.string(),
        page: z.number().int().min(0).default(0),
        format: z.enum(["json", "raw", "csv"]).optional(),
        columns: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ rsid, page, format, columns, account }) => {
      if (columns && format !== "csv") {
        throw new Error("`columns` requires `format=\"csv\"` per Loggly API behavior.");
      }

      const acct = resolveAccount(account);
      const events = await logglyGet(acct, "/apiv2/events", {
        rsid,
        page,
        format,
        columns
      });

      if (typeof events === "string") {
        return formatToolResult(events);
      }

      return formatToolResult({
        account: acct.name,
        rsid,
        page,
        format: format || "json",
        columns: columns || null,
        events
      });
    }
  );

  registerToolWithResource(
    "search_and_get_events",
    {
      title: "Search And Get Events",
      description:
        "Creates a search then fetches one page from legacy /apiv2/events using the returned RSID.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-2h"),
        until: z.string().default("now"),
        order: z.enum(["asc", "desc"]).default("desc"),
        size: z.number().int().min(1).max(5000).default(50),
        page: z.number().int().min(0).default(0),
        format: z.enum(["json", "raw", "csv"]).optional(),
        columns: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, order, size, page, format, columns, account }) => {
      if (columns && format !== "csv") {
        throw new Error("`columns` requires `format=\"csv\"` per Loggly API behavior.");
      }

      const acct = resolveAccount(account);
      const search = await logglyGet(acct, "/apiv2/search", {
        q: query,
        from,
        until,
        order,
        size
      });

      const rsid = getRsidId(search);

      if (!rsid) {
        return formatToolResult({
          account: acct.name,
          query,
          from,
          until,
          order,
          size,
          page,
          error: "Search response did not include an RSID.",
          search
        });
      }

      const events = await logglyGet(acct, "/apiv2/events", {
        rsid,
        page,
        format,
        columns
      });

      return formatToolResult({
        account: acct.name,
        query,
        from,
        until,
        order,
        size,
        page,
        rsid,
        format: format || "json",
        columns: columns || null,
        search,
        events
      });
    }
  );

  registerToolWithResource(
    "count_events",
    {
      title: "Count Events",
      description:
        "Calls /apiv2/events/count to return event count and optional volume.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        include_volume: z.boolean().default(false),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, include_volume, account }) => {
      const acct = resolveAccount(account);
      const result = await logglyGet(acct, "/apiv2/events/count", {
        q: query,
        from,
        until,
        include_volume: include_volume ? "true" : undefined
      });

      return formatToolResult({
        account: acct.name,
        query,
        from,
        until,
        include_volume,
        result
      });
    }
  );

  registerToolWithResource(
    "iterate_events_page",
    {
      title: "Iterate Events Page",
      description:
        "Calls /apiv2/events/iterate with query parameters and returns the first page plus `next` URL.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        size: z.number().int().min(1).max(1000).default(50),
        order: z.enum(["asc", "desc"]).default("desc"),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, size, order, account }) => {
      const acct = resolveAccount(account);
      const result = await logglyGet(acct, "/apiv2/events/iterate", {
        q: query,
        from,
        until,
        size,
        order
      });

      return formatToolResult({
        account: acct.name,
        query,
        from,
        until,
        size,
        order,
        event_count: eventCountFromResponse(result),
        next_url: result?.next || null,
        result
      });
    }
  );

  registerToolWithResource(
    "iterate_events_next",
    {
      title: "Iterate Events Next",
      description:
        "Fetches the next page from /apiv2/events/iterate using the exact `next` URL returned by the previous page.",
      inputSchema: {
        next_url: z.string().url(),
        account: z.string().optional()
      }
    },
    async ({ next_url, account }) => {
      const acct = account ? resolveAccount(account) : resolveAccountForUrl(next_url);
      const trustedUrl = ensureTrustedIterateUrl(acct, next_url);
      const result = await logglyGetAbsolute(acct, trustedUrl);

      return formatToolResult({
        account: acct.name,
        event_count: eventCountFromResponse(result),
        next_url: result?.next || null,
        result
      });
    }
  );

  registerToolWithResource(
    "volume_metrics",
    {
      title: "Volume Metrics",
      description:
        "Calls /apiv2/volume-metrics to retrieve count/volume grouped or filtered by host/app/log type/tag.",
      inputSchema: {
        from: z.string().default("-1h"),
        until: z.string().default("now"),
        group_by: z
          .array(z.enum(["host", "app", "log_type", "tag"]))
          .optional(),
        host: z.array(z.string()).optional(),
        app: z.array(z.string()).optional(),
        log_type: z.array(z.string()).optional(),
        measurement_types: z
          .array(z.enum(["volume_bytes", "count"]))
          .optional(),
        account: z.string().optional()
      }
    },
    async ({
      from,
      until,
      group_by,
      host,
      app,
      log_type,
      measurement_types,
      account
    }) => {
      const acct = resolveAccount(account);
      const result = await logglyGet(acct, "/apiv2/volume-metrics", {
        from,
        until,
        group_by,
        host,
        app,
        log_type,
        measurement_types
      });

      return formatToolResult({
        account: acct.name,
        from,
        until,
        group_by: group_by || [],
        host: host || [],
        app: app || [],
        log_type: log_type || [],
        measurement_types: measurement_types || ["volume_bytes", "count"],
        result
      });
    }
  );

  registerToolWithResource(
    "stats_query",
    {
      title: "Stats Query",
      description:
        "Calls /apiv2/stats/<stat_type>/<field> for numeric field statistics.",
      inputSchema: {
        stat_type: z.enum([
          "avg",
          "sum",
          "min",
          "max",
          "percentiles",
          "value_count",
          "cardinality",
          "stats",
          "all",
          "extended"
        ]),
        field: z.string(),
        query: z.string().default("*"),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        account: z.string().optional()
      }
    },
    async ({ stat_type, field, query, from, until, account }) => {
      const acct = resolveAccount(account);
      const encodedField = encodeURIComponent(field);
      const result = await logglyGet(acct, `/apiv2/stats/${stat_type}/${encodedField}`, {
        q: query,
        from,
        until
      });

      return formatToolResult({
        account: acct.name,
        stat_type,
        field,
        query,
        from,
        until,
        result
      });
    }
  );

  registerToolWithResource(
    "list_fields",
    {
      title: "List Fields",
      description:
        "Calls /apiv2/fields/ to return parsed field names in the selected time range.",
      inputSchema: {
        query: z.string().optional(),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        facet_size: z.number().int().min(1).max(500).default(10),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, facet_size, account }) => {
      const acct = resolveAccount(account);
      const result = await logglyGet(acct, "/apiv2/fields/", {
        q: query,
        from,
        until,
        facet_size
      });

      return formatToolResult({
        account: acct.name,
        query: query || null,
        from,
        until,
        facet_size,
        result
      });
    }
  );

  registerToolWithResource(
    "field_facets",
    {
      title: "Field Facets",
      description:
        "Calls /apiv2/fields/<field>/ to return terms and counts for a specific field.",
      inputSchema: {
        field_name: z.string(),
        query: z.string().optional(),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        facet_size: z.number().int().min(1).max(300).default(10),
        account: z.string().optional()
      }
    },
    async ({ field_name, query, from, until, facet_size, account }) => {
      const acct = resolveAccount(account);
      const encodedField = encodeURIComponent(field_name);
      const result = await logglyGet(acct, `/apiv2/fields/${encodedField}/`, {
        q: query,
        from,
        until,
        facet_size
      });

      return formatToolResult({
        account: acct.name,
        field_name,
        query: query || null,
        from,
        until,
        facet_size,
        result
      });
    }
  );

  registerToolWithResource(
    "raw_api_call",
    {
      title: "Raw API Call",
      description:
        "Makes a GET request to a Loggly API path. Useful while discovering exact endpoint behavior.",
      inputSchema: {
        path: z.string().default("/apiv2/search"),
        paramsJson: z
          .string()
          .default("{\"q\":\"*\",\"from\":\"-15m\",\"until\":\"now\",\"size\":1}"),
        account: z.string().optional()
      }
    },
    async ({ path, paramsJson, account }) => {
      let params;
      try {
        params = JSON.parse(paramsJson);
      } catch (error) {
        throw new Error(`Invalid paramsJson: ${String(error)}`);
      }

      const acct = resolveAccount(account);
      const data = await logglyGet(acct, path, params);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ account: acct.name, path, params, data }, null, 2)
          }
        ]
      };
    }
  );

  registerToolWithResource(
    "search_logs",
    {
      title: "Search Logs (Aggregated)",
      description:
        "Runs a query and returns an aggregated summary (total, top hosts/paths/status codes/" +
        "user agents, a bucketed timeline, and a small representative sample) instead of raw " +
        "events. Prefer this over get_events/iterate_events_* for exploratory analysis.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-1h"),
        until: z.string().default("now"),
        top_n: z.number().int().min(1).max(100).default(10),
        sample_size: z.number().int().min(0).max(50).default(15),
        bucket_count: z.number().int().min(1).max(48).default(12),
        host_field: z.string().optional(),
        path_field: z.string().optional(),
        status_field: z.string().optional(),
        user_agent_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({
      query,
      from,
      until,
      top_n,
      sample_size,
      bucket_count,
      host_field,
      path_field,
      status_field,
      user_agent_field,
      account
    }) => {
      const acct = resolveAccount(account);
      const result = await aggregateTraffic(acct, {
        query,
        from,
        until,
        top_n,
        sample_size,
        bucket_count,
        fields: { host: host_field, path: path_field, status: status_field, userAgent: user_agent_field }
      });
      return formatToolResult(result);
    }
  );

  registerToolWithResource(
    "traffic_by_ip",
    {
      title: "Traffic By IP",
      description: "Aggregated traffic summary (see search_logs) scoped to a single IP address.",
      inputSchema: {
        ip: z.string(),
        window: z.string().default("-1h"),
        top_n: z.number().int().min(1).max(100).default(10),
        sample_size: z.number().int().min(0).max(50).default(15),
        bucket_count: z.number().int().min(1).max(48).default(12),
        ip_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ ip, window, top_n, sample_size, bucket_count, ip_field, account }) => {
      const acct = resolveAccount(account);
      const scoping = await resolveScopingField(acct, "ip", ip, ip_field);
      const result = await aggregateTraffic(acct, {
        query: `${scoping.field}:"${ip}"`,
        from: window,
        until: "now",
        top_n,
        sample_size,
        bucket_count,
        fields: { ip: scoping.field }
      });
      return formatToolResult(mergeScopingResolution(result, scoping));
    }
  );

  registerToolWithResource(
    "traffic_by_host",
    {
      title: "Traffic By Host",
      description: "Aggregated traffic summary (see search_logs) scoped to a single hostname.",
      inputSchema: {
        hostname: z.string(),
        window: z.string().default("-1h"),
        top_n: z.number().int().min(1).max(100).default(10),
        sample_size: z.number().int().min(0).max(50).default(15),
        bucket_count: z.number().int().min(1).max(48).default(12),
        host_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ hostname, window, top_n, sample_size, bucket_count, host_field, account }) => {
      const acct = resolveAccount(account);
      const scoping = await resolveScopingField(acct, "host", hostname, host_field);
      const result = await aggregateTraffic(acct, {
        query: `${scoping.field}:"${hostname}"`,
        from: window,
        until: "now",
        top_n,
        sample_size,
        bucket_count,
        fields: { host: scoping.field }
      });
      return formatToolResult(mergeScopingResolution(result, scoping));
    }
  );

  registerToolWithResource(
    "traffic_by_path",
    {
      title: "Traffic By Path",
      description: "Aggregated traffic summary (see search_logs) scoped to a single request path.",
      inputSchema: {
        path: z.string(),
        window: z.string().default("-1h"),
        top_n: z.number().int().min(1).max(100).default(10),
        sample_size: z.number().int().min(0).max(50).default(15),
        bucket_count: z.number().int().min(1).max(48).default(12),
        path_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ path, window, top_n, sample_size, bucket_count, path_field, account }) => {
      const acct = resolveAccount(account);
      const scoping = await resolveScopingField(acct, "path", path, path_field);
      const result = await aggregateTraffic(acct, {
        query: `${scoping.field}:"${path}"`,
        from: window,
        until: "now",
        top_n,
        sample_size,
        bucket_count,
        fields: { path: scoping.field }
      });
      return formatToolResult(mergeScopingResolution(result, scoping));
    }
  );

  registerToolWithResource(
    "group_by_ip",
    {
      title: "Group By IP",
      description: "Facet counts by IP for a query/time range (thin wrapper over field_facets).",
      inputSchema: {
        query: z.string().default("*"),
        window: z.string().default("-1h"),
        facet_size: z.number().int().min(1).max(300).default(10),
        ip_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ query, window, facet_size, ip_field, account }) => {
      const acct = resolveAccount(account);
      const resolution = await discoverFieldNames(acct, query, { ip: ip_field }, ["ip"]);
      const field = resolution.fields.ip;
      const result = await logglyGet(acct, `/apiv2/fields/${encodeURIComponent(field)}/`, {
        q: query,
        from: window,
        until: "now",
        facet_size
      });
      return formatToolResult({
        account: acct.name,
        field,
        query,
        window,
        facet_size,
        result,
        note: fieldResolutionNote(resolution.discovered, resolution.ambiguous)
      });
    }
  );

  registerToolWithResource(
    "group_by_path",
    {
      title: "Group By Path",
      description: "Facet counts by path for a query/time range (thin wrapper over field_facets).",
      inputSchema: {
        query: z.string().default("*"),
        window: z.string().default("-1h"),
        facet_size: z.number().int().min(1).max(300).default(10),
        path_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ query, window, facet_size, path_field, account }) => {
      const acct = resolveAccount(account);
      const resolution = await discoverFieldNames(acct, query, { path: path_field }, ["path"]);
      const field = resolution.fields.path;
      const result = await logglyGet(acct, `/apiv2/fields/${encodeURIComponent(field)}/`, {
        q: query,
        from: window,
        until: "now",
        facet_size
      });
      return formatToolResult({
        account: acct.name,
        field,
        query,
        window,
        facet_size,
        result,
        note: fieldResolutionNote(resolution.discovered, resolution.ambiguous)
      });
    }
  );

  registerToolWithResource(
    "group_by_user_agent",
    {
      title: "Group By User Agent",
      description: "Facet counts by User-Agent for a query/time range (thin wrapper over field_facets).",
      inputSchema: {
        query: z.string().default("*"),
        window: z.string().default("-1h"),
        facet_size: z.number().int().min(1).max(300).default(10),
        user_agent_field: z.string().optional(),
        account: z.string().optional()
      }
    },
    async ({ query, window, facet_size, user_agent_field, account }) => {
      const acct = resolveAccount(account);
      const resolution = await discoverFieldNames(acct, query, { userAgent: user_agent_field }, ["userAgent"]);
      const field = resolution.fields.userAgent;
      const result = await logglyGet(acct, `/apiv2/fields/${encodeURIComponent(field)}/`, {
        q: query,
        from: window,
        until: "now",
        facet_size
      });
      return formatToolResult({
        account: acct.name,
        field,
        query,
        window,
        facet_size,
        result,
        note: fieldResolutionNote(resolution.discovered, resolution.ambiguous)
      });
    }
  );

  registerToolWithResource(
    "timeline",
    {
      title: "Timeline",
      description: "Bucketed event counts over a time range for a query, computed client-side from /apiv2/events/count.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-24h"),
        until: z.string().default("now"),
        bucket_count: z.number().int().min(1).max(48).default(12),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, bucket_count, account }) => {
      const acct = resolveAccount(account);
      const result = await computeTimeline(acct, query, from, until, bucket_count);
      return formatToolResult({
        account: acct.name,
        query,
        from,
        until,
        bucket_count,
        buckets: result.buckets,
        note: result.note
      });
    }
  );

  registerToolWithResource(
    "sample_events",
    {
      title: "Sample Events",
      description:
        "Returns a small number of representative events for a query — use this instead of " +
        "pulling full result pages when you just need examples, not the complete set.",
      inputSchema: {
        query: z.string().default("*"),
        from: z.string().default("-1h"),
        until: z.string().default("now"),
        limit: z.number().int().min(1).max(50).default(15),
        order: z.enum(["asc", "desc"]).default("desc"),
        account: z.string().optional()
      }
    },
    async ({ query, from, until, limit, order, account }) => {
      const acct = resolveAccount(account);
      const result = await logglyGet(acct, "/apiv2/events/iterate", {
        q: query,
        from,
        until,
        size: limit,
        order
      });
      return formatToolResult({
        account: acct.name,
        query,
        from,
        until,
        limit,
        order,
        sample_events: Array.isArray(result?.events) ? result.events.slice(0, limit) : []
      });
    }
  );

  registerToolWithResource(
    "rdap_lookup",
    {
      title: "RDAP Lookup",
      description:
        "Looks up IP ownership/network registration data (RIR, netblock, org, country) via " +
        "public RDAP (rdap.org) — no API key required.",
      inputSchema: {
        ip: z.string()
      }
    },
    async ({ ip }) => formatToolResult(await rdapLookup(ip))
  );

  registerToolWithResource(
    "ip_reputation",
    {
      title: "IP Reputation",
      description:
        "Checks GreyNoise (internet-wide scanning noise) and AbuseIPDB (community abuse " +
        "reports) for an IP. Requires GREYNOISE_API_KEY / ABUSEIPDB_API_KEY env vars — returns " +
        "available:false for whichever isn't configured, rather than erroring.",
      inputSchema: {
        ip: z.string()
      }
    },
    async ({ ip }) => {
      const [greynoise, abuseipdb] = await Promise.all([greyNoiseLookup(ip), abuseIpdbLookup(ip)]);
      return formatToolResult({ ip, greynoise, abuseipdb });
    }
  );

  registerToolWithResource(
    "get_ip_context",
    {
      title: "Get IP Context",
      description:
        "Combines RDAP, GreyNoise/AbuseIPDB reputation, and Loggly traffic (1h/24h/30d counts, " +
        "first/last seen, hosts, top paths — checked across every configured Loggly account " +
        "unless `account` is given) into one normalized profile for an IP. Flags " +
        "cross_domain_correlation when the IP shows activity in more than one account, which " +
        "the bot-traffic-triage playbook treats as the single strongest escalation signal.",
      inputSchema: {
        ip: z.string(),
        account: z.string().optional(),
        ip_field: z.string().optional(),
        host_field: z.string().optional(),
        path_field: z.string().optional()
      }
    },
    async ({ ip, account, ip_field, host_field, path_field }) =>
      formatToolResult(await getIpContext({ ip, account, ip_field, host_field, path_field }))
  );

  server.registerResource(
    "server-info",
    "loggly://server/info",
    {
      title: "Server Info",
      description: "Loggly MCP server configuration and capability summary.",
      mimeType: RESOURCE_MIME_TYPE
    },
    async (uri) => toReadResourceResult(uri.toString(), buildServerInfo(toolRegistry, RESOURCE_TEMPLATES))
  );

  server.registerResource(
    "tools",
    "loggly://tools",
    {
      title: "Tools",
      description: "All registered Loggly MCP tools and input metadata.",
      mimeType: RESOURCE_MIME_TYPE
    },
    async (uri) =>
      toReadResourceResult(uri.toString(), {
        tool_count: toolRegistry.size,
        tools: listToolMetadata(toolRegistry)
      })
  );

  server.registerResource(
    "resource-templates",
    "loggly://resource-templates",
    {
      title: "Resource Templates",
      description: "Parameterized resource URI templates supported by this server.",
      mimeType: RESOURCE_MIME_TYPE
    },
    async (uri) =>
      toReadResourceResult(uri.toString(), {
        resource_template_count: RESOURCE_TEMPLATES.length,
        resource_templates: RESOURCE_TEMPLATES
      })
  );

  for (const meta of toolRegistry.values()) {
    const baseUri = `loggly://tool/${encodeURIComponent(meta.name)}`;

    server.registerResource(
      `tool-${meta.name}`,
      baseUri,
      {
        title: `${meta.name} Tool`,
        description: meta.description || "Loggly MCP tool metadata.",
        mimeType: RESOURCE_MIME_TYPE
      },
      async (uri) => toReadResourceResult(uri.toString(), sanitizeToolMetadata(meta))
    );

    server.registerResource(
      `tool-call-${meta.name}`,
      `${baseUri}/call`,
      {
        title: `${meta.name} Tool Call`,
        description:
          "Execute this tool via resources/read. Pass JSON object in ?arguments_json=...",
        mimeType: RESOURCE_MIME_TYPE
      },
      async (uri) => {
        const args = parseArgumentsJson(uri.searchParams.get("arguments_json"));
        const result = await executeToolByName(toolRegistry, meta.name, args);
        return toReadResourceResult(uri.toString(), {
          tool: meta.name,
          arguments: args,
          result
        });
      }
    );
  }

  server.registerResource(
    "tool-call-template",
    new ResourceTemplate("loggly://tool/{name}/call{?arguments_json}", {}),
    {
      title: "Tool Call Template",
      description:
        "Generic Loggly tool call template. Use ?arguments_json=<JSON object> for tool inputs.",
      mimeType: RESOURCE_MIME_TYPE
    },
    async (uri, variables) => {
      const toolName = getTemplateVarString(variables, "name");
      if (!toolName) {
        throw new Error("Tool call template requires {name}");
      }
      const args = parseArgumentsJson(uri.searchParams.get("arguments_json"));
      const result = await executeToolByName(toolRegistry, toolName, args);
      return toReadResourceResult(uri.toString(), {
        tool: toolName,
        arguments: args,
        result
      });
    }
  );

  return { server, toolRegistry };
}

function buildServerInfo(toolRegistry, resourceTemplates) {
  return {
    name: "loggly-api-mcp",
    version: SERVER_VERSION,
    default_account: DEFAULT_ACCOUNT_NAME,
    accounts: [...ACCOUNTS.values()].map((account) => ({
      name: account.name,
      subdomain: account.subdomain || null,
      auth_mode: account.authMode,
      configured: Boolean(account.subdomain) && Boolean(account.token)
    })),
    log_level: settings.logLevel,
    max_retries: settings.maxRetries,
    request_timeout_ms: settings.requestTimeoutMs,
    max_concurrent_requests: settings.maxConcurrentRequests,
    field_mapping: settings.fields,
    ip_intelligence: {
      rdap: "always available (rdap.org, no key required)",
      greynoise_configured: Boolean(process.env.GREYNOISE_API_KEY),
      abuseipdb_configured: Boolean(process.env.ABUSEIPDB_API_KEY)
    },
    tool_count: toolRegistry.size,
    resource_template_count: resourceTemplates.length
  };
}

function listToolMetadata(toolRegistry) {
  return [...toolRegistry.values()]
    .map((meta) => sanitizeToolMetadata(meta))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function sanitizeToolMetadata(meta) {
  return {
    name: meta.name,
    title: meta.title || meta.name,
    description: meta.description || null,
    input_fields:
      meta.inputSchema && typeof meta.inputSchema === "object"
        ? Object.keys(meta.inputSchema).sort()
        : []
  };
}

async function executeToolByName(toolRegistry, toolName, args) {
  const meta = toolRegistry.get(toolName);
  if (!meta) {
    throw new Error(`Unknown tool: ${toolName}`);
  }

  const safeArgs =
    args && typeof args === "object" && !Array.isArray(args) ? args : {};
  return meta.handler(safeArgs);
}

function parseArgumentsJson(raw) {
  if (raw === null || raw === undefined || String(raw).trim() === "") {
    return {};
  }

  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    throw new Error("arguments_json must be valid JSON");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("arguments_json must decode to a JSON object");
  }

  return parsed;
}

function getTemplateVarString(variables, key) {
  const value = variables?.[key];
  if (Array.isArray(value)) {
    return value.length > 0 ? String(value[0]) : "";
  }
  return value === undefined || value === null ? "" : String(value);
}

function toReadResourceResult(uri, payload) {
  let text;
  try {
    text = JSON.stringify(payload, null, 2);
  } catch {
    text = JSON.stringify({ value: String(payload) });
  }

  return {
    contents: [
      {
        uri,
        mimeType: RESOURCE_MIME_TYPE,
        text
      }
    ]
  };
}

export { ACCOUNTS, DEFAULT_ACCOUNT_NAME, settings };
