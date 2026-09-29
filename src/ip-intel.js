// Standalone IP intelligence clients (RDAP, GreyNoise, AbuseIPDB). Deliberately has no
// dependency on server.js/loggly-client internals — it's a separate data source, not a Loggly
// concern, and keeping it standalone avoids a circular import with server.js.

const REQUEST_TIMEOUT_MS = Number.parseInt(process.env.IP_INTEL_TIMEOUT_MS || "10000", 10);
// Some upstream WAFs (e.g. rdap.org's Cloudflare front) block requests with no/blank
// User-Agent as a bot heuristic. A descriptive client UA is standard practice for API clients.
const USER_AGENT = "loggly-mcp-ip-intel/1.2.0";

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_CHAR_RE = /^[0-9a-fA-F:]+$/;

function isValidIp(ip) {
  const raw = String(ip || "").trim();
  const v4 = IPV4_RE.exec(raw);
  if (v4) {
    return v4.slice(1).every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return raw.includes(":") && IPV6_CHAR_RE.test(raw);
}

function assertValidIp(ip) {
  if (!isValidIp(ip)) {
    throw new Error(`"${ip}" does not look like a valid IPv4/IPv6 address.`);
  }
}

async function fetchJsonWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    let response;
    try {
      response = await fetch(url, {
        ...options,
        headers: { "User-Agent": USER_AGENT, ...options.headers },
        signal: controller.signal
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Network request to ${new URL(url).host} failed: ${message}`);
    }

    const text = await response.text();
    let body;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    return { ok: response.ok, status: response.status, body };
  } finally {
    clearTimeout(timeout);
  }
}

function extractRdapOrgName(rdap) {
  const entities = Array.isArray(rdap?.entities) ? rdap.entities : [];
  for (const entity of entities) {
    const vcard = entity?.vcardArray;
    if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) {
      continue;
    }
    const fnEntry = vcard[1].find((entry) => Array.isArray(entry) && entry[0] === "fn");
    if (fnEntry && typeof fnEntry[3] === "string") {
      return fnEntry[3];
    }
  }
  return null;
}

// RDAP via rdap.org's public bootstrap redirector — routes to whichever RIR (ARIN/RIPE/APNIC/
// LACNIC/AFRINIC) actually holds the record. No API key, no rate-limit guarantees documented.
export async function rdapLookup(ip) {
  assertValidIp(ip);

  const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;
  const { ok, status, body } = await fetchJsonWithTimeout(url, {
    headers: { Accept: "application/rdap+json" }
  });

  if (!ok) {
    return {
      available: false,
      status,
      error: typeof body === "string" ? body : JSON.stringify(body)
    };
  }

  const remarks = Array.isArray(body?.remarks)
    ? body.remarks.flatMap((remark) => (Array.isArray(remark?.description) ? remark.description : []))
    : [];

  return {
    available: true,
    handle: body?.handle || null,
    name: body?.name || null,
    type: body?.type || null,
    country: body?.country || null,
    start_address: body?.startAddress || null,
    end_address: body?.endAddress || null,
    organization: extractRdapOrgName(body),
    remarks,
    raw: body
  };
}

// GreyNoise Community API — answers "is this IP known internet-wide scanning noise, or does it
// look targeted?" Optional: requires GREYNOISE_API_KEY.
export async function greyNoiseLookup(ip) {
  const apiKey = process.env.GREYNOISE_API_KEY;
  if (!apiKey) {
    return { available: false, reason: "GREYNOISE_API_KEY not configured." };
  }

  assertValidIp(ip);

  const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
  const { ok, status, body } = await fetchJsonWithTimeout(url, {
    headers: { key: apiKey, Accept: "application/json" }
  });

  if (status === 404) {
    return { available: true, observed: false, message: body?.message || "No GreyNoise data for this IP." };
  }

  if (!ok) {
    return {
      available: false,
      status,
      error: typeof body === "string" ? body : JSON.stringify(body)
    };
  }

  return {
    available: true,
    observed: Boolean(body?.noise || body?.riot),
    noise: Boolean(body?.noise),
    riot: Boolean(body?.riot),
    classification: body?.classification || null,
    name: body?.name || null,
    link: body?.link || null,
    last_seen: body?.last_seen || null
  };
}

// AbuseIPDB — community-reported abuse. A signal to combine with direct evidence, not a
// standalone verdict. Optional: requires ABUSEIPDB_API_KEY.
export async function abuseIpdbLookup(ip, maxAgeInDays = 90) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { available: false, reason: "ABUSEIPDB_API_KEY not configured." };
  }

  assertValidIp(ip);

  const url = new URL("https://api.abuseipdb.com/api/v2/check");
  url.searchParams.set("ipAddress", ip);
  url.searchParams.set("maxAgeInDays", String(maxAgeInDays));

  const { ok, status, body } = await fetchJsonWithTimeout(url, {
    headers: { Key: apiKey, Accept: "application/json" }
  });

  if (!ok) {
    return {
      available: false,
      status,
      error: typeof body === "string" ? body : JSON.stringify(body)
    };
  }

  const data = body?.data || {};
  return {
    available: true,
    abuse_confidence_score: typeof data.abuseConfidenceScore === "number" ? data.abuseConfidenceScore : null,
    total_reports: typeof data.totalReports === "number" ? data.totalReports : null,
    num_distinct_users: typeof data.numDistinctUsers === "number" ? data.numDistinctUsers : null,
    last_reported_at: data.lastReportedAt || null,
    is_whitelisted: typeof data.isWhitelisted === "boolean" ? data.isWhitelisted : null,
    usage_type: data.usageType || null,
    isp: data.isp || null,
    domain: data.domain || null
  };
}

export { isValidIp };
