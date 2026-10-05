# Loggly MCP

[![loggly-mcp MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/andrewbabu/loggly-mcp/badges/card.svg)](https://glama.ai/mcp/servers/andrewbabu/loggly-mcp)

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/andrewbabu/loggly-mcp)

Read-only **Model Context Protocol (MCP) server** for Loggly `/apiv2/*` APIs, plus IP
intelligence (RDAP, GreyNoise, AbuseIPDB). Exposes Loggly search/analytics/field tools,
aggregation-first traffic tools, and IP-context tools, while blocking write endpoints.

---

# Skill Usage

For efficient log retrieval (less token use) and summarization, pair this server with a skill.

---

# Quickstart

## Install from npm

```bash
LOGGLY_SUBDOMAIN=your-subdomain LOGGLY_TOKEN=your-token npx -y @andrewbabu/loggly-mcp
```

MCP client configuration:

```json
{
  "mcpServers": {
    "loggly": {
      "command": "npx",
      "args": ["-y", "@andrewbabu/loggly-mcp"],
      "env": {
        "LOGGLY_SUBDOMAIN": "your-subdomain",
        "LOGGLY_TOKEN": "your-token"
      }
    }
  }
}
```

## Run from source

```bash
git clone https://github.com/andrewbabu/loggly-mcp.git
cd loggly-mcp
npm install
cp .env.example .env
```

Edit `.env` with your Loggly credentials, then run:

```bash
npm start
```

Once the repo is trusted in Codex, the MCP server can also be started automatically via `.codex/config.toml`.

---

# Configuration

The server loads `.env` from its working directory on startup.

## Required

- `LOGGLY_SUBDOMAIN`  
  Loggly account subdomain or full Loggly URL (e.g. `your-subdomain` or `https://your-subdomain.loggly.com`)
- `LOGGLY_TOKEN`  
  Loggly API token

## Optional

- `LOGGLY_AUTH_MODE`  
  `bearer` (default) or `basic`
- `LOGGLY_MAX_RETRIES`  
  Default: `2`
- `LOGGLY_REQUEST_TIMEOUT_MS`  
  Default: `15000`
- `LOGGLY_LOG_LEVEL`  
  `error`, `warn`, `info` (default), or `debug`

---

# Remote (HTTP) Server

For a stdio server anyone on the team can reach from Claude Code without a local checkout, run
the HTTP variant instead and host it on an internal server/VM.

```bash
cp .env.example .env
```

Edit `.env` with your Loggly credentials plus `MCP_BEARER_TOKEN` (generate one with
`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`), then:

```bash
npm run start:http
```

This starts a stateless Streamable HTTP MCP server on `MCP_HTTP_PORT` (default `8787`):

- `GET /healthz` — unauthenticated liveness check.
- `POST /mcp` — the MCP endpoint. Requires `Authorization: Bearer <MCP_BEARER_TOKEN>`; every
  other request to `/mcp` gets `401`.

The Loggly credentials stay server-side — everyone connecting shares the same Loggly account
access. `MCP_BEARER_TOKEN` only gates access to the MCP server itself, so treat it as a secret
and rotate it if it leaks (e.g. re-generate and redistribute).

**Only run this behind your internal network/VPN**, not exposed directly to the public internet —
there's a single shared token, not per-user auth.

## Connecting from Claude Code

Each org member adds the remote server once:

```bash
claude mcp add --transport http loggly https://your-internal-host:8787/mcp \
  --header "Authorization: Bearer <MCP_BEARER_TOKEN>"
```

Swap in the internal hostname/port you deployed to and the token you were given.

## Running with Docker

```bash
docker build -t loggly-mcp .
docker run -d --name loggly-mcp -p 8787:8787 --env-file .env loggly-mcp
```

---

# Multiple Accounts / Domains

The server can hold credentials for several Loggly accounts (different subdomains, different
tokens) at once and target them per tool call.

Set `LOGGLY_ACCOUNTS` to a JSON object mapping an account name to its credentials:

```bash
LOGGLY_ACCOUNTS={"acme":{"subdomain":"acme","token":"acme_token","authMode":"bearer"},"beta":{"subdomain":"beta","token":"beta_token"}}
```

When `LOGGLY_ACCOUNTS` is set, it replaces `LOGGLY_SUBDOMAIN`/`LOGGLY_TOKEN`/`LOGGLY_AUTH_MODE`.
Every tool then accepts an optional `account` argument (e.g. `account: "acme"`) to pick which
account's credentials to use for that call.

- If `account` is omitted, the server uses `LOGGLY_DEFAULT_ACCOUNT` if set, otherwise `"default"`,
  otherwise the single configured account if there's only one.
- An unknown `account` value returns an error listing the configured account names.
- `iterate_events_next` can also infer the account from the `next_url` host when `account` is
  omitted, as long as exactly one configured account matches that host.

Existing single-account setups (just `LOGGLY_SUBDOMAIN`/`LOGGLY_TOKEN`) keep working unchanged —
they're treated as one account named `"default"`.

---

# Aggregation-First Traffic Tools

Raw event dumps are slow and expensive to reason about. These tools return a summary — totals,
top-N breakdowns, a bucketed timeline, and a small representative sample — instead:

- `search_logs` — the general-purpose version: query + time range in, aggregated summary out.
- `traffic_by_ip` / `traffic_by_host` / `traffic_by_path` — same aggregation, pre-scoped to one
  IP/hostname/path.
- `group_by_ip` / `group_by_path` / `group_by_user_agent` — facet counts only (thin wrappers
  over `field_facets`), for when you just need a breakdown, not the full aggregate.
- `timeline` — bucketed counts over a range, computed client-side via repeated
  `/apiv2/events/count` calls (Loggly's `volume-metrics` endpoint doesn't accept a free-text
  query, so this is the only way to get a timeline for an arbitrary search).
- `sample_events` — a handful of representative raw events, when you need examples rather than
  the complete result set.

Field naming depends on how each Loggly source parses its logs, and can differ between accounts
and even between tags within one account — so these tools resolve field names **discovery-first**:
for any role not explicitly overridden (`host_field`/`path_field`/`status_field`/`user_agent_field`/
`ip_field` arguments, or the `LOGGLY_FIELD_HOST`/`_PATH`/`_STATUS`/`_USER_AGENT`/`_IP` env vars),
they check `/apiv2/fields/` for the actual query and match candidates against known role patterns:

- Exactly one match → used automatically, reported under `discovered_fields` in the result.
- Multiple plausible matches (e.g. a source with both `ClientIp` and `CustIP`) → never guessed
  between — reported under `ambiguous_fields` instead, falling back to the configured default.
  Pass the correct one explicitly via the matching `*_field` argument.
- No match → falls back to the configured default (`host`, `path`, `status`, `user_agent`, `ip`).

Run `list_fields` yourself if you want to see every candidate before deciding on an override.

---

# IP Intelligence

- `rdap_lookup` — IP ownership/network registration (RIR, netblock, org, country) via public
  RDAP (`rdap.org`). No API key required.
- `ip_reputation` — GreyNoise (internet-wide scanning noise) + AbuseIPDB (community abuse
  reports) for an IP. Requires `GREYNOISE_API_KEY` / `ABUSEIPDB_API_KEY`; either one missing
  just comes back as `available: false` for that source, not an error.
- `get_ip_context` — combines all of the above with Loggly traffic (1h/24h/30d counts,
  first/last seen, hosts, top paths) checked across **every configured Loggly account** unless
  `account` is given, and flags `cross_domain_correlation` when the IP shows activity in more
  than one account. Per the `bot-traffic-triage` playbook, that cross-domain pattern is the
  single strongest signal for distinguishing targeted reconnaissance from background noise.

Treat all IP-intel output as one input among several — identity/reputation data (who owns an
IP, third-party scanner reports) should carry less weight than behavioral evidence from your own
logs. See the `bot-traffic-triage` skill for the full investigation methodology.

---

# Logging

Logs are written to **stderr** to avoid interfering with MCP stdio traffic.  
Use `LOGGLY_LOG_LEVEL` to control verbosity. Default is `info`.

---

# Timeouts, Retries & Concurrency

Requests enforce a per-call timeout of `LOGGLY_REQUEST_TIMEOUT_MS` (default `15000`).  
Transient failures (`429`, `500` with timeout-like body, `503`, `504`, or network timeouts) are retried up to `LOGGLY_MAX_RETRIES` times, honoring a `Retry-After` header on `429` when Loggly sends one, falling back to exponential backoff otherwise.

The aggregation tools (`search_logs`, `traffic_by_*`, `get_ip_context`, etc.) fan out several requests per call via `Promise.all` (facets + timeline buckets + a sample). `LOGGLY_MAX_CONCURRENT_REQUESTS` (default `4`) caps how many of those run at once **per account**, so that fan-out doesn't trip Loggly's own rate limit by itself. If you still see `429`s from a single aggregation call, lower this; if Loggly's limit is more generous, raise it.

---

# Tool Manifest

Tool metadata is stored in `tool-manifest.json` and verified against `src/server.js`.

```bash
npm run verify:manifest
```

---

# Smoke Test

Smoke test runs without Loggly credentials by setting `LOGGLY_SMOKE_TEST=1`.

```bash
npm run smoke
```

---

# Implemented MCP Tools

Low-level Loggly API wrappers:
- `connection_test`
- `create_search`
- `get_events`
- `search_and_get_events`
- `iterate_events_page`
- `iterate_events_next`
- `count_events`
- `volume_metrics`
- `stats_query`
- `list_fields`
- `field_facets`
- `raw_api_call`

Aggregation-first traffic tools:
- `search_logs`
- `traffic_by_ip`
- `traffic_by_host`
- `traffic_by_path`
- `group_by_ip`
- `group_by_path`
- `group_by_user_agent`
- `timeline`
- `sample_events`

IP intelligence:
- `rdap_lookup`
- `ip_reputation`
- `get_ip_context`

---

# Examples

Example tool argument payloads are in `examples/`.

---

# Development

```bash
npm test
```

`npm test` runs manifest verification and the smoke test. CI runs the same checks in `.github/workflows/ci.yml`.

---

# Versioning

- `VERSION` contains the current release version.
- `CHANGELOG.md` tracks changes by release.

---

# Security Notes

- `.env` files must never be committed.
- Tokens and API keys (`LOGGLY_TOKEN`, `LOGGLY_ACCOUNTS`, `GREYNOISE_API_KEY`,
  `ABUSEIPDB_API_KEY`, `MCP_BEARER_TOKEN`) are treated as secrets.
- This server enforces **read-only** access to Loggly `/apiv2/*` endpoints. IP-intel calls
  (RDAP/GreyNoise/AbuseIPDB) are read-only GET requests to those third-party services; no
  Loggly credentials are ever sent to them, and no IP-intel keys are sent to Loggly.
