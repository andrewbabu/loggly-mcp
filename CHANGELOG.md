# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2026-09-30

- Added discovery-first field resolution: `search_logs`, `traffic_by_ip`/`host`/`path`,
  `group_by_ip`/`path`/`user_agent`, and `get_ip_context` now look at the fields actually parsed
  for a query (`/apiv2/fields/`) and match them against known role patterns (ip/host/path/
  status/user-agent) instead of only trusting the static `LOGGLY_FIELD_*` defaults. A single
  unambiguous match is used automatically and reported under `discovered_fields`; multiple
  plausible matches are never guessed between — they're reported under `ambiguous_fields` and
  the call falls back to the configured default. Different accounts (and different tags within
  one account) can parse logs into completely different field names, so this resolves per
  account/query rather than once globally.
- `get_ip_context` now resolves fields independently per account it queries, instead of once
  before the per-account loop — needed since different accounts don't share a schema.

## [1.2.1] - 2026-09-29

- Fixed 429 (`API rate exceeded`) errors from `traffic_by_ip`/`traffic_by_host`/`traffic_by_path`/
  `search_logs`/`get_ip_context`: these fan out several Loggly requests per call via
  `Promise.all` with zero concurrency cap (up to ~18 simultaneous requests for a single
  `traffic_by_ip` call at the default `bucket_count`). Added a per-account concurrency
  semaphore (`LOGGLY_MAX_CONCURRENT_REQUESTS`, default 4) at the request-dispatch layer, so
  every current and future tool is capped automatically.
- Added `429` to the retryable status list, honoring a `Retry-After` response header when
  present instead of always falling back to the fixed exponential backoff.

## [1.2.0] - 2026-09-29

- Added aggregation-first traffic tools (`search_logs`, `traffic_by_ip`, `traffic_by_host`,
  `traffic_by_path`, `group_by_ip`, `group_by_path`, `group_by_user_agent`, `timeline`,
  `sample_events`) so callers get summarized totals/top-N/timeline/sample events instead of raw
  event dumps, matching the `bot-traffic-triage` skill's documented connector spec.
- Added IP intelligence tools: `rdap_lookup` (RDAP, no key required), `ip_reputation`
  (GreyNoise + AbuseIPDB, optional API keys), and `get_ip_context` (combines RDAP, threat intel,
  and Loggly traffic across every configured account into one profile, flagging cross-account
  correlation).
- Added `LOGGLY_FIELD_IP`/`LOGGLY_FIELD_HOST`/`LOGGLY_FIELD_PATH`/`LOGGLY_FIELD_STATUS`/
  `LOGGLY_FIELD_USER_AGENT` env vars (plus per-call `*_field` overrides) since parsed field
  names depend on how each Loggly source ingests logs.

## [1.1.0] - 2026-09-16

- Added multi-account support: `LOGGLY_ACCOUNTS` env var configures multiple named accounts, each tool now accepts an optional `account` argument to target one, and `LOGGLY_DEFAULT_ACCOUNT` sets the fallback. Single-account `.env` setups keep working unchanged.

## [1.0.0] - 2026-03-18

- Added tool manifest file with verification script and CI enforcement.
- Added smoke test script and CI wiring.
- Documented logging and timeout defaults, plus examples and configuration details.
- Updated package metadata, .codex config defaults, and .gitignore.
