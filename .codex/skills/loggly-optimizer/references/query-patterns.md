# Query Patterns

Use this file only when the default workflow is not enough.

## Progressive Narrowing Pattern

1. Start with one primary anchor only:
- `"${primary_anchor}"`
2. Add one high-signal phrase:
- `"${primary_anchor}" AND "${signal_phrase}"`
3. Add one scope constraint:
- `"${primary_anchor}" AND "${signal_phrase}" AND ${scope_constraint}`
4. Add secondary qualifiers only if needed:
- `"${primary_anchor}" AND "${signal_phrase}" AND ${scope_constraint} AND "${secondary_qualifier}"`
5. Add time split:
- Keep the same query, reduce window to likely incident period, or prompted window.

After each step, run `count_events`. Continue only if the count is still too high.

## Count-Then-Pull Heuristic

1. If count <= 50: pull events directly with small page size.
2. If count is 51-1000: run facets first, then pull events.
3. If count > 1000: do not pull raw events yet; apply additional filters first.

## Suggested Event Columns

Use only fields required for diagnosis. Prefer:
- `timestamp`
- `logmsg`
- `host`
- `appName`
- `thread`
- `class`
- `method`

Avoid retrieving unused payload fields.

## Evidence Compression Pattern

1. Normalize each message by removing volatile tokens (IDs, hashes, byte counts, thread numbers).
2. Group normalized messages into patterns.
3. Report:
- pattern text
- count
- first seen timestamp
- last seen timestamp
- one representative raw line

## Stop Conditions

Stop and return findings when one of these is true:

1. A consistent repeated pattern explains the symptom.
2. A specific period and actor/source can be identified with confidence.
3. Additional pages add duplicate evidence without changing conclusions.

## Escalation Triggers

Escalate to deeper retrieval only if:

1. There are conflicting patterns.
2. Root cause depends on ordering across many events.
3. User explicitly asks for full raw evidence.
