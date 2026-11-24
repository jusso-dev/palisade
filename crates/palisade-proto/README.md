# palisade-proto

Wire types between agent and server: messages, the event schema and schema versioning.

**Status:** the canonical event schema and the OS event-ID mappings are in place (part of [#196](https://github.com/jusso-dev/palisade/issues/196)). The agent-server service definitions are still to come ([#62](https://github.com/jusso-dev/palisade/issues/62)). Overall work is tracked in [#4](https://github.com/jusso-dev/palisade/issues/4) and [#10](https://github.com/jusso-dev/palisade/issues/10).

## Modules

- `events`: the canonical `Event`. It has a common envelope (`schema_version`, `event_id`, `event_type`, `category`, `action`, `outcome`, `severity`, `mode`, `description`, `ts`, clock state, `tenant_id`, `host`, `user`, `policy`, `seq`, `prev_hash`, `labels`, `source`) plus field sets for `process` (with `parent` and a `grandparent` summary), `file`, `script`, `native` (OS-native enforcement details) and `agent`. Every value type has one accepted form: lowercase hex digests of a fixed length, canonical GUIDs and SIDs, and RFC 3339 UTC timestamps with exactly six fractional digits. Strings and lists are bounded. Unknown fields are rejected. `Event::validate` checks the rules that types cannot express. `Event::ism_0585_gaps` lists any ISM-0585 fields that are missing. `Severity::syslog` maps severity 0 to 10 onto the syslog levels.
- `events::schema`: generates the JSON Schema (draft 2020-12), including the cross-field rules. It is committed at [`schemas/events/v1.json`](../../schemas/events/v1.json).
- `mapping`: translates decoded OS log records into canonical events. The mapping tables are data, in [`mappings/`](mappings/). One file covers the OS code integrity log and one the OS legacy rule-collection logs. Loading a file checks that every target is a real, writable canonical field, and that each entry can fill its type's required field sets and the ISM-0585 fields. Envelope fields owned by the agent (`seq`, `prev_hash`, `event_id`, `tenant_id`, `host`, the clock fields) cannot be mapped, so a log record can never set them.

## Event types

Event types are defined in [`events/registry.yaml`](events/registry.yaml). Each type has a category, a default severity, its required field sets and whether its allowed events may be summarised. The Rust enum (`src/events/registry_gen.rs`) and the reference table [`events/REGISTRY.md`](events/REGISTRY.md) are generated from it. A test fails if either is stale.

## Schema versioning

Each event carries `schema_version` (semver). A patch release changes documentation only.

**Minor version** changes are additive. They may add:
- optional fields and field sets
- event types
- enum values
- mapping entries

**Major version** changes break compatibility. They include renames, removals and type changes, as well as changes to an existing type's category or required field sets. A major version gets a new schema file.

Readers are strict, because events are hash-chained and silently dropping a field would hide data. A reader accepts events with its own major version and the same or an older minor version. It refuses events from a newer minor version (`LoadError::NewerMinorVersion`). Upgrade the server before the agents. The full rules are in the `events` module docs.

## Regenerating committed files

After changing the event types or the registry:

```sh
PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry        # registry_gen.rs, REGISTRY.md
PALISADE_BLESS=1 cargo test -p palisade-proto --test events_schema  # schemas/events/v1.json
PALISADE_BLESS=1 cargo test -p palisade-proto --test mappings       # golden mapping output
```

Review the diff after each run. A bless writes whatever the code produces.

## Tests

- Unit tests for every value type's accepted and rejected forms, for the envelope rules and for every mapping-file lint.
- Property tests (2,000 cases; set `PROPTEST_CASES` to change). Random valid events validate, round-trip through JSON losslessly in canonical form, and pass the committed JSON Schema under an independent 2020-12 validator.
- `tests/events_schema.rs`: the committed schema is current, and the schema and `Event::validate` reject the same broken events.
- `tests/mappings.rs`: golden tests over synthetic, anonymised source records in `tests/fixtures/mappings/`. Every mapped source event ID has a fixture. Every result passes the JSON Schema. Every decision passes the ISM-0585 checklist. A separate test covers the #196 acceptance cases: an enforced code-integrity block maps to `exec.decision`, and a rule-collection script block maps to `script.decision`. Both carry the file name, hashes, signer, user, host and time.

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`. The rules are enforced by `cargo xtask check-deps`. The crate uses `palisade-policy`'s strict YAML reader for the registry and the mapping files.

## Platform support

All platforms.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change until the first event schema version is published.
