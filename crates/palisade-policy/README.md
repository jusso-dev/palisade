# palisade-policy

The policy model, conditions, precedence and evaluation, with a decision trace. Evaluation is pure and deterministic: no network or filesystem access.

**Status:** the policy object model, its JSON Schema and validation are in place (#30). Matching, precedence and evaluation are still to come. Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Modules

- `model`: the canonical policy object model. A `PolicyDocument` holds one `Policy` and the `RuleSet`s it references by ID. Each rule has a match tree (`all` / `any` / `not` / `criterion`) and an action. Strict serde: unknown fields are rejected, and enums are `snake_case` strings.
- `schema`: generates the JSON Schema (draft 2020-12) from the model. The generated schema is committed at [`schemas/policy/v1.json`](../../schemas/policy/v1.json).
- `validate`: `PolicyDocument::validate` reports every finding in one pass. Each finding has a stable code, a severity and the JSON Pointer of the field. A document that passes becomes a `ValidatedPolicy`.

## Schema versioning

Documents carry `schema_version` (semver). A reader accepts the same major version and any minor version. A minor version adds optional fields; a major version is a breaking change and gets a new schema file. `PolicyDocument::from_json` checks the version before reading the rest of the document.

The test `committed_schema_is_current` fails when the committed schema is stale. After changing the model, regenerate the schema:

```sh
PALISADE_BLESS=1 cargo test -p palisade-policy --test schema
```

## Tests

- Unit tests per type for defaults, limits and every validation code.
- Property tests over random valid documents (`model::arbitrary`): they validate, they match the JSON Schema, and they round-trip through JSON losslessly (10,000 cases; set `PROPTEST_CASES` to change).
- Fixtures in `tests/fixtures/`: `valid/` documents pass the schema and validation; `invalid/` documents pass the schema but fail validation with the codes and paths in their `.expected` files; `malformed/` documents are rejected by the schema at the paths in their `.expected` files.

## Allowed dependencies

`palisade-core`, `palisade-fileid`. Must never depend on an async runtime, an HTTP client or Windows API bindings. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms. This crate uses `std`. Only `palisade-core` has to build without it.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change, until the first schema version is published.
