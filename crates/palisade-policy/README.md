# palisade-policy

The policy model, conditions, precedence and evaluation, with a decision trace. Evaluation is pure and deterministic: no network or filesystem access.

**Status:** the policy object model, its JSON Schema and validation are in place (#30), with a YAML front end (#190). Single criteria can be matched against an object's facts (#31, #32). Evaluating whole match trees, precedence and the decision trace are still to come. Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Modules

- `model`: the canonical policy object model. A `PolicyDocument` holds one `Policy` and the `RuleSet`s it references by ID. Each rule has a match tree (`all` / `any` / `not` / `criterion`) and an action. Strict serde: unknown fields are rejected, and enums are `snake_case` strings.
- `schema`: generates the JSON Schema (draft 2020-12) from the model. The generated schema is committed at [`schemas/policy/v1.json`](../../schemas/policy/v1.json).
- `dsl`: reads and writes policy documents as YAML. The YAML form has the same fields as the JSON form, and the same JSON Schema validates both. Reading is strict and safe on untrusted input: YAML 1.2 only, no anchors, aliases, tags or merge keys, no duplicate keys or unknown fields, no scalar that YAML 1.1 and 1.2 type differently (such as `no` or `010`), and limits on size, depth, node count and parser lookahead. JSON input is read by a streaming JSON reader that builds the same tree under the same rules. Errors and warnings carry a line and column. Examples are in [`docs/examples/policies/`](../../docs/examples/policies/).
- `validate`: `PolicyDocument::validate` reports every finding in one pass. Each finding has a stable code, a severity and the JSON Pointer of the field. It normalises hash values to lowercase hex, compiles every criterion, and flags rules that match on negations alone, allow rules whose only identity is weak, and unsupported regular expressions. A document that passes becomes a `ValidatedPolicy`.
- `facts`: the facts about one object that criteria test (`ObjectFacts`): hashes, version-resource strings, the normalised path with its ACL safety, and the signatures with their verification status. Path variables (`%PROGRAMFILES%` and so on) are supplied per evaluation. Facts are computed elsewhere (#3, #4); this crate only reads them.
- `ops`: compiles one criterion (`CompiledCriterion`) and evaluates it against facts, giving `Match`, `NoMatch` or `Unknown` with notes for the decision trace. The module docs define the semantics: several values, negation of unknown facts, case folding and Unicode NFC, path normalisation and wildcards, alternate data streams, path variables, the path-ACL rule for allow rules, version comparison, and which signer statuses can match. Regular expressions use a linear-time engine; look-around and backreferences are rejected with a guided error.

Each identity field has a strength (`Field::strength`, #31): strong for SHA-256-family and Authenticode SHA-256 hashes and the leaf thumbprint, medium for the publisher and full or directory paths, and weak for everything else. Path normalisation (`palisade_core::path`) is shared with the agent, so facts and rule values are normalised the same way.

## Schema versioning

Documents carry `schema_version` (semver). A reader accepts the same major version and any minor version. A minor version adds optional fields; a major version is a breaking change and gets a new schema file. `PolicyDocument::from_json` checks the version before reading the rest of the document.

The test `committed_schema_is_current` fails when the committed schema is stale. After changing the model, regenerate the schema:

```sh
PALISADE_BLESS=1 cargo test -p palisade-policy --test schema
```

## Editor support

Policy files can name the schema in their first line, as the examples and `dsl::to_string` do:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/jusso-dev/palisade/main/schemas/policy/v1.json
```

An editor that uses the YAML language server then completes field names and enum values and shows each field's description. To check it by hand: open `docs/examples/policies/minimal.yaml` in such an editor, start a new line under `policy:` and request completions (the list includes `precedence_model` and `settings`), then change `mode: audit` to `mode: strict` (it is underlined as not one of the allowed values). To use a local copy of the schema instead, change the URL to a relative path, for example `$schema=../../../schemas/policy/v1.json`.

## Tests

- Unit tests per type for defaults, limits and every validation code.
- Property tests over random valid documents (`model::arbitrary`): they validate, they match the JSON Schema, and they round-trip through JSON losslessly (10,000 cases; set `PROPTEST_CASES` to change).
- YAML: property tests that random valid documents round-trip through YAML losslessly and byte-for-byte, and read the same as JSON (10,000 cases); unit tests for every strictness rule; and `tests/yaml.rs`, which checks the examples against the committed schema, reads every JSON fixture as YAML, and checks the codes, pointers and line:column of the fixtures in `tests/fixtures/yaml/`.
- Fixtures in `tests/fixtures/`: `valid/` documents pass the schema and validation; `invalid/` documents pass the schema but fail validation with the codes and paths in their `.expected` files; `malformed/` documents are rejected by the schema at the paths in their `.expected` files.

## Allowed dependencies

`palisade-core`, `palisade-fileid`. Must never depend on an async runtime, an HTTP client or Windows API bindings. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms. This crate uses `std`. Only `palisade-core` has to build without it.

## Dependencies

- `regex-automata` and `regex-syntax`: the engine and parser behind the `regex` crate, for linear-time regular expressions with RE2 semantics, also used to compile wildcards (#32). Patterns are parsed once and built from the parse tree with only the linear-time engines enabled. `regex-syntax` also recognises look-around and backreferences, so the error can explain the alternative. Both are already in the lock file through `boon`.
- `unicode-normalization`: NFC normalisation before strings are compared (#32).

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change, until the first schema version is published.
