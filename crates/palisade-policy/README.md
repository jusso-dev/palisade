# palisade-policy

The policy model, conditions, precedence and evaluation, with a decision trace. Evaluation is pure and deterministic: no network or filesystem access.

**Status:** the policy object model, its JSON Schema and validation are in place (#30), with a YAML front end (#190). Single criteria can be matched against an object's facts (#31, #32), and whole match trees can be evaluated, with context criteria for the user, device and session (#33). Rule actions, effect flags and the typed `Decision` are defined (#34). The evaluation pipeline and the five precedence models turn the matching rules into one decision (#35). Modes, the decision trace and indexing are still to come. Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Modules

- `model`: the canonical policy object model. A `PolicyDocument` holds one `Policy` and the `RuleSet`s it references by ID. Each rule has a match tree (`all` / `any` / `not` / `criterion`) and an action. Strict serde: unknown fields are rejected, and enums are `snake_case` strings.
- `schema`: generates the JSON Schema (draft 2020-12) from the model. The generated schema is committed at [`schemas/policy/v1.json`](../../schemas/policy/v1.json).
- `dsl`: reads and writes policy documents as YAML. The YAML form has the same fields as the JSON form, and the same JSON Schema validates both. Reading is strict and safe on untrusted input: YAML 1.2 only, no anchors, aliases, tags or merge keys, no duplicate keys or unknown fields, no scalar that YAML 1.1 and 1.2 type differently (such as `no` or `010`), and limits on size, depth, node count and parser lookahead. JSON input is read by a streaming JSON reader that builds the same tree under the same rules. Errors and warnings carry a line and column. Examples are in [`docs/examples/policies/`](../../docs/examples/policies/).
- `validate`: `PolicyDocument::validate` reports every finding in one pass. Each finding has a stable code, a severity and the JSON Pointer of the field. It normalises hash values to lowercase hex, compiles every criterion, checks each rule's `order` and `priority` against the precedence model, and flags rules that can match without a positive identity criterion (naming the criteria on one such path through the tree), rules that match on negations or context alone, allow rules whose only identity is weak, and unsupported regular expressions. A document that passes becomes a `ValidatedPolicy`.
- `decision`: the typed `Decision` every consumer gets: outcome, the enforce-mode outcome (`would_have_been`), the deciding action and rule (`RuleRef`), `audit` annotations, the mode, directives, effects with defaults applied, a reason code and a trace ID. Its JSON form is stable and snapshot-tested. `Decision::from_rule` builds the enforce-mode decision of one deciding rule, and `Decision::implicit_deny` the decision when none decides. The pipeline adds the rules the deciding rule overrode, the `audit` annotations and the trust-source grants (#35); applying non-enforcing modes is #36.
- `evaluate`: the evaluation pipeline (#35). An `Evaluator` compiles a validated policy once, and `Evaluator::evaluate` decides one object in fixed stages: the mandatory deny tier, exclusions (`ignore`), the policy's precedence model, then the implicit deny. See [Precedence](#precedence).
- `precedence`: the five precedence models, each a pure function from the matching rules to one winner (`Precedence::resolve`), and the specificity tiers that `specificity` ranks by.
- `facts`: the facts about one object that criteria test (`ObjectFacts`): hashes, version-resource strings, the normalised path with its ACL safety, and the signatures with their verification status. Path variables (`%PROGRAMFILES%` and so on) are supplied per evaluation. Facts are computed elsewhere (#3, #4); this crate only reads them.
- `context`: the user, device and session of one evaluation (`EvaluationContext`), which context criteria test: SIDs, group and tag sets, account names, host and domain names, the OS version, yes-or-no facts such as `user.is_admin`, and the session type. As with object facts, the agent collects them (#4); a fact that was not collected is unknown.
- `condition`: compiles a rule's match tree (`CompiledMatch`) into an arena of compiled criteria and evaluates it with Kleene three-valued logic. `all` stops at the first `NoMatch` and `any` at the first `Match`, and the order of children never changes the result. Only `Match` makes a rule match, and `Unknown` counts as no match for every action. An allow rule therefore cannot allow on an unknown fact (it fails closed), but a deny rule does not block on one either. That is the default (`no_match`) that #32 sets for deny rules; a deny's `unknown_as` and `on_unparseable` options change it (see [Unknown facts](#unknown-facts)).
- `ops`: compiles one criterion (`CompiledCriterion`) and evaluates it against facts, giving `Match`, `NoMatch` or `Unknown` with notes for the decision trace. The module docs define the semantics: several values, negation of unknown facts, case folding and Unicode NFC, path normalisation and wildcards, alternate data streams, path variables, the path-ACL rule for allow rules, version comparison, and which signer statuses can match. Regular expressions use a linear-time engine; look-around and backreferences are rejected with a guided error.

Each identity field has a strength (`Field::strength`, #31): strong for SHA-256-family and Authenticode SHA-256 hashes and the leaf thumbprint, medium for the publisher and full or directory paths, and weak for everything else. Path normalisation (`palisade_core::path`) is shared with the agent, so facts and rule values are normalised the same way.

## Actions and effects

An action is an object with a `type` and that action's options (#34). Each action is valid only in some rule set kinds and for some object types; validation reports a rule that breaks this table.

| Action | Options | Decides? | Rule set kinds | Object types |
|---|---|---|---|---|
| `allow` | none | yes: allowed | allowlist, baseline, mixed | all |
| `deny` | `kill_running`, `allow_request`, `request_template`, `unknown_as`, `on_unparseable` | yes: blocked | blocklist, mixed | all; `kill_running` not for driver or library |
| `audit` | none | no: an annotation | all | all |
| `allow_contained` | `profile_id` (#14) | yes: allowed | allowlist, containment, mixed | not driver or library |
| `allow_elevated` | `token_profile`, `condition` (`always`, `if_required`), `reason_prompt`, `auth` (`none`, `reauth`, `mfa`) (#12) | yes: allowed | elevation, mixed | executable, installer, script, control panel applet |
| `trust_source` | `mode` (`direct`, `chained`), `scope_paths`, `tag_output` (#9, #114) | no: adds a directive | trust, mixed | executable, installer |
| `ignore` | none | yes: ignored, nothing logged | mixed | not executable or driver |
| `defer` | none | no: no opinion | all | all |

An empty `object_types` list means every type, so a restricted action must list its types. `ignore` is for performance exclusions only: validation always warns (`exclusion_needs_permission`), and the server only accepts it from an administrator with the `admin.exclusions` permission (#10). Whether a path is user-writable is only known when a rule is evaluated (#54), so `ignore` never applies to executables or drivers. Every action that lets an object run, trusts it or excludes it needs a positive identity on every branch of its match tree, and only trusts a path users cannot write, as `allow` does. The engine passes the containment, elevation and trust-source directives through; their meaning belongs to the epics named.

Every rule may have an `effects` block. Each flag is optional; an unset flag takes the action's default:

| Action | `log` | `upload` | `notify` | `severity` | `suppress_duplicates_secs` |
|---|---|---|---|---|---|
| `allow`, `allow_contained` | `summary` | `batched` | `none` | `info` | 86400 |
| `allow_elevated` | `always` | `immediate` | `none` | `info` | 600 |
| `deny` | `always` | `immediate` | `default` | `medium` | 600 |
| `audit` | `always` | `immediate` | `none` | `low` | 600 |
| `trust_source` | `always` | `batched` | `none` | `info` | 600 |

The de-duplication default follows the effective `log`: 86400 for `summary`, 0 for `never`, and 600 otherwise. `deny`, `audit`, `allow_elevated` and `trust_source` need an event per decision, so `log: never` and `log: summary` are errors on them. `notify: custom` needs a `notification_text` of at most 2048 characters with the placeholders `{file}`, `{publisher}`, `{rule}`, `{user}` and `{hash}` (`{{` and `}}` are literal braces). `help_url` must be an `https` URL whose host is a DNS name or a bracketed IPv6 address, with an optional port from 1 to 65535, no user information, and none of the characters RFC 3986 never allows (including `\`, which browsers read as `/`). A `reason_prompt` is one trimmed line of at most 256 characters. A `trust_source` scope path is a drive, UNC or known path variable (`%PROGRAMFILES%` and the others in `facts::PathVariable`) path; `%` is not allowed elsewhere in it, and paths must be unique when compared as the engine compares paths (without case or a trailing `\`). `tags` follow the metadata tag rules. `ignore` and `defer` make no decision, so they take no `effects`. A deny with `allow_request` needs a notification, cannot be mandatory, and may name a `request_template`. See [`docs/examples/policies/actions-and-effects.yaml`](../../docs/examples/policies/actions-and-effects.yaml).

## Precedence

A file often matches several rules. `Evaluator::evaluate` decides it in fixed stages, whatever the model (#35, ADR 0004):

1. **Mandatory deny.** A matching rule of a `mandatory` blocklist blocks (`mandatory_deny`). No allow, elevation, trust source or exclusion changes that, under any model.
2. **Exclusion.** A matching `ignore` rule makes the object `ignored`.
3. **Policy.** The policy's `precedence_model` chooses among the matching `allow`, `allow_contained`, `allow_elevated` and `deny` rules.
4. **Unknown.** If nothing decided, the implicit deny (`implicit_deny_unknown`, #39).

Override sessions (#9, #36) and post-allow attribute rules (#33) are the stages still to come between them. The result is the enforce-mode decision: the policy's `mode`, a rule's `enforcement_override` and the per-class control levels are applied on top of it by #36. `audit` rules never decide: every one that matches is an annotation. `trust_source` rules never let an object run: their grants are attached only to an allowed object. `defer` rules have no opinion. When several mandatory denies or exclusions match, the most specific decides.

The decision names the deciding rule (`matched_rule`) and **every rule it overrode** (`overridden`): the other candidates of the deciding stage, every candidate of the later stages, and the trust sources of an object that is not allowed.

| Model | Decides | Options |
|---|---|---|
| `deny_wins` (default) | any matching deny, otherwise an allow | `allow_tiebreak` |
| `allow_wins` | any matching allow, otherwise a deny. Validation warns: not recommended for Essential Eight. | `allow_tiebreak`, `granularity_tiebreak` |
| `specificity` | the most specific rule; between equally specific rules, a deny | `allow_tiebreak`, `same_tier_tiebreak` |
| `first_match` | the lowest `order`; ties go to the newer rule | `curated_first` |
| `priority` | the lowest `priority`; ties go to deny, `allow_contained`, `allow`, `allow_elevated` (`always`, then `if_required`) | `priority_direction` |

Options live in `policy.precedence_options`; one the model does not use is a warning (`precedence_option_unused`).

- `allow_tiebreak`: when several allows could decide, `most_restrictive` (the default) prefers `allow_contained`, then `allow`, then `allow_elevated`; `most_permissive` reverses that.
- `granularity_tiebreak` (`allow_wins`): within one rule set, only the most specific matching rules take part, so a denied file in an allowed folder stays denied.
- `same_tier_tiebreak` (`specificity`): `deny` (the default) or `allow`.
- `curated_first` (`first_match`, on by default): rules of read-only rule sets come before every custom rule.
- `priority_direction` (`priority`): `lower_wins` (the default) or `higher_wins`.

**Specificity tiers**, from a rule's strongest identity that every match must satisfy (`all` takes its strongest child, `any` its weakest, `not` and context criteria identify nothing): 1 hash, 2 signer with file name and version, 3 signer with product name, 4 signer (publisher or certificate thumbprint), 5 full path (`path.full` equals), 6 directory (deeper first), 7 metadata, certificate issuer, or nothing.

**Order and priority.** Under `first_match`, every rule that allows or denies needs an `order` (`order_required`). Rules of custom rule sets use 100001 to 999989 (`order_reserved`). 0 to 99 is for system rules, 100 to 100000 for curated rule sets, and 999990 to 1000000 for defaults and catch-alls. Under `priority`, every such rule needs a `priority` (`priority_required`). Two rules with different actions at one priority are a warning (`duplicate_priority`). A newer rule is one with a higher rule ID, because rule IDs are UUIDv7s, which start with their creation time.

**Determinism.** Every choice ends with the unique rule ID, and the lists in a decision are sorted by rule ID. So a decision never depends on the order of rule sets or rules in a document, under any model. Only `first_match` and `priority` depend on `order` and `priority`, by design.

### Unknown facts

A rule applies only when its tree is `Match`, so an unknown fact never allows, trusts or excludes. A deny chooses how it treats what it cannot decide:

- `unknown_as: match` makes the deny apply when its tree is `Unknown`, so it blocks unless the model prefers an allow. The default, `no_match`, means an unknown fact does not block.
- `on_unparseable: match` makes each criterion whose version fact is not a version count towards the deny applying (as `Match`, or `NoMatch` under an odd number of `not` nodes). The rest of the tree must still match. The default leaves the criterion `Unknown`.

Mandatory denies use the same options and defaults. Making the shipped blocklists fail closed by default (`safety_critical`) belongs to #32 and #87.

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
- Actions: unit tests of the reader (options are checked as they are read, and an option of another action is an error at its key), the full validity matrix written out as a table, and each validation code. `Decision` JSON is compared with committed snapshots in `tests/snapshots/decision/`; after a deliberate change, regenerate them with `PALISADE_BLESS=1 cargo test -p palisade-policy decision::`.
- Benchmarks: `benches/criterion_eval.rs` (criterion) measures matching one compiled criterion against facts, for each kind of operator: `cargo bench -p palisade-policy`.
- Precedence: unit tests pin each model's choice, and property tests check that every model's winner does not depend on the order of the matching rules, that under `deny_wins` a deny always beats an allow, and, over random valid policies, that a matching mandatory deny always blocks and that shuffling rule sets and rules never changes a decision. `tests/precedence/*.yaml` is a conformance suite: each file gives rule sets, an object and the expected decision (outcome, deciding rule, overridden rules, annotations and grants) under all five models.
- Fixtures in `tests/fixtures/`: `valid/` documents pass the schema and validation; `invalid/` documents pass the schema but fail validation with the codes and paths in their `.expected` files; `malformed/` documents are rejected by the schema at the paths in their `.expected` files.

## Allowed dependencies

`palisade-core`, `palisade-fileid`. Must never depend on an async runtime, an HTTP client or Windows API bindings. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms. This crate uses `std`. Only `palisade-core` has to build without it.

## Dependencies

- `regex-automata` and `regex-syntax`: the engine and parser behind the `regex` crate, for linear-time regular expressions with RE2 semantics, also used to compile wildcards (#32). Patterns are parsed once and built from the parse tree with only the linear-time engines enabled. `regex-syntax` also recognises look-around and backreferences, so the error can explain the alternative. Both are already in the lock file through `boon`.
- `unicode-normalization`: NFC normalisation before strings are compared (#32).
- Dev-dependencies: `boon` checks documents against the JSON Schema, `proptest` drives the property tests, and `criterion` runs the benchmarks.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change, until the first schema version is published.
