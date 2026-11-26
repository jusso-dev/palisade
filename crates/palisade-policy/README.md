# palisade-policy

The policy model, conditions, precedence and evaluation, with a decision trace. Evaluation is pure and deterministic: no network or filesystem access.

**Status:** the policy object model, its JSON Schema and validation are in place (#30), with a YAML front end (#190). Single criteria can be matched against an object's facts (#31, #32), and whole match trees can be evaluated, with context criteria for the user, device and session (#33). Rule actions, effect flags and the typed `Decision` are defined (#34). The evaluation pipeline and the five precedence models turn the matching rules into one decision (#35). Enforcement modes, their resolution per decision and the mode state machine are in place (#36). The group hierarchy, inheritance, reusable libraries and the effective policy of a device are in place (#37). Rules, rule-set assignments and policies can be scoped by user, group, device, network location, session and time (#38). Every decision can be traced, explained and simulated (#41). Indexing is still to come (#42). Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Modules

- `model`: the canonical policy object model. A `PolicyDocument` holds one `Policy` and the `RuleSet`s it references by ID. Each rule has a match tree (`all` / `any` / `not` / `criterion`) and an action. Strict serde: unknown fields are rejected, and enums are `snake_case` strings.
- `schema`: generates the JSON Schema (draft 2020-12) from the model. The generated schema is committed at [`schemas/policy/v1.json`](../../schemas/policy/v1.json).
- `dsl`: reads and writes policy documents as YAML. The YAML form has the same fields as the JSON form, and the same JSON Schema validates both. Reading is strict and safe on untrusted input: YAML 1.2 only, no anchors, aliases, tags or merge keys, no duplicate keys or unknown fields, no scalar that YAML 1.1 and 1.2 type differently (such as `no` or `010`), and limits on size, depth, node count and parser lookahead. JSON input is read by a streaming JSON reader that builds the same tree under the same rules. Errors and warnings carry a line and column. Examples are in [`docs/examples/policies/`](../../docs/examples/policies/).
- `validate`: `PolicyDocument::validate` reports every finding in one pass. Each finding has a stable code, a severity and the JSON Pointer of the field. It normalises hash values to lowercase hex, compiles every criterion, checks each rule's `order` and `priority` against the precedence model, and flags rules that can match without a positive identity criterion (naming the criteria on one such path through the tree), rules that match on negations or context alone, allow rules whose only identity is weak, and unsupported regular expressions. A document that passes becomes a `ValidatedPolicy`.
- `decision`: the typed `Decision` every consumer gets: outcome, the enforce-mode outcome (`would_have_been`), the deciding action and rule (`RuleRef`), `audit` annotations, the mode, directives, effects with defaults applied, a reason code and a trace ID. Its JSON form is stable and snapshot-tested. `Decision::from_rule` builds the enforce-mode decision of one deciding rule, and `Decision::implicit_deny` the decision when none decides. The pipeline adds the rules the deciding rule overrode, the `audit` annotations and the trust-source grants (#35), then applies the effective mode (#36): `would_have_been` keeps the enforce-mode outcome, and `learning_candidate` marks an object to learn.
- `evaluate`: the evaluation pipeline (#35). An `Evaluator` compiles a validated policy once, and `Evaluator::evaluate` decides one object in fixed stages: the mandatory deny tier, exclusions (`ignore`), the policy's precedence model, then the implicit deny. See [Precedence](#precedence). `Evaluator::evaluate_in` then applies the device's modes; see [Modes](#modes).
- `mode`: enforcement modes (#36). `mode::resolve` gives the effective mode of one decision from the policy, the object type, the deciding rule and the device state (`DeviceState`: base mode, connectivity, override session, lockdown); `ProtectionStatus` reports a device's protection; `mode::machine` is the state machine of legal mode changes, with time boxes that revert on a monotonic and a wall clock.
- `library`: reusable libraries (#37): rule sets, application definitions, match fragments, and hash, publisher, path, principal, device, network and schedule sets, and message templates. A `ref` node in a match tree names one by ID and pin (`latest` or a version). `Catalogue` checks every library version, resolves references and rejects reference cycles, naming the path. `Catalogue::expand` replaces each reference with its tree. Libraries are global (read-only to tenants) or one tenant's, have an owner, and can be duplicated into an editable copy that records `derived_from`.
- `hierarchy`: the scope hierarchy (#37): global, tenant, nested groups (at most 8 deep), devices, dynamic groups and templates, with the built-in `unassigned`, `unmanaged` and `staging` groups. `HierarchyDocument::validate` checks a snapshot, and `ValidatedHierarchy::effective_policy` computes one device's effective policy: a pure function of the snapshot, the libraries at their resolved versions and the device's dynamic groups, with per-rule and per-setting provenance and a content hash. `place` runs the automatic placement rules. See [Hierarchy](#hierarchy).
- `trace`: the decision trace, explanations and the policy simulator (#41). See [Trace, explain and simulate](#trace-explain-and-simulate).
- `precedence`: the five precedence models, each a pure function from the matching rules to one winner (`Precedence::resolve`), and the specificity tiers that `specificity` ranks by.
- `facts`: the facts about one object that criteria test (`ObjectFacts`): hashes, version-resource strings, the normalised path with its ACL safety, and the signatures with their verification status. Path variables (`%PROGRAMFILES%` and so on) are supplied per evaluation. Facts are computed elsewhere (#3, #4); this crate only reads them.
- `context`: the user, device and session of one evaluation (`EvaluationContext`), which context criteria test: SIDs, group and tag sets, account names, host and domain names, the OS version, yes-or-no facts such as `user.is_admin`, and the session type. As with object facts, the agent collects them (#4); a fact that was not collected is unknown.
- `condition`: compiles a rule's match tree (`CompiledMatch`) into an arena of compiled criteria and evaluates it with Kleene three-valued logic. `all` stops at the first `NoMatch` and `any` at the first `Match`, and the order of children never changes the result. Only `Match` makes a rule match, and `Unknown` counts as no match for every action. An allow rule therefore cannot allow on an unknown fact (it fails closed), but a deny rule does not block on one either. That is the default (`no_match`) that #32 sets for deny rules; a deny's `unknown_as` and `on_unparseable` options change it (see [Unknown facts](#unknown-facts)).
- `scope`: rule scoping (#38): who, where and when a rule applies. See [Scopes](#scopes).
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

An override session (#9) lowers the mode of stages 3 and 4 (see [Modes](#modes)); post-allow attribute rules (#33) are the stage still to come between them. The result is the enforce-mode decision; `Evaluator::evaluate_in` applies the modes on top of it. `audit` rules never decide: every one that matches is an annotation. `trust_source` rules never let an object run: their grants are attached only to an allowed object. `defer` rules have no opinion. When several mandatory denies or exclusions match, the most specific decides.

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

## Modes

`policy.mode` sets how a policy's decisions take effect (#36):

| Mode | Decision |
|---|---|
| `disabled` | Only a device can be disabled (see the state machine below). The engine is not consulted: `evaluate_in` returns `None`, and not even a mandatory deny applies. |
| `monitor` | Evaluated fully. A would-block runs as `allowed_audit`, with `would_have_been: blocked`. |
| `audit` | As `monitor`; the agent sends a full event for every decision rather than would-blocks and summaries (#16). |
| `learning` | As `audit`. An object that only the implicit deny would block is a `learning_candidate` (#5). An object a deny rule would block is never one. |
| `enforce` | Blocked means blocked. |

A relaxed block keeps the deciding rule and its effects, so the would-block event is still logged, but notifies nobody and carries no `kill_running` or `request`. **A mandatory deny blocks in every mode and every override session** (#125: the blocklist always wins); only a disabled device skips it. A relaxed deny never lets through what an enforcing rule blocks: the matching rules are decided again without the denies that do not enforce, and if an enforcing deny or the implicit deny then blocks, the object is blocked. If an allow decides instead, the object runs with that allow's containment, elevation and grants. An override session is applied as a second layer, after the modes: only what the modes still block can become `allowed_override`, and the decision names the enforcing rule the session bypassed.

**Where modes are set**, resolved for each decision by `mode::resolve`:

1. **Lockdown** (`DeviceState::lockdown`, from the bundle) forces `enforce` over everything below, including a disabled device. Clearing it restores every prior mode.
2. **Device mode**: the policy's `mode`, or the mode the state machine moved the device to. `disabled` stops here.
3. **Mandatory deny**: always `enforce`.
4. **Disconnected**: `policy.mode_options.mode_disconnected`, if stricter, while the device has not checked in for `disconnected_after_secs` (default 3 check-in intervals). It must be at least as strict as `mode` (`mode_disconnected_weaker`).
5. **Object type**: `mode_options.mode_by_type` (for example `script.powershell: audit`). The control levels in `settings` then cap it: `audit` at `audit`, `off` at `monitor`.
6. **Rule set**: a non-mandatory blocklist's `mode_override` replaces it (`mode_override_not_allowed` elsewhere).
7. **Rule**: on a deny, `enforcement_override: always_enforce` makes it `enforce`; `never_enforce` caps it at `audit`. Other actions cannot set it (`enforcement_override_not_deny`).
8. **Override session** (#9): caps it at `audit` (`allowed_override`), except for an `always_enforce` rule unless the session is `full_bypass`.

`disabled` is rejected for a policy, an object type and a rule set (`mode_not_allowed`). Strictness ranks `enforce` above `learning` and `audit`, above `monitor`, above `disabled`.

**Protection status** (`ProtectionStatus::of`): `lockdown`, `disabled`, `override_active`, then `protected_enforce` if every Essential Eight object type is enforced, `protected_partial` if the device mode is `enforce` but some type is not, and otherwise `audit`, `learning` or `monitor`.

**State machine** (`mode::machine::ModeMachine`). Legal changes: `disabled` to any mode; `monitor` to `audit`, `learning`, `enforce` or `disabled`; `audit` to `learning`, `enforce`, `monitor` or `disabled`; `learning` to `audit`, `enforce` or `disabled`; `enforce` to any other mode, time-boxed. Leaving `enforce` for a weaker mode, and entering `disabled`, needs a reason, a ticket where the tenant requires one, and an expiry at most 30 days ahead; only `enforce` to `audit` may be permanent, with the elevated permission. A time box ends when the wall clock reaches the expiry **or** the monotonic clock has run for its length, so setting the clock back cannot extend it; the device then returns to the mode it left, offline too. Observing the end is final: `current` and `tick` both close the box and store the rollback target, so a later read with the clock set back never brings the weaker mode back, and the read that observes it returns the expiry record. Each change gives a `ModeChanged` record for the `mode_changed` event (#16). Time comes from the caller (`Clock`, `Now`).

**Readiness gate.** When the readiness check (`trace::readiness`, below) says `ack_required`, the caller sets `Governance::readiness_ack_required`, and a requested move to `enforce` is rejected (`ReadinessAckRequired`) unless it carries `readiness_ack`; the record then has `readiness_acked`. Returning to `enforce` from a time box that left it, and the revert when a box ends, are never held back.

**Event fidelity** (`mode::events::fidelity`). Which decisions a mode reports; the agent emits them (#16). A disabled device reports nothing. `ignore` is never reported. A block keeps its rule's `log`. A would-block and an override-session allow are always an event. An allowed object follows its rule's `log` in `enforce`, is only summarised in `monitor` (nothing for `log: never`), and is a full event in `audit` and `learning`. A learning candidate's event carries the object's full facts (#5).

## Hierarchy

A device's effective policy is built from layers, outermost first: the global node, its tenant, its groups from the tenant down, its dynamic groups (highest `rank` first), and the device. A node linked to a template has the template's layer just before its own. On one node, policies apply by `slot_order`, and the lowest slot wins a conflict. The module docs of `hierarchy` have the full semantics. In short:

- **Rules are additive.** The effective rule list is the union of every layer's rule sets: those of assigned policies, of assigned rule set libraries (`rule_sets`, with a pin) and of every rule set library in an assigned category, including ones added later. Each rule keeps its provenance (`EffectivePolicy::rule`). A rule set two layers contribute is included once. Two different rule sets with one ID, or two versions of one library, are rejected.
- **Removal.** A child cannot delete an inherited rule. It can suppress one (`suppress_inherited`) when the rule set allows it: `allow_child_suppress` defaults to `true` for allowlists and baselines and to `false` for every other kind. A mandatory rule set can never be suppressed (`suppress_not_allowed`), so the #125 rule that the blocklist always wins holds below every node. A suppressed rule stays in the effective policy, disabled, and its provenance names the node. A child can also shadow a rule with one that wins under the precedence model. Nothing shadows a mandatory deny, because it is decided before every model.
- **Settings** are override-by-nearest, per top-level key of `settings` and per mode option. A node's own `settings` beat its policies. A key in `locked_settings` keeps its value for every layer below, and a later attempt is reported as `blocked_by_lock`. `locked_settings` can also lock `mode_options.mode_disconnected`, `mode_options.disconnected_after_secs` and `mode_options.mode_by_type`.
- **Modes.** Each layer's mode is the node's `mode`, or its policies' modes merged by `mode_merge`: `closest` (the default) or `strictest`. The built-in `unassigned` group audits unless it sets a mode, and so does a device with no mode anywhere. `lock_mode: true` sets a floor at the mode in force at that node. A weaker effective mode, type mode or rule set `mode_override` is raised to the floor, and so is a control level that would cap below it. With an `enforce` floor, `never_enforce` rules become `inherit`. Every change is listed in `ModeProvenance::adjustments`.
- **Precedence.** The model is chosen by the global node or the tenant, or by a group if its tenant allows it (`precedence_not_allowed`). With no node choosing, the highest-ranked policy's model applies. Every policy in one effective policy must use that model (`precedence_conflict`).
- **First match across levels.** Each rule set carries the band of the first layer that contributed it (`RuleSet::band`). The hierarchy sets the band and replaces any value a policy gives. `level_order: top_down` (the default) puts global rules first, then the tenant, the groups from the tenant down, the dynamic groups and the device. `bottom_up` reverses that order, and `flat` ignores levels.
- **Determinism.** The content hash is the SHA-256 of the effective policy's canonical JSON (sorted keys, revision left out) with the resolved library versions. It never depends on the order of anything in the snapshot (property-tested).
- **Placement.** Each tenant's placement rules are first-match on directory OU, directory group, hostname wildcard, CIDR, tags and OS, and end with an implicit catch-all to `unassigned` that cannot be removed. A group can opt out of placement as a source and as a target (`allow_auto_assignment: false`). Placement runs on first contact and on reconnect, and on a user change only if the tenant sets `place_on_user_change`.

## Trace, explain and simulate

**Trace.** `trace::Tracer::trace(subject, extras, state, trace_id, options)` decides one object with `Evaluator::evaluate_in` and returns a `Trace`, a bounded, structured record of that evaluation. The trace embeds the evaluator's decision unchanged and takes the set of matched rules from the evaluator. It then explains each rule by evaluating its criteria one by one, with the same compiled criteria and the same three-valued logic, without stopping early. Property tests check, over random policies, facts and device states, that the trace and the evaluator agree.

| Field | Contents | Level |
|---|---|---|
| `trace_schema_version` | `1.0.0` | all |
| `trace_id`, `policy_id`, `policy_revision`, `bundle_hash` | identity; `bundle_hash` is supplied by the caller (#43) | all |
| `effective_mode`, `decisive`, `decision` | the mode, the deciding rule, and the decision exactly as the evaluator made it | all |
| `mode_resolution[]` | each step of #36 that applied (lockdown, device mode, mandatory deny, disconnected, type mode, control level, rule set and rule overrides, session), the effective mode and what it did to the outcome | standard |
| `precedence_model`, `stages[]` | each pipeline stage: `decided`, `passed` or `skipped`, with its candidate count and, with a clock (`trace_timed`), its duration | standard |
| `matched[]` | every rule that matched: stage, action, specificity tier, `order`, `priority`, and its role (`decided`, `overridden`, `annotation`, `granted`) | standard |
| `decisive.criteria[]` | the deciding rule's criteria, each with its tri-state result, the result it needed (`no_match` under `not`), and its notes | standard |
| `inactive_matches[]` | disabled rules that would have matched | standard |
| `scope_rejections[]` | rules whose match tree matched but whose scopes (#38) took them out: the rule, the level (`policy`, `rule_set`, `rule`) and, when one decided alone, the dimension | standard |
| `unknown_facts[]` | each missing or untrusted fact, why, and its effect on the rules it left unknown (an allow did not apply, a deny did not apply, a deny failed closed) | standard |
| `warnings[]` | `path_acl_unsafe`, `short_name_unresolved`, `signature_relaxed` (#256), `scope_stale` and `clock_untrusted` from scopes (#38), and `condition_timeout` and `user_controlled_context` once their sources exist (#33) | standard |
| `inheritance[]` | the deciding rule's provenance: policy, rule set, rule. The group steps that `hierarchy::EffectivePolicy` records (#37) are a follow-up under #41 | standard |
| `allow_suggestion` | for a block or a would-block, a draft allow rule from the strongest identity available (hash, then publisher with product and version, then publisher, then a path users cannot write), with caveats if a mandatory or ordinary deny also matched. The engine never applies it: it is handed to approvals and recommendations (#5, #11) | standard |
| `near_misses[]` | rules whose identity anchor matched but which did not apply, ranked by matched criteria (at most 10), each with its failing criteria: pointer, field, operator, expected and observed values | full |
| `facts_used[]` | every fact the evaluated criteria read | full |

`trace::LevelPolicy` chooses the level an agent records: `minimal` for an object that runs, `standard` for a block or a would-block, and `full` with the device's debug flag or during a diagnostic session (`DIAGNOSTIC_SESSION_SECS`, 30 minutes). The simulator always traces at `full`. A `minimal` trace is built from the decision alone, with no further evaluation.

**Bounds.** Every list has a limit (`trace::limits`), and the entries left out are counted (`omitted`, `*_omitted`). Values are cut to 128 characters, and at most 4 values of one fact are written. The decision's own lists (`overridden`, `annotations`, `trust_sources`) are cut to 10 in the trace's JSON, with `*_omitted` counts. A test builds the largest trace the limits allow and checks that it stays within `MAX_TRACE_BYTES` (1 MiB).

**Privacy** (#18). Facts are written as `trace::Privacy` allows, when the trace is built. By default, object facts and paths are written and the user, device and session are withheld. A withheld value becomes its field plus, if a key is set, an HMAC-SHA-256 digest, so two traces can be compared without revealing the value. Every value written first passes the `Redactor`, whose linear-time patterns replace each match with `[redacted]`. Command-line facts (#7) will pass the same redactor.

**Explain.** `trace::explain(trace, verbosity)` gives an `ExplainDoc`: a summary, a reason a person can act on (such as a group membership), paragraphs, "why not allowed?" from the near misses, "what would allow this?" from the draft, and a table of the matching rules. `render_text` (CLI), `render_markdown` (console; policy text is escaped) and `render_tray` (one sentence, such as "Blocked by rule 'Block script hosts for standard users' (R-000004). This is because you are not in S-1-5-21-…-1100."; groups are named as the rule names them, until directory names arrive with #4) write it. The messages are templates in a `Catalog` (English built in). A translation is a file in a subset of the Fluent syntax (`id = text`, with `{ $name }` placeholders), and a message it lacks falls back to English.

**Simulate.** `trace::simulate::Simulator` replays recorded facts against the current policy and a `Candidate`: a draft document, a `ChangeSet` (add, replace, remove, enable or disable rules, or change the mode), or a mode change such as `audit` to `enforce`. Facts come as a `SnapshotFile` (`facts_schema_version` 1.0.0, YAML or JSON). Events, test files and inventory exports all use this format. A snapshot of another major version, or of a newer minor version, is rejected rather than guessed at. A fact a snapshot lacks is unknown, as on the agent. `run` reports the summary (newly blocked, newly allowed, changed attribution, changed outcome, unchanged), the changed events, and aggregates by device, user, rule and object. `events` gives every event's decision under both policies. Every decision comes from `Evaluator::evaluate_in`, the agent's function. Events are evaluated in parallel and sorted by event ID, so the result does not depend on the thread count. `cross_check` compares recorded agent decisions with the simulator's.

**Readiness** (#36). `trace::readiness::readiness` counts the would-block events per device in a window of `days` days, marks devices with at most `max_would_block` as ready, lists the objects with the most would-blocks with a draft rule for each, and gives the gate: "N would-block events across M devices in the last D days", with `ack_required` when N is above the threshold.

**Policy-as-code tests.** `trace::policy_test` reads a `tests:` file (`given` facts, `expect` an outcome, enforce-mode outcome, reason code, mode or deciding rule) and runs it through the simulator. The report has `exit_code` (non-zero on failure) and `junit()`. The examples in [`docs/examples/simulation/`](../../docs/examples/simulation/) run in CI (`tests/simulation.rs`). The `pal policy test` command is #15.

**Effective view.** `trace::effective::effective_view(policy, state)` lists what a device enforces: every rule with its provenance and whether it is active (a disabled rule, or every rule on a disabled device, is not), the settings with their source, the mode of every object type, the session, lockdown and the protection status.

## Scopes

A `scope` narrows a rule to some users and groups, devices, network locations, sessions and times (#38). It can be set on a rule, on a rule set's assignment (`policy.rule_set_scopes`, which covers every rule of the set) and on the policy (`policy.scope`). Scopes **intersect** down that chain: a rule applies only when its match tree matches and every scope on the way to it matches. A rule out of scope behaves as if it were absent. It never decides, it is not listed as overridden, and a scheduled deny outside its windows does not deny. Scopes are evaluated before the match tree. They never count towards a rule's identity anchor or its specificity, so the precedence model chooses among the rules in scope exactly as before. See [`docs/examples/policies/scoped-rules.yaml`](../../docs/examples/policies/scoped-rules.yaml).

| Field | Meaning |
|---|---|
| `principals` | `include` and `exclude` lists of `sid`, `well_known` (`everyone`, `authenticated_users`, `administrators`, `users`, `system`, `local_service`, `network_service`, `interactive`, `remote_desktop_users`, `domain_controllers`), `local_group` (by name, resolved on the device, without case), `directory_group` (SID and display name), `cloud_group` (tenant and object ID), `user_pattern` (a `DOMAIN\user` wildcard) and `principal_set` (#37) |
| `devices` | `device_id`, `hostname_pattern`, `device_set` (#37), `directory_computer_group`, `cloud_device_group` (tenant and object ID, tested against the device's cached cloud groups with the same staleness rule as users'), `ou` (with `include_sub_ous`) and `tag` |
| `network` | `cidr`, `range`, `dns_suffix`, `gateway_mac`, `server_reachable`, `location_profile` (a named profile in `policy.location_profiles`) and `network_set` (#37). An address test matches when any local interface address does. |
| `sessions` | `types` (`console`, `rdp`, `remote_shell`, `service`, `batch`, `network`) and, on multi-session hosts, the connecting `client`: `hostname` wildcards, `ip` blocks or ranges, and `device_sets` |
| `schedule` / `schedule_set` | when the scope is active (below) |
| `combine` | `all` (the default): every dimension that is set must match; `any`: one must |
| `negate` | apply when the scope does **not** match |
| `subject` | whose token `principals` tests: `process_user` (the default), `session_user` or `parent_process_user` |
| `max_instances_per_session` | allows only: block the object, with `instance_limit`, once this many instances already run in the session. `0` (the default) means no limit. An unknown count blocks. A mode that relaxes the block runs the object with the allow's containment, elevation, grants and window close. |

**Rules of evaluation.** An empty scope matches everything, and an empty `include` means everyone or everything. A match in `exclude` always beats `include`. Each list holds at most 1000 entries; larger lists belong in a library set (#37). A scope evaluates to match, no match or unknown, with the three-valued logic of match trees, and `unknown` follows the rule's action: an allow, trust source or exclusion never applies on it (it fails closed), and a deny applies only with `unknown_as: match`. Every note is collected in the decision's `scope_notes`: `fact_missing`, `fact_malformed`, `scope_stale`, `clock_untrusted`, `deny_only_group`, `set_unresolved`, `timezone_fallback` and `instance_limit`.

**Group membership** is tested against the subject's token: its group SIDs, which already hold nested directory groups and local groups, kept sorted so that a test is a binary search. Cloud-directory groups are not in the token. The agent caches them on the device with `cached_at`, and a cached membership older than `settings.group_cache_max_age_secs` (default 86400, range 3600 to 86400), from the future, or read with an untrusted clock is unknown (`scope_stale`). A deny-only SID in a filtered administrator token (UAC) is read both as membership and as none, and a rule takes the reading that makes it apply less if it lets an object run, and more if it denies or audits (`deny_only_group`). So a non-elevated administrator never gets an administrators-only allow, and is never let off a deny that excludes administrators. Absence from a token is proven only when its user SID and groups were both collected and are well formed, because the user SID is not among the groups. A SID set or cloud-group cache with a malformed entry cannot prove absence either (`fact_malformed`).

Membership in token groups changes only when a new token is created, at the next logon. Removing a user from a group may therefore need them to log off before scopes see it. Cached cloud groups refresh on the configured interval, or on a manual refresh command (#4).

**Name patterns** (`user_pattern`) match the account name, which is easier to spoof than a SID. Validation only accepts one where a match makes the rules it covers apply less if they let an object run, or more if they deny (`user_pattern_not_allowed`). That rules them out of allow includes. Audit rules may use them anywhere.

**Schedules.** `timezone_basis` is `device_local`, `utc` or `user_local`, defaulting to `settings.time_zone_basis`. `user_local` uses the session user's time zone if the agent could read it, and otherwise the device's (`timezone_fallback`). Zones are IANA names, read from the time zone database bundled into the binary. `windows` are `{days, start, end | duration_mins}`. A window starts on one of its days at `start`, includes its start and excludes its end, and may wrap midnight (`22:00` to `06:00`). `dates` limit the schedule to absolute date ranges and `except_dates` remove days such as holidays. Both test the local date of the instant decided. Across daylight-saving changes, a local time that occurs twice means its first occurrence, and a skipped one moves forward by the gap. This is the "compatible" rule of the ECMAScript Temporal proposal. A scheduled rule outside its windows is absent. If the agent's trusted time is missing or its integrity is flagged (#18), or the zone is unknown, scheduled allows go inactive and scheduled denies stay active (`clock_untrusted`). On an allow, in a scope with `combine: all` and no `negate`, so that the rule stops applying when the schedule closes, `on_window_close` (`none`, `warn`, `warn_then_terminate`, with `grace_secs`, default 300) gives the decision a `window_close` directive with the instant the schedule closes, for the agent and tray to act on (#4, #11). A schedule that is not well formed, such as an unvalidated library schedule, reads as an untrusted clock does (`fact_malformed`).

**Network location.** `policy.location_profiles` names locations such as `corporate` (`dns_suffix: corp.example.org` and `server_reachable: true`). The agent evaluates them with `scope::CompiledProfiles` on every network change and heartbeat (60 seconds by default). `scope::LocationTracker` keeps the previous location until a new one has been stable for 5 seconds, and scopes test the result with `location_profile`.

**Library sets.** `principal_set`, `device_set`, `network_set`, `schedule_set` and client `device_sets` refer to library sets by `{id, pin}`, where `pin` is `latest` (the default) or a version number. Hierarchy validation checks each one like a tree reference, pins it to the version it resolves to, and counts it for in-use checks, so a new version of a set changes an effective policy's content hash. A schedule set holds one schedule, written as JSON. `Evaluator::with_library`, `trace::Tracer::with_library` and `Simulator::with_library` resolve principal, network and schedule sets through a `scope::ScopeLibrary` (#37 provides one: `ResolvedLibraries`). A set it cannot resolve is unknown (`set_unresolved`). Device-set membership is worked out by the server and arrives as a fact.

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
- `tests/decision_snapshots.rs` (needs `test-util`): whole-pipeline decisions for policies built with `test_util`, compared with reviewed `insta` snapshots in `tests/snapshots/pipeline/`. Review a change with `cargo insta review` (docs/testing.md#snapshot-tests).
- `tests/version_properties.rs`: every version operator, and `version_between` with both bounds, agree with a reference that compares versions as one integer, with values drawn next to each other to find off-by-one bugs. A planted exclusive maximum, and `version_ge` as `>`, each failed it at once.
- Modes: an exhaustive table test checks `mode::resolve` against an independent statement of the rules for every combination of device mode, connectivity, offline mode, type mode, control level, deciding rule, rule set override, rule override, session and lockdown (202,500 cases). Unit tests cover each mode's effect on a decision. Property tests check, over random policies and device states, that a mode only relaxes a block, `would_have_been` is the enforce-mode outcome, and a matching mandatory deny always blocks; and, over random histories of requests, ticks, clock changes and restarts, that no mode change outside the legal table happens and no weaker mode outlives its time box.
- Benchmarks: `benches/criterion_eval.rs` (criterion) measures matching one compiled criterion against facts, for each kind of operator, and `benches/simulate.rs` measures simulated decisions per second and the cost of a trace at each level: `cargo bench -p palisade-policy`.
- Trace: snapshot tests in `tests/snapshots/trace/` pin the trace JSON and the text, Markdown and tray explanations for an allow, a deny, a mandatory deny, a near miss, unknown facts, an inactive rule, an unsafe path, a would-block and an override session, plus the simulation, readiness, effective-view and JUnit outputs. Regenerate them with `PALISADE_BLESS=1 cargo test -p palisade-policy trace::`. Property tests check that the trace agrees with the evaluator, and that the simulator reproduces the evaluator's decisions on any thread count.
- Precedence: unit tests pin each model's choice, and property tests check that every model's winner does not depend on the order of the matching rules, that under `deny_wins` a deny always beats an allow, and, over random valid policies, that a matching mandatory deny always blocks and that shuffling rule sets and rules never changes a decision. `tests/precedence/*.yaml` is a conformance suite: each file gives rule sets, an object and the expected decision (outcome, deciding rule, overridden rules, annotations and grants) under all five models.
- Hierarchy: unit tests for every rule above and every hierarchy and library code. They cover parent and reference cycles (named in the error), pins, visibility, in-use checks, templates, placement and ownership. Property tests over random group trees, policies, locks and suppressions check four things. First, shuffling the snapshot never changes the content hash. Second, no suppression removes an inherited mandatory deny or a default blocklist rule. Every refused suppression is one of those, and a mandatory deny still blocks. Third, nothing in the effective policy is weaker than a `lock_mode` floor. Fourth, computing twice gives the same policy. `tests/hierarchy/*.yaml` is a fixture suite. Each file gives a snapshot, a device and the expected decisions. Its effective policy and explain output (the provenance of every rule and setting, and the mode with its floor) are compared with `tests/snapshots/hierarchy/`. Regenerate them with `PALISADE_BLESS=1 cargo test -p palisade-policy --test hierarchy`.
- Scopes: table tests for every dimension's include and exclude lists, `combine` and `negate`, filtered administrator tokens, stale and unknown group caches, connecting clients, the location debounce and the instance limit, and end-to-end pipeline tests. Schedule tests cover midnight wrap, daylight-saving changes in Sydney and New York, half-hour and 45-minute offsets (Adelaide, Kolkata, Kathmandu, Lord Howe), holidays and all three time-zone bases. They are checked against a reference that finds local times by scanning instants rather than through the time library. Property tests check that an `exclude` holding every `include` entry never matches, that adding a scope to a chain never raises its result (a scope only narrows a rule), that `negate` is three-valued negation, that a deny-only group takes the reading that makes an allow apply less and a deny apply more, that a scoped rule decides only where the unscoped rule would, and that `closes_at` is the first inactive instant.
- Fixtures in `tests/fixtures/`: `valid/` documents pass the schema and validation; `invalid/` documents pass the schema but fail validation with the codes and paths in their `.expected` files; `malformed/` documents are rejected by the schema at the paths in their `.expected` files.

## Allowed dependencies

`palisade-core`, `palisade-fileid`. Must never depend on an async runtime, an HTTP client or Windows API bindings. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms. This crate uses `std`. Only `palisade-core` has to build without it.

## Dependencies

- `regex-automata` and `regex-syntax`: the engine and parser behind the `regex` crate, for linear-time regular expressions with RE2 semantics, also used to compile wildcards (#32). Patterns are parsed once and built from the parse tree with only the linear-time engines enabled. `regex-syntax` also recognises look-around and backreferences, so the error can explain the alternative. Both are already in the lock file through `boon`.
- `unicode-normalization`: NFC normalisation before strings are compared (#32).
- `sha2` and `hmac`: the SHA-256 content hash of an effective policy (#37), deterministic trace IDs from event IDs in the simulator, and keyed digests of facts a trace withholds (#41). Both are from the same family as the hashes in `palisade-fileid`, and are already in the lock file.
- `jiff`: civil dates and times, IANA time zones and daylight-saving arithmetic for schedules (#38), with the time zone database bundled into the binary (`tzdb-bundle-always`, no other default features), so evaluation never reads the system. It replaced `chrono` and `chrono-tz`, which `cargo deny` reports unmaintained.
- Dev-dependencies: `boon` checks documents against the JSON Schema, `proptest` drives the property tests, `criterion` runs the benchmarks, and `insta` compares the decision snapshots.

## Feature flags

- `test-util`: builders for tests, in `palisade_policy::test_util`: policies, rule sets and rules (`PolicyBuilder`, `RuleSetBuilder`, `RuleBuilder`), match trees (`hash`, `publisher`, `under`, `all`, `any`, `not`), object facts (`facts()`), evaluation contexts (`context()`) and a `subject(..).decide(&policy)` shortcut. Off by default. Only `[dev-dependencies]` may turn it on (`cargo xtask check-manifests`), so it never reaches a release build. This crate's own unit tests always have it.

## Stability

Unstable and not published. Anything may change, until the first schema version is published.
