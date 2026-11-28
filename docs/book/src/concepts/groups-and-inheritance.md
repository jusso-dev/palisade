# Groups and inheritance

A policy reaches a device through a hierarchy of scopes: global, tenant, nested groups, and the
device itself. Specified in [#37](https://github.com/jusso-dev/palisade/issues/37); the engine
side is built (`hierarchy` and `library` in
[`palisade-policy`](../../../../crates/palisade-policy/README.md#hierarchy)). The server and
console that manage the hierarchy are milestone M3
([#129](https://github.com/jusso-dev/palisade/issues/129)).

Each level can add rule sets and change settings, and a level can **lock** a setting so lower
levels cannot weaken it. Groups nest at most 8 deep; built-in groups catch devices that are
`unassigned`, `unmanaged` or in `staging`, and dynamic groups and placement rules put devices in
groups automatically.

Reusable **libraries** (rule sets, application definitions, match fragments, and hash, publisher,
path, principal, device, network and schedule sets) are referenced by ID and version pin rather
than copied, so a fix in one place reaches every policy that uses it. A `ref` node in a match
tree names one; reference cycles are rejected.

The output is one deterministic **effective policy** per device: a pure function of the
hierarchy, the libraries at their resolved versions and the device's dynamic groups, with the
provenance of every rule and setting and a content hash. The engine only ever evaluates an
effective policy, so everything in [Rules](rules-and-conditions.md) and
[Precedence](precedence.md) applies unchanged.

That provenance carries into explanations: a decision trace names the groups the deciding rule
came from (which node contributed its rule set, through which policy, library or template) and
the node that suppressed it, if one did, and the effective view of a device shows the same for
every rule. Group names follow the trace's redaction settings.

Rule scoping by user, group, device, time, network and session is specified in
[#38](https://github.com/jusso-dev/palisade/issues/38).

See also: [`LibraryRef`](../reference/generated/policy/library-ref.md) and
[`Match`](../reference/generated/policy/match.md) in the policy reference.
