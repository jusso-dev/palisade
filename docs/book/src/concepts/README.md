# Concepts

These pages explain the ideas behind Palisade's policy model. Each one links the issue that
specifies it in detail (the "E02" issues of the policy epic, [#2](https://github.com/jusso-dev/palisade/issues/2))
and the reference pages for the exact fields.

- [Identities](identities.md): how a file is recognised (hash, publisher, path, metadata).
- [Rules and conditions](rules-and-conditions.md): match trees, operators and actions.
- [Precedence models](precedence.md): which rule wins when several match.
- [Modes](modes.md): audit, enforce, learning, monitor and disabled.
- [Groups and inheritance](groups-and-inheritance.md): how policy reaches a device.
- [Unknown applications](unknown-applications.md): what happens when no rule decides.
- [Exceptions and offline overrides](exceptions-and-overrides.md): workable default-deny.
- [Decision trace](decision-trace.md): explaining every decision.

The policy engine's own README, [`palisade-policy`](../../../../crates/palisade-policy/README.md),
is the detailed reference for what is implemented today.
