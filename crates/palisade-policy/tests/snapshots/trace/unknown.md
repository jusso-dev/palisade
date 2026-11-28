**Blocked: no rule allows this executable.**

Effective mode: enforce.

Mode step effective: enforce.

Mode step applied: enforce (blocked; no rule allows it, and the mode enforces).

Decided at stage unknown, under the deny\_wins precedence model.

The signer.publisher fact was unknown, so a rule that would let this run did not apply.

The signer.publisher fact was unknown, so an audit rule did not annotate.

The path.directory fact was unknown, so a rule that would let this run did not apply.

The meta.product\_name fact was unknown, so a rule that would let this run did not apply.

The user.groups fact was unknown, so a deny rule did not apply.

Warning: a path rule did not count, because users may be able to write the path, or it is not on a fixed local disk: R\-000003.

Rule 'Block script hosts for standard users' \(R\-000004\) would block this file, but the user.groups is unknown.

### What would allow this?

Draft: a rule allowing this exact file by its hash. Added to the policy, it would allow this file.
