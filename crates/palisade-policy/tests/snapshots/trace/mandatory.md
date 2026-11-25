**Blocked by mandatory rule 'Known bad' \(R\-000010\). Nothing can override it.**

Effective mode: enforce.

Mode step mandatory\_deny: enforce (a mandatory deny enforces in every mode).

Mode step effective: enforce.

Mode step applied: enforce (blocked; a mandatory deny is never relaxed).

Decided at stage mandatory\_deny, under the deny\_wins precedence model.

Other matching rules overridden by the deciding rule: 1.

### Why not allowed?

- Rule 'Tools folder' \(R\-000003\) would allow this file, but the path.directory on this file is `C:\Apps` (expected starts\_with `C:\Tools`).

### What would allow this?

Draft: a rule allowing this exact file by its hash. A mandatory rule blocks this file, so no allow rule can change that.

### Matching rules

| Rule | Name | Action | Stage | Role |
|---|---|---|---|---|
| R\-000001 | Example signed tools | allow | policy | overridden |
| R\-000006 | Watch Example | audit | annotation | annotation |
| R\-000010 | Known bad | deny | mandatory_deny | decided |
