# Operator test vectors (#32)

Each `*.toml` file here is a table of cases. `tests/ops_vectors.rs` runs every one. A case is:

```toml
[[case]]
name = "what it shows"
criterion = { field = "meta.product_name", operator = "equals", values = ["Editor"] }
# The fact. Use `fact` for a text, hash or version fact, `path` (with `user_writable`
# and `volume`: fixed, removable, optical or network) for a path, or `context` for the
# context fields the case sets. An allow only trusts a path with `user_writable = false`
# on a `fixed` volume.
fact = "editor"
action = "deny"        # optional: the rule's action; default deny
expect = "match"       # match | no_match | unknown
```

A criterion that must not compile has `error = "<kind>"` instead of a fact and `expect`. The kinds are
`operator_field_mismatch`, `value_count`, `invalid_value`, `regex_look_around`, `regex_backreference`,
`pattern_too_large`, `regex_syntax`, `case_sensitivity_not_applicable` and `option_not_applicable`.

Context keys are `user.groups`, `user.dn`, `user.integrity_level`, `device.os_build`, `device.dn`,
`session.id`, `session.client_ip`, `net.ip`, `net.mac`, `net.dns_suffix`, `net.locations`, `time.weekday`,
`time.minute`, `time.date` and `process.command_line` (which also sets the split arguments).

For a probed field (`env.var`, `reg.key`, `reg.value`, `fs.file`, `fs.folder`, #329), `probe` says what the agent
found at the criterion's `target`: `"absent"`, `"present"`, `"timed_out"` (the rule's budget ran out), `"other"` (a value no operator compares), a string, or a
number (a `REG_DWORD`/`REG_QWORD`). Without `probe` the agent did not look.
