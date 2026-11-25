# Simulation examples

Policy-as-code tests and recorded facts for
[`../policies/staged-rollout.yaml`](../policies/staged-rollout.yaml) (#41).

- `staged-rollout.tests.yaml`: `given` facts and the decision each must
  get. `cargo test -p palisade-policy --test simulation` runs them, so CI
  fails when the policy and its tests disagree. The `pal policy test`
  command (#15) will read the same files and write JUnit XML.
- `staged-rollout.snapshots.yaml`: decision inputs as an agent records
  them, in the `facts_schema_version` 1 format. The same test replays them
  under the policy, and again under the policy moved to `enforce`. It then
  checks the readiness report: how many would-block events each device
  had, and whether the move needs a `readiness_ack`.
