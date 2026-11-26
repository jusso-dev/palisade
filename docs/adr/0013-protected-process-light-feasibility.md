# 0013. Protected process light feasibility

- Status: proposed
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

A Windows service can run as a **protected process light (PPL)** at the antimalware signer level.
Then even administrators and SYSTEM cannot terminate it, inject into it or debug it, unless the
caller runs at an equal or higher protection level. Some commercial application control agents
use this. It needs three things:

1. an early-launch antimalware (ELAM) driver that declares the service's signing certificate in
   its certificate-info resource;
2. that ELAM driver signed through the OS vendor's antimalware partner program; and
3. the service executable signed with the declared certificate (page hashes, SHA-256). Every
   DLL loaded into the service must either be signed as part of Windows, or be signed with the
   declared certificate, or be listed in a catalog file that is signed with the declared
   certificate and installed with the service. Third-party DLLs can be covered by that catalog
   without re-signing them.

The partner program has membership criteria that an educational open-source project probably
cannot meet. Test-signing mode allows experiments, but it is not a deployable protection. The
ISM's "users cannot disable or bypass" requirement (ISM-0846) allows exemptions for local
administrator and break-glass accounts, and it can largely be met without PPL through the
driver-backed handle protection in #220. PPL mainly raises the bar against an attacker who
already has administrator or SYSTEM rights.

Issue #221 is the investigation and spike. This ADR records the options and a provisional
direction now, so that #220 and #8 can design against it.

## Decision drivers

1. Feasibility for an open-source project without partner-program membership.
2. Protection against stopping or tampering with the agent by standard users (required) and by
   administrators (desirable).
3. Constraints PPL places on the agent: only correctly signed DLLs may load, Winsock layered
   providers are restricted, some ETW consumers and diagnostics are limited, and updates need a
   protected stop path.
4. Coverage on Server Core, ARM64 and with hypervisor-enforced code integrity on.

## Considered options

- **(a) Full PPL through the partner program.** Strongest protection against SYSTEM, but
  probably unavailable to this project.
- **(b) Driver-backed handle protection only** (#220 `moderate`/`strong` levels). The Palisade
  driver strips terminate, write and inject rights from handles to the agent processes for
  callers that are not Palisade. Feasible with test signing in the lab, and with an attested
  driver later (#112). It does not stop a SYSTEM attacker who can unload or disable drivers.
- **(c) Optional PPL for organisations that can sign their own ELAM driver.** A build feature
  `ppl` and an install property `PALISADE_ENABLE_PPL=0|1`, default 0. The organisation supplies
  the signing inputs. Palisade ships the plumbing, not the signature.
- **(d) A virtualization-based-security enclave for key material only.** Protects device keys
  from a SYSTEM attacker, but does not stop the agent being killed.
- **(e) User-mode hardening only:** service and file ACLs plus the mutual watchdog (#220
  `minimal`). Stops standard users. Does not stop administrators.

## Decision

**Proposed, not accepted.** The provisional direction is **(b) as the baseline, with (c) as an
opt-in**, and (e) as the floor when no driver is present. (a) is recorded as out of reach unless
the eligibility criteria turn out to be met. (d) is a separate question for key custody (#224)
and is not a substitute for process protection.

This ADR becomes `accepted` (or is revised) when the #221 spike has produced:

- the documented eligibility criteria of the OS vendor's antimalware partner program, and a
  yes or no on whether an open-source project can be admitted;
- a test-signed ELAM driver and a service launched as antimalware PPL on a test-signing VM, with
  captured results showing administrator `taskkill /f`, `OpenProcess(PROCESS_TERMINATE)` and
  debugger attach all fail with PPL on and succeed with it off;
- confirmation that the Rust agent binaries and their dependencies load under the PPL signing
  rules: the agent's own binaries signed with the declared certificate, every other DLL either
  signed as part of Windows or listed in a signed catalog, and no DLL outside those three cases;
  and that the agent's `tracing` and ETW use still works;
- measured startup and boot-time impact;
- a working clean-uninstall and update path, with the service stopping itself on a signed command;
- notes on Server Core, ARM64 and hypervisor-enforced code integrity.

Results go under `docs/spikes/ppl/`, and the residual-risk register in #219 is updated with the
final choice.

## Consequences

### Positive

- #220 and #8 can design the handle protection and the tamper levels now, without waiting for
  the spike.
- Organisations that can sign an ELAM driver are not shut out, if (c) is confirmed.

### Negative

- Until the spike is done, Palisade makes no claim of protection against administrators or SYSTEM.
- Devices without a signed native policy and Secure Boot have no protection of the baseline
  against an administrator, under any option here. Closing that gap is a deployment choice (#85),
  not something PPL or the driver can provide.
- Option (c) adds a build flavour and a signing input that CI can only exercise with test
  certificates.
- If PPL is adopted, the agent has to be split into a small protected part and an unprotected
  helper for heavy parsing (#221 design notes). That design work only happens if (c) is chosen.

## Security impact

This decision sets how strongly the agent resists an attacker who already has administrator or
SYSTEM rights. Under the provisional direction, standard users and user-level malware cannot stop
the agent (through #220), but an administrator who can disable the driver can. Because of
[ADR 0002](0002-enforcement-strategy.md) and [ADR 0018](0018-fail-open-vs-fail-closed-defaults-revised.md),
stopping the agent does not stop the kernel-enforced native policy. How much of the baseline
survives an administrator then depends on how the native policy is deployed:

- **Signed native policy on a Secure Boot device** (#85). The administrator cannot remove or
  replace the code integrity policy, so the kernel-enforced code integrity baseline is kept. The
  residual risk is loss of reporting, of driver-only rules, and of per-user rules in the
  rule-collection format, which depend on a service the administrator can stop
  ([ADR 0002](0002-enforcement-strategy.md)). Signing does not protect that service.
- **Unsigned native policy, or Secure Boot off.** An administrator can delete or replace the
  code integrity policy, so the residual risk also includes **loss of the code integrity
  baseline**. Palisade layers
  cannot prevent this, because the same administrator can disable the driver too.

Signing and Secure Boot are **not required**. A signed policy that is wrong can leave a device
unbootable, with recovery only by turning Secure Boot off (#85), so signing stays an opt-in per
deployment, recommended once a policy is stable. The unsigned case is an accepted risk. To keep
it visible, the agent reports `secure_boot_enabled` and `signed_policy_active` (#85), and the
console shows a device without both as "baseline removable by an administrator". Both residual
risks are recorded in #219. Test signing is only ever enabled
on throwaway VMs, never on runner hosts.

## Links

- Issues #20, #221 (PPL spike), #220 (tamper protection), #112 (driver signing), #85 (signed
  native policies), #219 (threat model), #224 (key custody). Epics #8, #18.
