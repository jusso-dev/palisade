# 0002. Enforcement strategy: OS-native policy first, optional own driver

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Palisade's rules (#2) have to stop code *before* it runs. Windows has two built-in
application control policy formats:

- the **OS-native code integrity policy** (XML compiled to binary, with base and supplemental
  policies). It is enforced by the kernel for drivers, executables, DLLs, packaged apps,
  installers and scripts run by enlightened hosts; and
- the **OS-native legacy rule-collection policy** (exe, dll, script, msi and packaged-app
  collections), enforced through the Application Identity service. It can target users and
  groups by SID.

Neither format can express every Palisade condition. The code integrity format has no notion
of the user, the parent process or the command line. The alternative is Palisade's own kernel
minifilter with process-creation callbacks (#8), which can see all of those, but which needs
kernel code, driver signing and a careful boot story.

Some products enforce from user mode by terminating a process after it has started. The first
execution still happens, so an assessment treats that approach as ineffective. Epic #8 (#113)
already rules it out as a default.

## Decision drivers

1. Pre-execution blocking. Kill-after-start is not acceptable.
2. Boot safety. A bad policy or driver must not leave a machine unbootable without a recovery
   path.
3. Expressiveness: per-user rules, parent process, command line, file owner.
4. Cost and feasibility for an open-source educational project: driver signing needs an EV
   certificate and attestation signing, and server SKUs need hardware certification (#112).
5. Robustness against a local administrator, and survival when the Palisade agent is not
   running.

## Considered options

1. **(a) OS-native only.** Compile Palisade policy to both OS-native formats. The agent only
   collects audit events and inventory.
   - Pro: kernel-enforced and pre-execution, with no Palisade kernel code. It keeps enforcing
     when the agent is stopped or has crashed. Signed code integrity policies, with Secure Boot,
     resist removal by administrators. Recovery tooling for bad policies is built into the OS.
   - Con: no parent-process, command-line or owner-based conditions. Per-user rules only
     exist in the rule-collection format, which depends on a service. Format limits apply.
2. **(b) Own driver only.** A Palisade minifilter decides on section creation, and
   process-creation callbacks decide on process start.
   - Pro: full expressiveness, one decision engine everywhere.
   - Con: a kernel bug can stop the machine. Production signing needs an EV certificate and
     attestation signing (client SKUs only without hardware certification). Nothing enforces
     when the driver is absent, unsigned or fails to load. That is the largest attack and
     failure surface.
3. **(c) Hybrid.** OS-native compile for the baseline, plus the optional Palisade driver for
   the conditions the native formats cannot express (user, parent, command line, owner). A file
   must pass both layers.
   - Pro: the native layer gives a robust, boot-safe baseline that keeps working without the
     driver. The driver only adds restrictions on top.
   - Con: two compilers and two sets of events to keep consistent. Each rule needs a
     "requires driver" flag so that gaps are reported, not hidden.

## Decision

Option (c), delivered in stages:

- **M2 default: (a) OS-native only.** The `enforcement_strategy` is `native_only`. The OS-native
  compiler (#6) is the first enforcement path. The agent (#4) collects events and inventory and
  deploys the compiled policies.
- **When the driver exists (#8): `layered` becomes the recommended default.** The native base
  expresses everything it can, and the driver enforces the rest. The two intersect.
  `driver_only` stays available for experiments but is not recommended.
- **Kill-after-start is never a default.** It is only an opt-in `post_start_terminate` mode for
  endpoints with neither the driver nor native support, with a warning that it does not meet
  pre-execution requirements (#113).
- Rules the active layers cannot enforce are reported per endpoint as "not enforced" (#81,
  #113). They are never silently dropped.

## Consequences

### Positive

- Pre-execution enforcement is available from M2 without any Palisade kernel code.
- Losing the driver degrades to the native column of the capability matrix, not to nothing.
- The project can ship and test enforcement without a production driver signature. Driver work
  can proceed on test-signed lab VMs.

### Negative

- Until the driver ships, parent-process, command-line and owner-based rules can only audit
  (through ETW). The console must show this.
- Per-user enforcement relies on the rule-collection format, which an administrator can
  disable by stopping its service. The tamper work in #220 has to account for that.
- Two compilers (code integrity and rule-collection) plus the driver protocol must stay
  consistent. The compile report and golden tests in #6 carry that cost.

## Security impact

This choice decides what an attacker has to defeat. With (a) and (c), stopping the Palisade
agent does not stop enforcement, because the kernel keeps enforcing the native policy, and
signed native policies on Secure Boot devices resist removal by an administrator (#85). With (c), the driver only
adds denies, so a driver fault cannot widen what is allowed. The residual risks are the
conditions only the driver can enforce (open until #8 ships) and the service dependency of the
rule-collection format. Both are recorded in the threat model (#219). Rejecting kill-after-start
removes a false sense of protection.

## Links

- Issue #20. Epics #4, #6, #8. Issues #81, #85, #112, #113, #219, #220.
- Failure behaviour of each layer: [ADR 0012](0012-fail-open-vs-fail-closed-defaults.md).
