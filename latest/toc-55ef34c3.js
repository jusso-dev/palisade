// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="introduction.html">Introduction</a></span></li><li class="chapter-item expanded "><li class="part-title">User guide</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/index.html"><strong aria-hidden="true">1.</strong> Concepts</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/identities.html"><strong aria-hidden="true">1.1.</strong> Identities</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/rules-and-conditions.html"><strong aria-hidden="true">1.2.</strong> Rules and conditions</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/precedence.html"><strong aria-hidden="true">1.3.</strong> Precedence models</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/modes.html"><strong aria-hidden="true">1.4.</strong> Modes</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/groups-and-inheritance.html"><strong aria-hidden="true">1.5.</strong> Groups and inheritance</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/unknown-applications.html"><strong aria-hidden="true">1.6.</strong> Unknown applications</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/exceptions-and-overrides.html"><strong aria-hidden="true">1.7.</strong> Exceptions and offline overrides</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/concepts/decision-trace.html"><strong aria-hidden="true">1.8.</strong> Decision trace</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/examples/simulation/index.html"><strong aria-hidden="true">1.8.1.</strong> Simulation examples</a></span></li></ol></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/getting-started/index.html"><strong aria-hidden="true">2.</strong> Getting started</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/getting-started/lab-install.html"><strong aria-hidden="true">2.1.</strong> Lab install</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/getting-started/first-policy.html"><strong aria-hidden="true">2.2.</strong> Your first policy</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Reference</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/index.html"><strong aria-hidden="true">3.</strong> Policy reference</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/action.html"><strong aria-hidden="true">3.1.</strong> Action</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/client-filter.html"><strong aria-hidden="true">3.2.</strong> ClientFilter</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/cloud-object.html"><strong aria-hidden="true">3.3.</strong> CloudObject</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/criterion.html"><strong aria-hidden="true">3.4.</strong> Criterion</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/date-range.html"><strong aria-hidden="true">3.5.</strong> DateRange</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/device-ref.html"><strong aria-hidden="true">3.6.</strong> DeviceRef</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/directory-group.html"><strong aria-hidden="true">3.7.</strong> DirectoryGroup</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/effects.html"><strong aria-hidden="true">3.8.</strong> Effects</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/library-ref.html"><strong aria-hidden="true">3.9.</strong> LibraryRef</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/location-profile.html"><strong aria-hidden="true">3.10.</strong> LocationProfile</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/match.html"><strong aria-hidden="true">3.11.</strong> Match</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/metadata.html"><strong aria-hidden="true">3.12.</strong> Metadata</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/mode-options.html"><strong aria-hidden="true">3.13.</strong> ModeOptions</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/network-ref.html"><strong aria-hidden="true">3.14.</strong> NetworkRef</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/ou-ref.html"><strong aria-hidden="true">3.15.</strong> OuRef</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/policy-settings.html"><strong aria-hidden="true">3.16.</strong> PolicySettings</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/policy.html"><strong aria-hidden="true">3.17.</strong> Policy</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/precedence-options.html"><strong aria-hidden="true">3.18.</strong> PrecedenceOptions</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/principal-ref.html"><strong aria-hidden="true">3.19.</strong> PrincipalRef</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/ref-list.html"><strong aria-hidden="true">3.20.</strong> RefList</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/ref-list2.html"><strong aria-hidden="true">3.21.</strong> RefList2</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/ref-list3.html"><strong aria-hidden="true">3.22.</strong> RefList3</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/rule-set-scope.html"><strong aria-hidden="true">3.23.</strong> RuleSetScope</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/rule-set.html"><strong aria-hidden="true">3.24.</strong> RuleSet</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/rule.html"><strong aria-hidden="true">3.25.</strong> Rule</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/schedule.html"><strong aria-hidden="true">3.26.</strong> Schedule</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/scope.html"><strong aria-hidden="true">3.27.</strong> Scope</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/session-filter.html"><strong aria-hidden="true">3.28.</strong> SessionFilter</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/types.html"><strong aria-hidden="true">3.29.</strong> Value types</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/policy/window.html"><strong aria-hidden="true">3.30.</strong> Window</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/index.html"><strong aria-hidden="true">4.</strong> Event reference</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/account.html"><strong aria-hidden="true">4.1.</strong> Account</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/admin.html"><strong aria-hidden="true">4.2.</strong> Admin</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/agent-info.html"><strong aria-hidden="true">4.3.</strong> AgentInfo</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/approval.html"><strong aria-hidden="true">4.4.</strong> Approval</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/audit-policy.html"><strong aria-hidden="true">4.5.</strong> AuditPolicy</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/cache-stats.html"><strong aria-hidden="true">4.6.</strong> CacheStats</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/change.html"><strong aria-hidden="true">4.7.</strong> Change</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/device.html"><strong aria-hidden="true">4.8.</strong> Device</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/elevation.html"><strong aria-hidden="true">4.9.</strong> Elevation</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/file.html"><strong aria-hidden="true">4.10.</strong> File</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/fim.html"><strong aria-hidden="true">4.11.</strong> Fim</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/hashes.html"><strong aria-hidden="true">4.12.</strong> Hashes</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/host.html"><strong aria-hidden="true">4.13.</strong> Host</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/identity.html"><strong aria-hidden="true">4.14.</strong> Identity</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/native.html"><strong aria-hidden="true">4.15.</strong> Native</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/network.html"><strong aria-hidden="true">4.16.</strong> Network</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/origin.html"><strong aria-hidden="true">4.17.</strong> Origin</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/parent-process.html"><strong aria-hidden="true">4.18.</strong> ParentProcess</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/policy-ref.html"><strong aria-hidden="true">4.19.</strong> PolicyRef</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/principal.html"><strong aria-hidden="true">4.20.</strong> Principal</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/probe.html"><strong aria-hidden="true">4.21.</strong> Probe</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/process-summary.html"><strong aria-hidden="true">4.22.</strong> ProcessSummary</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/process.html"><strong aria-hidden="true">4.23.</strong> Process</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/registry-data.html"><strong aria-hidden="true">4.24.</strong> RegistryData</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/registry.html"><strong aria-hidden="true">4.25.</strong> Registry</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/restriction.html"><strong aria-hidden="true">4.26.</strong> Restriction</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/script.html"><strong aria-hidden="true">4.27.</strong> Script</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/signer.html"><strong aria-hidden="true">4.28.</strong> Signer</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/source.html"><strong aria-hidden="true">4.29.</strong> Source</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/types.html"><strong aria-hidden="true">4.30.</strong> Value types</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/user.html"><strong aria-hidden="true">4.31.</strong> User</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/events/version-info.html"><strong aria-hidden="true">4.32.</strong> VersionInfo</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/cli.html"><strong aria-hidden="true">5.</strong> CLI reference</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/api.html"><strong aria-hidden="true">6.</strong> API reference</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/NAMING.html"><strong aria-hidden="true">7.</strong> Vendor-neutral naming</a></span></li><li class="chapter-item expanded "><li class="part-title">Architecture</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="project-overview.html"><strong aria-hidden="true">8.</strong> Project overview</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/reference/generated/crates.html"><strong aria-hidden="true">9.</strong> Crate map</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-core/index.html"><strong aria-hidden="true">9.1.</strong> palisade-core</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-fileid/index.html"><strong aria-hidden="true">9.2.</strong> palisade-fileid</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-policy/index.html"><strong aria-hidden="true">9.3.</strong> palisade-policy</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-proto/index.html"><strong aria-hidden="true">9.4.</strong> palisade-proto</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-agent/index.html"><strong aria-hidden="true">9.5.</strong> palisade-agent</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-server/index.html"><strong aria-hidden="true">9.6.</strong> palisade-server</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-cli/index.html"><strong aria-hidden="true">9.7.</strong> palisade-cli</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-tray/index.html"><strong aria-hidden="true">9.8.</strong> palisade-tray</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-console/index.html"><strong aria-hidden="true">9.9.</strong> palisade-console</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="crates/palisade-driver/index.html"><strong aria-hidden="true">9.10.</strong> palisade-driver</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="xtask/index.html"><strong aria-hidden="true">9.11.</strong> xtask</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/workspace.html"><strong aria-hidden="true">10.</strong> Workspace rules</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/index.html"><strong aria-hidden="true">11.</strong> Architecture decision records</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/PROCESS.html"><strong aria-hidden="true">11.1.</strong> ADR process</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0001-record-architecture-decisions.html"><strong aria-hidden="true">11.2.</strong> 0001. Record architecture decisions</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0002-enforcement-strategy.html"><strong aria-hidden="true">11.3.</strong> 0002. Enforcement strategy: OS-native policy first, optional own driver</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0003-crate-boundaries-and-dependency-direction.html"><strong aria-hidden="true">11.4.</strong> 0003. Crate boundaries and dependency direction</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0004-default-rule-precedence-model.html"><strong aria-hidden="true">11.5.</strong> 0004. Default rule precedence model</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0005-agent-server-protocol.html"><strong aria-hidden="true">11.6.</strong> 0005. Agent-server protocol</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0006-server-database.html"><strong aria-hidden="true">11.7.</strong> 0006. Server database and tenant isolation</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0007-agent-local-store.html"><strong aria-hidden="true">11.8.</strong> 0007. Agent local store</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0008-cryptographic-algorithms.html"><strong aria-hidden="true">11.9.</strong> 0008. Cryptographic algorithms and libraries</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0009-async-runtime-and-concurrency.html"><strong aria-hidden="true">11.10.</strong> 0009. Async runtime and concurrency model</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0010-licence.html"><strong aria-hidden="true">11.11.</strong> 0010. Licence</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0011-msrv-and-unsafe-code-policy.html"><strong aria-hidden="true">11.12.</strong> 0011. MSRV and unsafe code policy</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0012-fail-open-vs-fail-closed-defaults.html"><strong aria-hidden="true">11.13.</strong> 0012. Fail-open versus fail-closed defaults</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0013-protected-process-light-feasibility.html"><strong aria-hidden="true">11.14.</strong> 0013. Protected process light feasibility</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0014-educational-scope-statement.html"><strong aria-hidden="true">11.15.</strong> 0014. Educational scope statement</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0015-agent-server-protocol-fallback-triggers.html"><strong aria-hidden="true">11.16.</strong> 0015. Agent-server protocol with protocol-failure fallback</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0016-server-database-and-tenant-scope.html"><strong aria-hidden="true">11.17.</strong> 0016. Server database, tenant isolation and tenant scope binding</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0017-cryptographic-algorithms-and-nonces.html"><strong aria-hidden="true">11.18.</strong> 0017. Cryptographic algorithms, libraries and AEAD nonces</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0018-fail-open-vs-fail-closed-defaults-revised.html"><strong aria-hidden="true">11.19.</strong> 0018. Fail-open versus fail-closed defaults, revised</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/adr/0019-contributor-sign-off-dco.html"><strong aria-hidden="true">11.20.</strong> 0019. Contributor sign-off: DCO, no CLA</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Security</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/security/index.html"><strong aria-hidden="true">12.</strong> Security</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/security/threat-model.html"><strong aria-hidden="true">12.1.</strong> Threat model</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/security/hardening.html"><strong aria-hidden="true">12.2.</strong> Hardening guide</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="SECURITY.html"><strong aria-hidden="true">12.3.</strong> Reporting a vulnerability</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/responsible-use.html"><strong aria-hidden="true">12.4.</strong> Responsible use</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Compliance</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/compliance/index.html"><strong aria-hidden="true">13.</strong> Compliance</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/compliance/essential-eight.html"><strong aria-hidden="true">13.1.</strong> Essential Eight</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/compliance/ism.html"><strong aria-hidden="true">13.2.</strong> ISM controls</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Contributing</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="CONTRIBUTING.html"><strong aria-hidden="true">14.</strong> Contributing</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/dev/windows.html"><strong aria-hidden="true">14.1.</strong> Developing on Windows</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/dev/unix.html"><strong aria-hidden="true">14.2.</strong> Developing on Linux and other desktop OS</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/testing.html"><strong aria-hidden="true">14.3.</strong> Testing</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/ci.html"><strong aria-hidden="true">14.4.</strong> Continuous integration</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/packaging.html"><strong aria-hidden="true">14.5.</strong> Packaging</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/releasing.html"><strong aria-hidden="true">14.6.</strong> Releasing</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/dependencies.html"><strong aria-hidden="true">14.7.</strong> Dependencies</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/repo-settings.html"><strong aria-hidden="true">14.8.</strong> Repository settings</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="CODE_OF_CONDUCT.html"><strong aria-hidden="true">14.9.</strong> Code of conduct</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="SUPPORT.html"><strong aria-hidden="true">14.10.</strong> Support</a></span></li></ol><li class="chapter-item expanded "><li class="spacer"></li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="docs/book/src/glossary.html">Glossary</a></span></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split('#')[0].split('?')[0];
        if (current_page.endsWith('/')) {
            current_page += 'index.html';
        }
        const links = Array.prototype.slice.call(this.querySelectorAll('a'));
        const l = links.length;
        for (let i = 0; i < l; ++i) {
            const link = links[i];
            const href = link.getAttribute('href');
            if (href && !href.startsWith('#') && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The 'index' page is supposed to alias the first chapter in the book.
            if (link.href === current_page
                || i === 0
                && path_to_root === ''
                && current_page.endsWith('/index.html')) {
                link.classList.add('active');
                let parent = link.parentElement;
                while (parent) {
                    if (parent.tagName === 'LI' && parent.classList.contains('chapter-item')) {
                        parent.classList.add('expanded');
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', e => {
            if (e.target.tagName === 'A') {
                const clientRect = e.target.getBoundingClientRect();
                const sidebarRect = this.getBoundingClientRect();
                sessionStorage.setItem('sidebar-scroll-offset', clientRect.top - sidebarRect.top);
            }
        }, { passive: true });
        const sidebarScrollOffset = sessionStorage.getItem('sidebar-scroll-offset');
        sessionStorage.removeItem('sidebar-scroll-offset');
        if (sidebarScrollOffset !== null) {
            // preserve sidebar scroll position when navigating via links within sidebar
            const activeSection = this.querySelector('.active');
            if (activeSection) {
                const clientRect = activeSection.getBoundingClientRect();
                const sidebarRect = this.getBoundingClientRect();
                const currentOffset = clientRect.top - sidebarRect.top;
                this.scrollTop += currentOffset - parseFloat(sidebarScrollOffset);
            }
        } else {
            // scroll sidebar to current active section when navigating via
            // 'next/previous chapter' buttons
            const activeSection = document.querySelector('#mdbook-sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        const sidebarAnchorToggles = document.querySelectorAll('.chapter-fold-toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(el => {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define('mdbook-sidebar-scrollbox', MDBookSidebarScrollbox);


// ---------------------------------------------------------------------------
// Support for dynamically adding headers to the sidebar.

(function() {
    // This is used to detect which direction the page has scrolled since the
    // last scroll event.
    let lastKnownScrollPosition = 0;
    // This is the threshold in px from the top of the screen where it will
    // consider a header the "current" header when scrolling down.
    const defaultDownThreshold = 150;
    // Same as defaultDownThreshold, except when scrolling up.
    const defaultUpThreshold = 300;
    // The threshold is a virtual horizontal line on the screen where it
    // considers the "current" header to be above the line. The threshold is
    // modified dynamically to handle headers that are near the bottom of the
    // screen, and to slightly offset the behavior when scrolling up vs down.
    let threshold = defaultDownThreshold;
    // This is used to disable updates while scrolling. This is needed when
    // clicking the header in the sidebar, which triggers a scroll event. It
    // is somewhat finicky to detect when the scroll has finished, so this
    // uses a relatively dumb system of disabling scroll updates for a short
    // time after the click.
    let disableScroll = false;
    // Array of header elements on the page.
    let headers;
    // Array of li elements that are initially collapsed headers in the sidebar.
    // I'm not sure why eslint seems to have a false positive here.
    // eslint-disable-next-line prefer-const
    let headerToggles = [];
    // This is a debugging tool for the threshold which you can enable in the console.
    let thresholdDebug = false;

    // Updates the threshold based on the scroll position.
    function updateThreshold() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const windowHeight = window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;

        // The number of pixels below the viewport, at most documentHeight.
        // This is used to push the threshold down to the bottom of the page
        // as the user scrolls towards the bottom.
        const pixelsBelow = Math.max(0, documentHeight - (scrollTop + windowHeight));
        // The number of pixels above the viewport, at least defaultDownThreshold.
        // Similar to pixelsBelow, this is used to push the threshold back towards
        // the top when reaching the top of the page.
        const pixelsAbove = Math.max(0, defaultDownThreshold - scrollTop);
        // How much the threshold should be offset once it gets close to the
        // bottom of the page.
        const bottomAdd = Math.max(0, windowHeight - pixelsBelow - defaultDownThreshold);
        let adjustedBottomAdd = bottomAdd;

        // Adjusts bottomAdd for a small document. The calculation above
        // assumes the document is at least twice the windowheight in size. If
        // it is less than that, then bottomAdd needs to be shrunk
        // proportional to the difference in size.
        if (documentHeight < windowHeight * 2) {
            const maxPixelsBelow = documentHeight - windowHeight;
            const t = 1 - pixelsBelow / Math.max(1, maxPixelsBelow);
            const clamp = Math.max(0, Math.min(1, t));
            adjustedBottomAdd *= clamp;
        }

        let scrollingDown = true;
        if (scrollTop < lastKnownScrollPosition) {
            scrollingDown = false;
        }

        if (scrollingDown) {
            // When scrolling down, move the threshold up towards the default
            // downwards threshold position. If near the bottom of the page,
            // adjustedBottomAdd will offset the threshold towards the bottom
            // of the page.
            const amountScrolledDown = scrollTop - lastKnownScrollPosition;
            const adjustedDefault = defaultDownThreshold + adjustedBottomAdd;
            threshold = Math.max(adjustedDefault, threshold - amountScrolledDown);
        } else {
            // When scrolling up, move the threshold down towards the default
            // upwards threshold position. If near the bottom of the page,
            // quickly transition the threshold back up where it normally
            // belongs.
            const amountScrolledUp = lastKnownScrollPosition - scrollTop;
            const adjustedDefault = defaultUpThreshold - pixelsAbove
                + Math.max(0, adjustedBottomAdd - defaultDownThreshold);
            threshold = Math.min(adjustedDefault, threshold + amountScrolledUp);
        }

        if (documentHeight <= windowHeight) {
            threshold = 0;
        }

        if (thresholdDebug) {
            const id = 'mdbook-threshold-debug-data';
            let data = document.getElementById(id);
            if (data === null) {
                data = document.createElement('div');
                data.id = id;
                data.style.cssText = `
                    position: fixed;
                    top: 50px;
                    right: 10px;
                    background-color: 0xeeeeee;
                    z-index: 9999;
                    pointer-events: none;
                `;
                document.body.appendChild(data);
            }
            data.innerHTML = `
                <table>
                  <tr><td>documentHeight</td><td>${documentHeight.toFixed(1)}</td></tr>
                  <tr><td>windowHeight</td><td>${windowHeight.toFixed(1)}</td></tr>
                  <tr><td>scrollTop</td><td>${scrollTop.toFixed(1)}</td></tr>
                  <tr><td>pixelsAbove</td><td>${pixelsAbove.toFixed(1)}</td></tr>
                  <tr><td>pixelsBelow</td><td>${pixelsBelow.toFixed(1)}</td></tr>
                  <tr><td>bottomAdd</td><td>${bottomAdd.toFixed(1)}</td></tr>
                  <tr><td>adjustedBottomAdd</td><td>${adjustedBottomAdd.toFixed(1)}</td></tr>
                  <tr><td>scrollingDown</td><td>${scrollingDown}</td></tr>
                  <tr><td>threshold</td><td>${threshold.toFixed(1)}</td></tr>
                </table>
            `;
            drawDebugLine();
        }

        lastKnownScrollPosition = scrollTop;
    }

    function drawDebugLine() {
        if (!document.body) {
            return;
        }
        const id = 'mdbook-threshold-debug-line';
        const existingLine = document.getElementById(id);
        if (existingLine) {
            existingLine.remove();
        }
        const line = document.createElement('div');
        line.id = id;
        line.style.cssText = `
            position: fixed;
            top: ${threshold}px;
            left: 0;
            width: 100vw;
            height: 2px;
            background-color: red;
            z-index: 9999;
            pointer-events: none;
        `;
        document.body.appendChild(line);
    }

    function mdbookEnableThresholdDebug() {
        thresholdDebug = true;
        updateThreshold();
        drawDebugLine();
    }

    window.mdbookEnableThresholdDebug = mdbookEnableThresholdDebug;

    // Updates which headers in the sidebar should be expanded. If the current
    // header is inside a collapsed group, then it, and all its parents should
    // be expanded.
    function updateHeaderExpanded(currentA) {
        // Add expanded to all header-item li ancestors.
        let current = currentA.parentElement;
        while (current) {
            if (current.tagName === 'LI' && current.classList.contains('header-item')) {
                current.classList.add('expanded');
            }
            current = current.parentElement;
        }
    }

    // Updates which header is marked as the "current" header in the sidebar.
    // This is done with a virtual Y threshold, where headers at or below
    // that line will be considered the current one.
    function updateCurrentHeader() {
        if (!headers || !headers.length) {
            return;
        }

        // Reset the classes, which will be rebuilt below.
        const els = document.getElementsByClassName('current-header');
        for (const el of els) {
            el.classList.remove('current-header');
        }
        for (const toggle of headerToggles) {
            toggle.classList.remove('expanded');
        }

        // Find the last header that is above the threshold.
        let lastHeader = null;
        for (const header of headers) {
            const rect = header.getBoundingClientRect();
            if (rect.top <= threshold) {
                lastHeader = header;
            } else {
                break;
            }
        }
        if (lastHeader === null) {
            lastHeader = headers[0];
            const rect = lastHeader.getBoundingClientRect();
            const windowHeight = window.innerHeight;
            if (rect.top >= windowHeight) {
                return;
            }
        }

        // Get the anchor in the summary.
        const href = '#' + lastHeader.id;
        const a = [...document.querySelectorAll('.header-in-summary')]
            .find(element => element.getAttribute('href') === href);
        if (!a) {
            return;
        }

        a.classList.add('current-header');

        updateHeaderExpanded(a);
    }

    // Updates which header is "current" based on the threshold line.
    function reloadCurrentHeader() {
        if (disableScroll) {
            return;
        }
        updateThreshold();
        updateCurrentHeader();
    }


    // When clicking on a header in the sidebar, this adjusts the threshold so
    // that it is located next to the header. This is so that header becomes
    // "current".
    function headerThresholdClick(event) {
        // See disableScroll description why this is done.
        disableScroll = true;
        setTimeout(() => {
            disableScroll = false;
        }, 100);
        // requestAnimationFrame is used to delay the update of the "current"
        // header until after the scroll is done, and the header is in the new
        // position.
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                // Closest is needed because if it has child elements like <code>.
                const a = event.target.closest('a');
                const href = a.getAttribute('href');
                const targetId = href.substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    threshold = targetElement.getBoundingClientRect().bottom;
                    updateCurrentHeader();
                }
            });
        });
    }

    // Takes the nodes from the given head and copies them over to the
    // destination, along with some filtering.
    function filterHeader(source, dest) {
        const clone = source.cloneNode(true);
        clone.querySelectorAll('mark').forEach(mark => {
            mark.replaceWith(...mark.childNodes);
        });
        dest.append(...clone.childNodes);
    }

    // Scans page for headers and adds them to the sidebar.
    document.addEventListener('DOMContentLoaded', function() {
        const activeSection = document.querySelector('#mdbook-sidebar .active');
        if (activeSection === null) {
            return;
        }

        const main = document.getElementsByTagName('main')[0];
        headers = Array.from(main.querySelectorAll('h2, h3, h4, h5, h6'))
            .filter(h => h.id !== '' && h.children.length && h.children[0].tagName === 'A');

        if (headers.length === 0) {
            return;
        }

        // Build a tree of headers in the sidebar.

        const stack = [];

        const firstLevel = parseInt(headers[0].tagName.charAt(1));
        for (let i = 1; i < firstLevel; i++) {
            const ol = document.createElement('ol');
            ol.classList.add('section');
            if (stack.length > 0) {
                stack[stack.length - 1].ol.appendChild(ol);
            }
            stack.push({level: i + 1, ol: ol});
        }

        // The level where it will start folding deeply nested headers.
        const foldLevel = 3;

        for (let i = 0; i < headers.length; i++) {
            const header = headers[i];
            const level = parseInt(header.tagName.charAt(1));

            const currentLevel = stack[stack.length - 1].level;
            if (level > currentLevel) {
                // Begin nesting to this level.
                for (let nextLevel = currentLevel + 1; nextLevel <= level; nextLevel++) {
                    const ol = document.createElement('ol');
                    ol.classList.add('section');
                    const last = stack[stack.length - 1];
                    const lastChild = last.ol.lastChild;
                    // Handle the case where jumping more than one nesting
                    // level, which doesn't have a list item to place this new
                    // list inside of.
                    if (lastChild) {
                        lastChild.appendChild(ol);
                    } else {
                        last.ol.appendChild(ol);
                    }
                    stack.push({level: nextLevel, ol: ol});
                }
            } else if (level < currentLevel) {
                while (stack.length > 1 && stack[stack.length - 1].level > level) {
                    stack.pop();
                }
            }

            const li = document.createElement('li');
            li.classList.add('header-item');
            li.classList.add('expanded');
            if (level < foldLevel) {
                li.classList.add('expanded');
            }
            const span = document.createElement('span');
            span.classList.add('chapter-link-wrapper');
            const a = document.createElement('a');
            span.appendChild(a);
            a.href = '#' + header.id;
            a.classList.add('header-in-summary');
            filterHeader(header.children[0], a);
            a.addEventListener('click', headerThresholdClick);
            const nextHeader = headers[i + 1];
            if (nextHeader !== undefined) {
                const nextLevel = parseInt(nextHeader.tagName.charAt(1));
                if (nextLevel > level && level >= foldLevel) {
                    const toggle = document.createElement('a');
                    toggle.classList.add('chapter-fold-toggle');
                    toggle.classList.add('header-toggle');
                    toggle.addEventListener('click', () => {
                        li.classList.toggle('expanded');
                    });
                    const toggleDiv = document.createElement('div');
                    toggleDiv.textContent = '❱';
                    toggle.appendChild(toggleDiv);
                    span.appendChild(toggle);
                    headerToggles.push(li);
                }
            }
            li.appendChild(span);

            const currentParent = stack[stack.length - 1];
            currentParent.ol.appendChild(li);
        }

        const onThisPage = document.createElement('div');
        onThisPage.classList.add('on-this-page');
        onThisPage.append(stack[0].ol);
        const activeItemSpan = activeSection.parentElement;
        activeItemSpan.after(onThisPage);
    });

    document.addEventListener('DOMContentLoaded', reloadCurrentHeader);
    document.addEventListener('scroll', reloadCurrentHeader, { passive: true });
})();

