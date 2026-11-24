# Responsible use

Palisade is a **defensive** project. It exists to learn how application control stops unwanted
code from running on Windows, and how to explain and evidence that control. It is educational,
not a replacement for commercial application control products, and it should not be relied on to
protect production systems.

## Test files and scenarios are benign

Everything in this repository that is used to exercise a control is harmless:

- Test executables, scripts, libraries and installers only prove that they ran, for example by
  writing a marker file or printing a line. They do nothing else.
- Fixtures are built from source in this repository, or are well-known harmless files.
- Scenarios run on disposable virtual machines that you control ([#26](https://github.com/jusso-dev/palisade/issues/26)), never on machines you do
  not own.

If a test needs something that looks like attacker behaviour, such as a file in a user-writable
folder, an unsigned binary or an unusual parent process, it reproduces the *shape* of that
behaviour with a benign file. It never uses the real thing.

## Contributions that are rejected

Pull requests and issues that do any of the following are closed, and the content may be removed:

- **Offensive tooling**: code whose purpose is to attack systems, such as exploit chains, credential
  theft, persistence or lateral movement.
- **Real malware samples**, live or "defanged", including links to download them, and test
  signatures or hashes that only make sense for real samples.
- **Bypass weaponisation**: turning a way around a control, in Palisade or in any other product,
  into a ready-to-use tool, payload or step-by-step guide.
- Detection-evasion techniques presented as something to use, rather than as a gap to close.

Discussing *classes* of bypass in design documents and the
[threat model](security/threat-model.md) is fine and encouraged, as long as the aim is to defend
against them.

## Found a bypass?

If you find a way to run code that Palisade should block, tamper with it or escalate privileges
through it, **do not** open a public issue or pull request. Report it privately as described in
[SECURITY.md](../SECURITY.md). That page also covers scope and safe harbour for good-faith
research.

## Your responsibilities

- Only test on systems you own or are explicitly allowed to test.
- Follow the law and the policies of your organisation.
- Treat Palisade as a learning project. Test it on disposable machines first, and do not make it
  the only control protecting a system you care about.

Contributors also follow the [Code of Conduct](../CODE_OF_CONDUCT.md).
