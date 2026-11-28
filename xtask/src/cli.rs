//! The `cargo xtask` command line (#29), declared with clap.
//!
//! Every command, sub-command and flag is a variant or field here, so
//! `cargo xtask help`, `cargo xtask <command> --help` and parsing come from
//! one declaration. Values that need checking beyond their type (a target
//! triple, a signer name, a shard, the fuzz time) are checked by the
//! command's own module, as before, so its rules and their tests stay in
//! one place. `src/help.rs` snapshots the rendered help of every command.

// The doc comments here are also clap's help text, which shows placeholders
// as `<commit>` and `<dir>`. Escaping them for rustdoc would put the escapes
// into `--help`, so rustdoc's HTML check is turned off for this module only.
#![allow(
    rustdoc::invalid_html_tags,
    reason = "doc comments are clap help text with <placeholder> arguments"
)]

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Palisade repository automation.
#[derive(Debug, Parser)]
#[command(
    name = "cargo xtask",
    bin_name = "cargo xtask",
    about = "Palisade repository automation",
    disable_version_flag = true,
    help_expected = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Every command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// The ADR tooling (docs/adr/PROCESS.md)
    #[command(subcommand)]
    Adr(AdrCommand),
    /// Run cargo-audit over the root and fuzz lockfiles, ignoring exactly the advisories deny.toml
    /// ignores
    Audit,
    /// Run the checks from .github/workflows/ci.yml locally
    Ci {
        /// Skip coverage, fuzz, docs, the book build, feature-powerset, msrv, package, sign-test
        /// and server-image
        #[arg(long)]
        fast: bool,
    },
    /// Run every criterion bench at <commit> and at the working tree, and fail if a median is more
    /// than 10% slower outside the noise (bench.yml)
    BenchCompare(Base),
    /// Check a commit message file against Conventional Commits (the opt-in commit-msg hook in
    /// .githooks/ runs this)
    CheckCommitMsg {
        /// The commit message file
        file: PathBuf,
    },
    /// No commercial vendor or product names in any file or path (docs/banned-terms.txt,
    /// docs/NAMING.md)
    CheckBannedTerms {
        /// Print the list line for a new term instead of checking
        #[arg(long, value_name = "term")]
        digest: Option<String>,
    },
    /// Enforce the allowed dependency directions between crates
    CheckDeps,
    /// Check that every crates/*/fuzz/Cargo.lock is current (cargo metadata --locked)
    CheckFuzzLocks,
    /// Fail if any file in the repository that starts like an executable (MZ) is not allowlisted
    /// in testdata/manifest.txt
    CheckTestdata,
    /// Enforce workspace inheritance of package fields, lints and dependency versions, and that
    /// every crate README documents its features
    CheckManifests,
    /// Enforce the duplicate-version budget, deny.toml ignore expiry and reasons, the cargo-vet
    /// criteria and exemption notes, and no audit.toml
    CheckSupplyChain,
    /// Enforce the unsafe-code allowlist (unsafe-allowlist.txt, ADR 0011)
    CheckUnsafe,
    /// Release-build the Windows binaries (with --msi, the installer package) or the Linux server,
    /// with symbols and size reports, as CI does (docs/packaging.md)
    Dist(DistArgs),
    /// Authenticode-sign and verify files (docs/releasing.md#code-signing)
    Sign(SignArgs),
    /// The release pipeline's steps (docs/releasing.md)
    #[command(subcommand)]
    Release(ReleaseCommand),
    /// The documentation site (docs/ci.md#documentation-site)
    #[command(subcommand)]
    Docs(DocsCommand),
    /// Print the dependency report: duplicates, third-party crates per crate, third-party unsafe
    /// counts and code that runs at build time
    DepsReport {
        /// Only when Cargo.lock changed since <commit>, adding cargo tree -d and unsafe changes
        #[arg(long, value_name = "commit")]
        base: Option<String>,
    },
    /// Reserved for the SBOM (#226); prints where it will be written and fails
    Sbom,
    /// Enforce the CI runner and action policy for .github/workflows, and that nothing under
    /// .github names a cloud-managed build service
    CheckWorkflows,
    /// Check the threat model's tables, and that every test, fuzz target and CI check it cites
    /// exists (docs/security/threat-model.md)
    ThreatCoverage,
    /// Summarise a nextest JUnit report for the GitHub job page
    TestSummary {
        /// The label for the summary
        label: String,
        /// The JUnit report
        junit: PathBuf,
    },
    /// Summarise a cargo-llvm-cov JSON summary for the GitHub job page
    CoverageSummary {
        /// The label for the summary
        label: String,
        /// The JSON summary
        coverage: PathBuf,
    },
    /// Fail if palisade-policy line coverage is lower than at <commit>; needs cargo-llvm-cov and
    /// cargo-nextest
    CoverageGate(Base),
    /// Build the generated test fixture corpus into target/fixtures/
    Fixtures,
    /// Check the corpus's hashes against testdata/golden/fixtures.txt
    Golden {
        /// Rewrite testdata/golden/fixtures.txt instead of checking it
        #[arg(long)]
        update: bool,
    },
    /// Build every cargo-fuzz target, seed it from the test fixtures and run it; needs the pinned
    /// nightly and cargo-fuzz
    Fuzz(FuzzArgs),
}

/// `--base <commit>`, required.
#[derive(Debug, Args)]
pub struct Base {
    /// The commit to compare with
    #[arg(long, value_name = "commit")]
    pub base: String,
}

/// `adr` sub-commands.
#[derive(Debug, Subcommand)]
pub enum AdrCommand {
    /// Copy docs/adr/0000-template.md to the next ADR number, as `proposed`
    New {
        /// The ADR's title
        title: String,
    },
    /// Regenerate the ADR index table in docs/adr/README.md
    Index,
    /// Check every ADR's file name, number, status, date and sections (Security impact included),
    /// supersession links, and that the index is current
    Lint,
}

/// `dist` options. `dist driver` is the sub-command; without it, a build.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct DistArgs {
    #[command(subcommand)]
    pub command: Option<DistCommand>,
    /// The target triple (default: this machine's)
    #[arg(long, value_name = "triple")]
    pub target: Option<String>,
    /// Also build and validate the installer package (Windows targets)
    #[arg(long)]
    pub msi: bool,
    /// Sign the executables and package with this signer
    #[arg(long, value_name = "signer")]
    pub sign: Option<String>,
    /// Where to write the output
    #[arg(long, value_name = "dir")]
    pub out: Option<PathBuf>,
    /// Build as the next patch version (the package upgrade test)
    #[arg(long)]
    pub bump_patch: bool,
    /// Warn about size changes against this earlier size report
    #[arg(long, value_name = "sizes.json")]
    pub compare_sizes: Option<PathBuf>,
    /// Package these prebuilt (and signed) executables instead of building them (needs --msi)
    #[arg(long, value_name = "dir")]
    pub from: Option<PathBuf>,
    /// Sign without a timestamp server (the CI test of the signing path only)
    #[arg(long)]
    pub no_timestamp: bool,
}

/// `dist` sub-commands.
#[derive(Debug, Subcommand)]
pub enum DistCommand {
    /// Explain how the optional kernel driver is packaged (local-only, #8)
    Driver,
}

impl DistArgs {
    /// The arguments as `dist::parse_args` reads them, which checks the
    /// values and how they combine.
    pub fn to_words(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut flag = |name: &str, value: Option<String>| {
            if let Some(v) = value {
                out.push(name.to_owned());
                out.push(v);
            }
        };
        flag("--target", self.target.clone());
        flag("--sign", self.sign.clone());
        flag("--out", self.out.as_ref().map(|p| p.display().to_string()));
        flag(
            "--compare-sizes",
            self.compare_sizes.as_ref().map(|p| p.display().to_string()),
        );
        flag(
            "--from",
            self.from.as_ref().map(|p| p.display().to_string()),
        );
        for (set, name) in [
            (self.msi, "--msi"),
            (self.bump_patch, "--bump-patch"),
            (self.no_timestamp, "--no-timestamp"),
        ] {
            if set {
                out.push(name.to_owned());
            }
        }
        out
    }
}

/// `sign` options.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// The signer: none, test-ca, pfx or cloud-hsm
    #[arg(long, value_name = "signer", required = true)]
    pub signer: String,
    /// Only verify the files' signatures
    #[arg(long)]
    pub verify: bool,
    /// Sign without a timestamp server (the CI test of the signing path only)
    #[arg(long)]
    pub no_timestamp: bool,
    /// The files to sign
    #[arg(required = true, value_name = "file")]
    pub files: Vec<PathBuf>,
}

impl SignArgs {
    /// The arguments as `release::sign::parse_args` reads them.
    pub fn to_words(&self) -> Vec<String> {
        let mut out = vec!["--signer".to_owned(), self.signer.clone()];
        if self.verify {
            out.push("--verify".to_owned());
        }
        if self.no_timestamp {
            out.push("--no-timestamp".to_owned());
        }
        out.extend(self.files.iter().map(|f| f.display().to_string()));
        out
    }
}

/// `release` sub-commands.
#[derive(Debug, Subcommand)]
pub enum ReleaseCommand {
    /// Bump the version and write the changelog section (RELEASE_DATE gives the date)
    Prepare {
        /// The new version
        version: String,
    },
    /// Check that a tag names the workspace version
    CheckTag {
        /// The tag
        tag: String,
    },
    /// Print a version's release notes from CHANGELOG.md
    Notes {
        /// The version
        version: String,
    },
    /// Write SHA256SUMS for every file in a directory
    Checksums {
        /// The directory
        dir: PathBuf,
    },
    /// Check every file in a directory against its SHA256SUMS
    VerifyChecksums {
        /// The directory
        dir: PathBuf,
    },
    /// The provenance hook (does nothing until RELEASE_PROVENANCE is on)
    Provenance,
    /// Verify every signature in a directory, including inside packages
    Verify {
        /// The directory
        dir: PathBuf,
        /// Accept signatures without a timestamp
        #[arg(long)]
        allow_untimestamped: bool,
    },
}

/// `docs` sub-commands.
#[derive(Debug, Subcommand)]
pub enum DocsCommand {
    /// Regenerate the reference pages in docs/book/src/reference/generated
    Generate,
    /// Fail if the generated pages are stale, or a doc page is not in the book, is not accessible,
    /// or has an untested example
    Check,
    /// Build the book into target/book (warnings are errors), then check every internal link;
    /// needs mdbook, mdbook-mermaid-ssr, a headless browser and lychee
    Build {
        /// The published site's path, for absolute links
        #[arg(long, value_name = "path")]
        site_url: Option<String>,
    },
    /// Stage the book and serve it at http://127.0.0.1:3000/ with mdbook serve, until interrupted;
    /// run it again after editing a page (links are checked by docs build)
    Serve {
        /// The port to listen on, 1024 to 65535 (default 3000)
        #[arg(long, value_name = "n")]
        port: Option<String>,
        /// Open the book in a browser
        #[arg(long)]
        open: bool,
    },
    /// Assemble the GitHub Pages tree: the book and the Rust API docs under <dir>/<version>/, the
    /// version list and the root redirect
    Assemble {
        /// The output directory
        dir: PathBuf,
        /// The docs version
        #[arg(long, value_name = "latest|vX.Y")]
        version: String,
    },
    /// Print the docs version for a ref: latest for main, vX.Y for tag vX.Y.Z
    VersionForRef {
        /// The git ref
        #[arg(value_name = "git ref")]
        git_ref: String,
    },
}

/// `fuzz` options.
#[derive(Debug, Args)]
pub struct FuzzArgs {
    /// Seconds per target (default 60, at most 3600)
    #[arg(long, value_name = "N")]
    pub seconds: Option<String>,
    /// Only this target
    #[arg(long, value_name = "NAME", conflicts_with = "shard")]
    pub target: Option<String>,
    /// Only every N-th target starting at index I (as CI's shards do)
    #[arg(long, value_name = "I/N")]
    pub shard: Option<String>,
}

impl FuzzArgs {
    /// The arguments as `fuzz::parse_args` reads them.
    pub fn to_words(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, value) in [
            ("--seconds", &self.seconds),
            ("--target", &self.target),
            ("--shard", &self.shard),
        ] {
            if let Some(v) = value {
                out.push(name.to_owned());
                out.push(v.clone());
            }
        }
        out
    }
}
