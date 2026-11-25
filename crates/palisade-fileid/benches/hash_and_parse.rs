//! Benchmarks for flat hashing, streaming file hashing, PE parsing, and
//! each tier of the file identity record (#55).
//!
//! ```sh
//! cargo bench -p palisade-fileid --bench hash_and_parse
//! ```
//!
//! CI only builds and smoke-runs this (`cargo test --bench hash_and_parse`), because
//! timings on shared hosted runners are too noisy to compare (docs/testing.md).
//! Inputs are synthetic and built here: 1 MiB of bytes for hashing, and the
//! same small PE image the property tests use for parsing, and that image
//! padded to 1 MiB with an overlay for the identity tiers. The 50 MB, 100
//! MB and 1 GB file sizes from #25 and #55 stay a local, on-demand run.

// `criterion_group!` generates an undocumented public function.
#![allow(missing_docs)]
// Bench code: fixture sizes are small constants, and a failed fixture build
// should panic loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;
use std::io::Cursor;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use palisade_fileid::authenticode::hash::hash_pe;
use palisade_fileid::hash::{AlgorithmSet, HashOptions, hash_bytes, hash_reader};
use palisade_fileid::identity::{IdentityContext, Tier, Tiers, identify_bytes};
use palisade_fileid::pe::{self, ParseOptions};

const MIB: usize = 1024 * 1024;

fn hashing(c: &mut Criterion) {
    let data: Vec<u8> = (0..MIB).map(|i| (i % 251) as u8).collect();
    let mut group = c.benchmark_group("hash_1mib");
    group.throughput(Throughput::Bytes(data.len() as u64));
    for (name, set) in [
        ("sha256", AlgorithmSet::SHA256),
        ("default_set", AlgorithmSet::DEFAULT),
        ("all", AlgorithmSet::ALL),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| black_box(hash_bytes(black_box(&data), set)))
        });
    }
    // The streaming path that `hash_file` uses, over an in-memory reader.
    let options = HashOptions::default();
    group.bench_function("streamed_default_set", |b| {
        b.iter(|| black_box(hash_reader(Cursor::new(black_box(&data)), &options).unwrap()));
    });
    group.finish();
}

fn parsing(c: &mut Criterion) {
    let version = common::VersionSpec {
        fixed: Some(common::fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", common::all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    let image = common::with_version(&version).build();
    assert!(pe::parse(&image).is_ok(), "the bench image must parse");
    let mut group = c.benchmark_group("pe");
    group.throughput(Throughput::Bytes(image.len() as u64));
    group.bench_function("parse_full", |b| {
        b.iter(|| black_box(pe::parse(black_box(&image))));
    });
    let metadata_only = ParseOptions::metadata_only();
    group.bench_function("parse_metadata_only", |b| {
        b.iter(|| black_box(pe::parse_with(black_box(&image), &metadata_only)));
    });
    group.bench_function("authenticode_hash", |b| {
        b.iter(|| black_box(hash_pe(black_box(&image), AlgorithmSet::EMPTY)));
    });
    group.finish();
}

fn identity_tiers(c: &mut Criterion) {
    let version = common::VersionSpec {
        fixed: Some(common::fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", common::all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    };
    let small = common::with_version(&version).build();
    let mut large = common::with_version(&version);
    large.overlay = (0..MIB).map(|i| (i % 251) as u8).collect();
    let large = large.build();
    let ctx = IdentityContext::untrusted(1_795_564_800);
    for (label, image) in [("identity_small", &small), ("identity_1mib", &large)] {
        let mut group = c.benchmark_group(label);
        group.throughput(Throughput::Bytes(image.len() as u64));
        for tier in Tier::ALL {
            group.bench_function(tier.name(), |b| {
                b.iter(|| {
                    black_box(identify_bytes(
                        black_box(image),
                        Some("a.exe"),
                        tier.into(),
                        &ctx,
                    ))
                });
            });
        }
        group.bench_function("all", |b| {
            b.iter(|| {
                black_box(identify_bytes(
                    black_box(image),
                    Some("a.exe"),
                    Tiers::ALL,
                    &ctx,
                ))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, hashing, parsing, identity_tiers);
criterion_main!(benches);
