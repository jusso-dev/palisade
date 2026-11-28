//! The event-log ingest chain's fuzz seeds (#58).

// Test code: helpers outside `#[test]` functions may unwrap or expect, since
// a failure there should fail the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use palisade_agent::eventlog::os_ids::EVENT_NS as NS;

fn ci(event_id: u32, data: &[(&str, &str)]) -> String {
    let data: String = data
        .iter()
        .map(|(k, v)| format!("<Data Name=\"{k}\">{v}</Data>"))
        .collect();
    format!(
        "<Event xmlns=\"{NS}\"><System><Provider Name=\"X-Windows-CodeIntegrity\"/>\
         <EventID>{event_id}</EventID><TimeCreated SystemTime=\"2026-11-24T03:15:22.1234567Z\"/>\
         <EventRecordID>1</EventRecordID>\
         <Correlation ActivityID=\"{{A244370E-44C9-4C06-B551-F6016E563076}}\"/>\
         <Execution ProcessID=\"4\" ThreadID=\"8\"/><Security UserID=\"S-1-5-18\"/>\
         </System><EventData>{data}</EventData></Event>"
    )
}

/// Seeds for the `eventlog_records` fuzz target: one byte for the source,
/// then rendered XML.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR=target/seeds \
///     cargo test -p palisade-agent --test eventlog -- --ignored write_eventlog_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_eventlog_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let seeds = [
        (
            0_u8,
            ci(
                3076,
                &[
                    ("File Name", "\\Device\\HarddiskVolume3\\t\\a.exe"),
                    ("Requested Signing Level", "2"),
                    ("Validated Signing Level", "1"),
                    ("Status", "0xc0e90002"),
                    ("SI Signing Scenario", "1"),
                    ("TotalSignatureCount", "0"),
                ],
            ),
        ),
        (
            0,
            ci(3099, &[("PolicyIdBuffer", "Base"), ("Options", "0x10004")]),
        ),
        (
            1,
            format!(
                "<Event xmlns=\"{NS}\"><System><EventID>8004</EventID>\
                 <TimeCreated SystemTime=\"2026-11-24T03:15:22Z\"/></System>\
                 <UserData><RuleAndFileData><PolicyNameBuffer>EXE</PolicyNameBuffer>\
                 <FullFilePathBuffer>C:\\t\\a.exe</FullFilePathBuffer>\
                 <TargetProcessId>7</TargetProcessId></RuleAndFileData></UserData></Event>"
            ),
        ),
        (
            2,
            format!(
                "<Event xmlns=\"{NS}\"><System><EventID>16387</EventID>\
                 <TimeCreated SystemTime=\"2026-11-24T03:15:22Z\"/></System>\
                 <EventData><Data Name=\"Title\">t</Data></EventData></Event>"
            ),
        ),
    ];
    for (i, (source, xml)) in seeds.iter().enumerate() {
        let mut bytes = vec![*source];
        bytes.extend_from_slice(xml.as_bytes());
        std::fs::write(dir.join(format!("seed-{i}")), bytes).unwrap();
    }
}
