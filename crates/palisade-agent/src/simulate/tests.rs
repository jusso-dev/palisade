use palisade_core::test_util::RecordingSink;
use palisade_proto::events::{Event, EventType, Outcome};

use super::{Scenario, run, scenario::DEFAULT};

fn default_events() -> Vec<Event> {
    let scenario = Scenario::from_toml(DEFAULT).unwrap();
    let mut sink = RecordingSink::new();
    let count = run(&scenario, &mut sink).unwrap();
    let events = sink.take();
    assert_eq!(u64::try_from(events.len()).unwrap(), count);
    events
}

#[test]
fn default_scenario_emits_valid_chained_events() {
    let events = default_events();
    let types: Vec<EventType> = events.iter().map(|e| e.event_type).collect();
    assert_eq!(types.first(), Some(&EventType::AgentStarted));
    assert_eq!(types.last(), Some(&EventType::AgentStopped));
    assert_eq!(
        types
            .iter()
            .filter(|t| **t == EventType::ExecDecision)
            .count(),
        5
    );
    for (i, event) in events.iter().enumerate() {
        event.validate().unwrap();
        assert_eq!(event.seq, u64::try_from(i).unwrap());
        assert_eq!(event.prev_hash.is_some(), i > 0);
        // The canonical form round-trips through the strict reader.
        let json = event.to_canonical_json().unwrap();
        assert_eq!(&Event::from_json(&json).unwrap(), event);
    }
    // Timestamps and monotonic time move forwards; event IDs are unique.
    for pair in events.windows(2) {
        assert!(pair[0].ts < pair[1].ts);
        assert!(pair[0].ts_agent_monotonic < pair[1].ts_agent_monotonic);
        assert_ne!(pair[0].event_id, pair[1].event_id);
    }
}

#[test]
fn simulation_is_deterministic() {
    assert_eq!(default_events(), default_events());
}

#[test]
fn exec_events_carry_process_user_file_and_ancestry() {
    let events = default_events();
    let tool = events
        .iter()
        .find(|e| {
            e.process
                .as_ref()
                .and_then(|p| p.image_path.as_ref())
                .is_some_and(|p| p.as_str().ends_with("tool.exe"))
        })
        .unwrap();
    let process = tool.process.as_ref().unwrap();
    assert_eq!(process.pid, Some(6344));
    assert!(
        process
            .cmdline
            .as_ref()
            .unwrap()
            .as_str()
            .ends_with("--version")
    );
    let parent = process.parent.as_ref().unwrap();
    assert_eq!(parent.pid, Some(6200));
    assert!(
        parent
            .image_path
            .as_ref()
            .unwrap()
            .as_str()
            .ends_with("cmd.exe")
    );
    let grandparent = process.grandparent.as_ref().unwrap();
    assert_eq!(grandparent.pid, Some(5120));
    assert_eq!(
        process.signers.as_slice()[0]
            .publisher
            .as_ref()
            .unwrap()
            .as_str(),
        "Example Software Ltd"
    );
    let user = tool.user.as_ref().unwrap();
    assert_eq!(user.name.as_ref().unwrap().as_str(), "alice");
    let file = tool.file.as_ref().unwrap();
    assert!(file.hashes.sha256.is_some());
    assert!(file.size.unwrap() > 0);
    assert_eq!(tool.host.name.as_ref().unwrap().as_str(), "SIM-0001");
    assert_eq!(
        tool.host.fqdn.as_ref().unwrap().as_str(),
        "SIM-0001.example.test"
    );
}

#[test]
fn a_reused_process_id_does_not_inherit_the_old_ancestry() {
    let events = default_events();
    let wmi = events
        .iter()
        .find(|e| e.process.as_ref().and_then(|p| p.pid) == Some(8100))
        .unwrap();
    let process = wmi.process.as_ref().unwrap();
    let parent = process.parent.as_ref().unwrap();
    assert_eq!(parent.pid, Some(6200));
    assert!(
        parent
            .image_path
            .as_ref()
            .unwrap()
            .as_str()
            .ends_with("svchost.exe")
    );
    // The grandparent is the service control manager, not explorer.exe,
    // which was the parent of the shell that used to have ID 6200.
    assert_eq!(process.grandparent.as_ref().unwrap().pid, Some(744));
}

#[test]
fn outcomes_and_severity_follow_the_scenario() {
    let events = default_events();
    let setup = events
        .iter()
        .find(|e| e.process.as_ref().and_then(|p| p.pid) == Some(7020))
        .unwrap();
    assert_eq!(setup.outcome, Outcome::Audited);
    assert!(setup.severity.get() > EventType::ExecDecision.default_severity().get());
    assert!(setup.file.as_ref().unwrap().signers.is_empty());
}

#[test]
fn a_full_sink_stops_the_simulation() {
    let scenario = Scenario::from_toml(DEFAULT).unwrap();
    let mut sink = RecordingSink::with_capacity(2);
    let err = run(&scenario, &mut sink).unwrap_err();
    assert!(err.0.contains("full"), "{err}");
    assert_eq!(sink.events().len(), 2);
}

fn with_step(extra: &str) -> String {
    format!("{DEFAULT}\n{extra}")
}

#[test]
fn bad_scenarios_are_rejected() {
    for (source, expect) in [
        ("start = 1", "invalid type"),
        (&with_step("bogus = 1") as &str, "unknown field"),
        (
            &with_step("[[step]]\npid = 9\nimage = 'a'\nuser = 'S-1-5-99'\noutcome = 'allowed'"),
            "not declared",
        ),
        (
            &with_step("[[step]]\npid = 8100\nimage = 'a'\nuser = 'S-1-5-18'\noutcome = 'allowed'"),
            "already running",
        ),
        (
            &with_step(
                "[[step]]\npid = 9\nexited = [12345]\nimage = 'a'\nuser = 'S-1-5-18'\noutcome = 'allowed'",
            ),
            "not running",
        ),
        (
            &with_step("[[step]]\npid = 9\nimage = 'a'\nuser = 'S-1-5-18'\noutcome = 'maybe'"),
            "unknown outcome",
        ),
        (
            &with_step(
                "[[step]]\npid = 9\nafter_ms = 86400001\nimage = 'a'\nuser = 'S-1-5-18'\noutcome = 'allowed'",
            ),
            "after_ms",
        ),
        (
            &DEFAULT.replace("mode = \"audit\"", "mode = \"loud\""),
            "unknown mode",
        ),
        (
            &DEFAULT.replace("session = \"console\"", "session = \"tty\""),
            "unknown session",
        ),
    ] {
        let err = Scenario::from_toml(source).unwrap_err();
        assert!(err.0.contains(expect), "{expect}: got {err}");
    }
}

#[test]
fn schema_violations_are_reported_not_panicked() {
    let bad_sid = DEFAULT.replace("S-1-5-18", "not-a-sid");
    let scenario = Scenario::from_toml(&bad_sid).unwrap();
    let mut sink = RecordingSink::new();
    assert!(run(&scenario, &mut sink).is_err());

    let bad_version = DEFAULT.replace("10.0.26100.2314", "10.0");
    let scenario = Scenario::from_toml(&bad_version).unwrap();
    assert!(run(&scenario, &mut RecordingSink::new()).is_err());

    let bad_arch = DEFAULT.replace("architecture = \"x64\"", "architecture = \"sparc\"");
    let scenario = Scenario::from_toml(&bad_arch).unwrap();
    assert!(run(&scenario, &mut RecordingSink::new()).is_err());
}

#[test]
fn json_lines_writes_one_canonical_event_per_line() {
    use palisade_core::platform::EventSink as _;
    let events = default_events();
    let mut out = Vec::new();
    let mut sink = super::JsonLines(&mut out);
    for e in &events {
        sink.emit(e.clone()).unwrap();
    }
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), events.len());
    for (line, event) in lines.iter().zip(&events) {
        assert_eq!(&Event::from_json(line).unwrap(), event);
    }
}

#[test]
fn oversized_and_missing_scenario_files_are_rejected() {
    let dir = std::env::temp_dir().join(format!("palisade-sim-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let big = dir.join("big.toml");
    let limit = usize::try_from(super::scenario::MAX_SCENARIO_BYTES).unwrap();
    std::fs::write(&big, "#".repeat(limit + 1)).unwrap();
    assert!(Scenario::load(&big).unwrap_err().0.contains("larger than"));
    assert!(Scenario::load(&dir.join("absent.toml")).is_err());
    let ok = dir.join("ok.toml");
    std::fs::write(&ok, DEFAULT).unwrap();
    assert!(Scenario::load(&ok).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reusing_an_id_with_no_delay_still_gives_a_new_process() {
    let source = format!(
        "{DEFAULT}\n[[step]]\nafter_ms = 0\nexited = [8100]\npid = 8100\nparent = 744\n\
         image = 'C:\\\\other.exe'\nuser = 'S-1-5-18'\noutcome = 'allowed'\n"
    );
    let scenario = Scenario::from_toml(&source).unwrap();
    let mut sink = RecordingSink::new();
    run(&scenario, &mut sink).unwrap();
    let keys: Vec<_> = sink
        .events()
        .iter()
        .filter_map(|e| e.process.as_ref())
        .filter(|p| p.pid == Some(8100))
        .map(|p| p.process_key.clone().unwrap())
        .collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn an_unsigned_step_does_not_inherit_an_earlier_signature() {
    let source = format!(
        "{DEFAULT}\n[[step]]\nexited = [6344]\npid = 6345\nparent = 744\n\
         image = 'C:\\\\Program Files\\\\Example\\\\tool.exe'\nuser = 'S-1-5-18'\noutcome = 'allowed'\n"
    );
    let scenario = Scenario::from_toml(&source).unwrap();
    let mut sink = RecordingSink::new();
    run(&scenario, &mut sink).unwrap();
    let last = sink
        .events()
        .iter()
        .rev()
        .find_map(|e| e.process.as_ref())
        .unwrap();
    assert_eq!(last.pid, Some(6345));
    assert!(last.signers.is_empty());
}
