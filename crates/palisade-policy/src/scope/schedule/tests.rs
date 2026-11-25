//! Schedule tests: midnight wrap, DST in both hemispheres, half-hour and
//! 45-minute zones, holidays, dates and the three time-zone bases.

use jiff::civil;
use jiff::tz::TimeZone;
use proptest::prelude::*;

use super::*;
use crate::scope::facts::TrustedTime;
use crate::scope::model::{Date, DateRange, TimeOfDay, Weekday as W, Window};

fn tz(name: &str) -> TimeZone {
    TimeZone::get(name).unwrap()
}

fn utc() -> TimeZone {
    TimeZone::UTC
}
fn sydney() -> TimeZone {
    tz("Australia/Sydney")
}
fn new_york() -> TimeZone {
    tz("America/New_York")
}

fn t(s: &str) -> TimeOfDay {
    s.parse().unwrap()
}

fn d(s: &str) -> Date {
    s.parse().unwrap()
}

fn window(days: &[W], start: &str, end: &str) -> Window {
    Window {
        days: days.to_vec(),
        start: t(start),
        end: Some(t(end)),
        duration_mins: None,
    }
}

fn compile(windows: Vec<Window>) -> CompiledSchedule {
    CompiledSchedule::compile(
        &Schedule {
            windows,
            ..Schedule::default()
        },
        TimeZoneBasis::Utc,
    )
}

/// Every instant, on a minute, whose local time in `tz` is the one given.
/// None if it is skipped, two if it repeats. Found by scanning, not by the
/// library's resolver, so the tests check that resolver too.
fn occurrences(tz: &TimeZone, y: i16, mo: i8, day: i8, h: i8, mi: i8) -> Vec<i64> {
    let want = civil::date(y, mo, day).at(h, mi, 0, 0);
    // The local time is within a day of the same reading in UTC.
    let base = as_utc(want);
    (-1560..=1560)
        .map(|m| base + m * 60)
        .filter(|&t| local(tz, t) == want)
        .collect()
}

/// A local time read as if it were UTC, in seconds.
fn as_utc(dt: civil::DateTime) -> i64 {
    TimeZone::UTC
        .to_ambiguous_timestamp(dt)
        .unambiguous()
        .unwrap()
        .as_second()
}

/// The local time of an instant in `tz`.
fn local(tz: &TimeZone, t: i64) -> civil::DateTime {
    tz.to_datetime(jiff::Timestamp::from_second(t).unwrap())
}

/// The first instant of a local time that exists.
fn instant(tz: &TimeZone, y: i16, mo: i8, day: i8, h: i8, mi: i8) -> i64 {
    occurrences(tz, y, mo, day, h, mi)[0]
}

fn active(s: &CompiledSchedule, tz: &TimeZone, at: i64) -> bool {
    s.is_active(at, tz).unwrap()
}

const WEEK: [W; 7] = [W::Mon, W::Tue, W::Wed, W::Thu, W::Fri, W::Sat, W::Sun];

#[test]
fn boundaries_include_the_start_and_exclude_the_end() {
    let s = compile(vec![window(&WEEK, "09:00", "17:00")]);
    let start = instant(&utc(), 2026, 3, 2, 9, 0);
    let end = instant(&utc(), 2026, 3, 2, 17, 0);
    assert!(!active(&s, &utc(), start - 1));
    assert!(active(&s, &utc(), start));
    assert!(active(&s, &utc(), end - 1));
    assert!(!active(&s, &utc(), end));
}

#[test]
fn windows_wrap_midnight_and_belong_to_their_start_day() {
    // Friday 22:00 to 06:00: active into Saturday morning, but not Friday
    // morning (that belongs to Thursday, which is not listed).
    let s = compile(vec![window(&[W::Fri], "22:00", "06:00")]);
    // 2026-03-06 is a Friday.
    assert!(!active(&s, &utc(), instant(&utc(), 2026, 3, 6, 5, 59)));
    assert!(active(&s, &utc(), instant(&utc(), 2026, 3, 6, 22, 0)));
    assert!(active(&s, &utc(), instant(&utc(), 2026, 3, 7, 0, 0)));
    assert!(active(&s, &utc(), instant(&utc(), 2026, 3, 7, 5, 59)));
    assert!(!active(&s, &utc(), instant(&utc(), 2026, 3, 7, 6, 0)));
    // Equal start and end is a full day.
    let full = compile(vec![window(&[W::Mon], "08:00", "08:00")]);
    assert!(active(&full, &utc(), instant(&utc(), 2026, 3, 3, 7, 59)));
    assert!(!active(&full, &utc(), instant(&utc(), 2026, 3, 3, 8, 0)));
    // 24:00 is the end of the day.
    let evening = compile(vec![window(&[W::Mon], "18:00", "24:00")]);
    assert!(active(
        &evening,
        &utc(),
        instant(&utc(), 2026, 3, 2, 23, 59)
    ));
    assert!(!active(&evening, &utc(), instant(&utc(), 2026, 3, 3, 0, 0)));
}

#[test]
fn durations_run_for_elapsed_time_across_days() {
    let s = CompiledSchedule::compile(
        &Schedule {
            windows: vec![Window {
                days: vec![W::Sun],
                start: t("20:00"),
                end: None,
                duration_mins: Some(36 * 60),
            }],
            ..Schedule::default()
        },
        TimeZoneBasis::Utc,
    );
    // 2026-03-08 is a Sunday; the window ends Tuesday 08:00.
    assert!(active(&s, &utc(), instant(&utc(), 2026, 3, 9, 12, 0)));
    assert!(active(&s, &utc(), instant(&utc(), 2026, 3, 10, 7, 59)));
    assert!(!active(&s, &utc(), instant(&utc(), 2026, 3, 10, 8, 0)));
}

#[test]
fn sydney_clocks_going_back_lengthen_the_window() {
    // DST ends 2026-04-05 at 03:00 AEDT, which becomes 02:00 AEST: 02:00 to
    // 03:00 happens twice. 01:00 to 04:00 lasts four hours that day.
    let s = compile(vec![window(&WEEK, "01:00", "04:00")]);
    let start = instant(&sydney(), 2026, 4, 5, 1, 0);
    let end = instant(&sydney(), 2026, 4, 5, 4, 0);
    assert_eq!(end - start, 4 * 3600);
    assert!(active(&s, &sydney(), start));
    // Both 02:30s are inside.
    let both = occurrences(&sydney(), 2026, 4, 5, 2, 30);
    assert_eq!(both.len(), 2);
    let second = both[1];
    assert!(active(&s, &sydney(), second));
    assert!(active(&s, &sydney(), end - 1));
    assert!(!active(&s, &sydney(), end));
}

#[test]
fn ambiguous_times_mean_the_first_occurrence() {
    // A window that starts at 02:30 on the day clocks go back starts at the
    // first 02:30, and one that ends at 02:30 ends then too.
    let starts = compile(vec![window(&[W::Sun], "02:30", "05:00")]);
    let first = instant(&sydney(), 2026, 4, 5, 2, 30);
    assert!(!active(&starts, &sydney(), first - 1));
    assert!(active(&starts, &sydney(), first));
    let ends = compile(vec![window(&[W::Sun], "00:00", "02:30")]);
    assert!(active(&ends, &sydney(), first - 1));
    assert!(!active(&ends, &sydney(), first));
    // The second 02:30 is an hour later and outside.
    assert!(!active(&ends, &sydney(), first + 3600));
}

#[test]
fn skipped_times_move_forward_by_the_gap() {
    // DST starts 2026-10-04 at 02:00 AEST, which becomes 03:00 AEDT. 02:30
    // does not exist; it is read as 03:30.
    let s = compile(vec![window(&[W::Sun], "02:30", "06:00")]);
    assert!(occurrences(&sydney(), 2026, 10, 4, 2, 30).is_empty());
    let three = instant(&sydney(), 2026, 10, 4, 3, 0);
    let three_thirty = instant(&sydney(), 2026, 10, 4, 3, 30);
    assert!(!active(&s, &sydney(), three));
    assert!(!active(&s, &sydney(), three_thirty - 1));
    assert!(active(&s, &sydney(), three_thirty));
    // A window over the gap lasts an hour less.
    let over = compile(vec![window(&[W::Sun], "01:00", "04:00")]);
    let start = instant(&sydney(), 2026, 10, 4, 1, 0);
    let end = instant(&sydney(), 2026, 10, 4, 4, 0);
    assert_eq!(end - start, 2 * 3600);
    assert!(active(&over, &sydney(), end - 1));
    assert!(!active(&over, &sydney(), end));
}

#[test]
fn new_york_transitions_are_the_other_way_round() {
    // 2026-03-08: 02:00 EST becomes 03:00 EDT.
    let s = compile(vec![window(&WEEK, "02:15", "02:45")]);
    // Both ends are skipped and move to 03:15 and 03:45.
    assert!(active(
        &s,
        &new_york(),
        instant(&new_york(), 2026, 3, 8, 3, 15)
    ));
    assert!(!active(
        &s,
        &new_york(),
        instant(&new_york(), 2026, 3, 8, 3, 45)
    ));
    // 2026-11-01: 02:00 EDT becomes 01:00 EST, so 01:30 happens twice.
    let late = compile(vec![window(&WEEK, "01:30", "03:00")]);
    let first = instant(&new_york(), 2026, 11, 1, 1, 30);
    assert!(active(&late, &new_york(), first));
    assert!(active(&late, &new_york(), first + 3600));
    let end = instant(&new_york(), 2026, 11, 1, 3, 0);
    assert_eq!(end - first, 2 * 3600 + 30 * 60);
}

#[test]
fn half_hour_and_45_minute_offsets() {
    let s = compile(vec![window(&WEEK, "09:00", "17:00")]);
    for name in [
        "Australia/Adelaide",
        "Asia/Kathmandu",
        "Asia/Kolkata",
        "Australia/Lord_Howe",
    ] {
        let tz = &tz(name);
        let start = instant(tz, 2026, 7, 1, 9, 0);
        assert!(!active(&s, tz, start - 1), "{name}");
        assert!(active(&s, tz, start), "{name}");
        assert!(active(&s, tz, instant(tz, 2026, 7, 1, 16, 59)), "{name}");
        assert!(!active(&s, tz, instant(tz, 2026, 7, 1, 17, 0)), "{name}");
    }
    // Kathmandu is UTC+05:45: 09:00 local is 03:15 UTC.
    assert_eq!(
        instant(&tz("Asia/Kathmandu"), 2026, 7, 1, 9, 0),
        instant(&utc(), 2026, 7, 1, 3, 15)
    );
    // Lord Howe moves by 30 minutes at DST: 2026-10-04 02:00 becomes 02:30.
    let gap = compile(vec![window(&[W::Sun], "02:10", "05:00")]);
    let moved = instant(&tz("Australia/Lord_Howe"), 2026, 10, 4, 2, 40);
    assert!(!active(&gap, &tz("Australia/Lord_Howe"), moved - 1));
    assert!(active(&gap, &tz("Australia/Lord_Howe"), moved));
}

#[test]
fn dates_and_holidays_use_the_local_date() {
    let s = CompiledSchedule::compile(
        &Schedule {
            windows: vec![window(&WEEK, "08:00", "18:00")],
            dates: vec![DateRange {
                from: d("2026-12-01"),
                to: Some(d("2026-12-31")),
            }],
            except_dates: vec![DateRange {
                from: d("2026-12-25"),
                to: Some(d("2026-12-26")),
            }],
            ..Schedule::default()
        },
        TimeZoneBasis::DeviceLocal,
    );
    assert!(active(
        &s,
        &sydney(),
        instant(&sydney(), 2026, 12, 24, 9, 0)
    ));
    assert!(!active(
        &s,
        &sydney(),
        instant(&sydney(), 2026, 12, 25, 9, 0)
    ));
    assert!(!active(
        &s,
        &sydney(),
        instant(&sydney(), 2026, 12, 26, 9, 0)
    ));
    assert!(active(
        &s,
        &sydney(),
        instant(&sydney(), 2026, 12, 31, 17, 59)
    ));
    assert!(!active(&s, &sydney(), instant(&sydney(), 2027, 1, 4, 9, 0)));
    assert!(!active(
        &s,
        &sydney(),
        instant(&sydney(), 2026, 11, 30, 9, 0)
    ));
    // 2026-12-25 09:00 in Sydney is still 24 December in New York.
    let christmas_sydney = instant(&sydney(), 2026, 12, 25, 9, 0);
    assert!(!active(&s, &sydney(), christmas_sydney));
    let ny = compile(vec![]);
    assert!(active(&ny, &new_york(), christmas_sydney));
}

#[test]
fn a_holiday_cuts_a_window_that_wraps_into_it() {
    let s = CompiledSchedule::compile(
        &Schedule {
            windows: vec![window(&WEEK, "20:00", "04:00")],
            except_dates: vec![DateRange {
                from: d("2026-12-25"),
                to: None,
            }],
            ..Schedule::default()
        },
        TimeZoneBasis::Utc,
    );
    assert!(active(&s, &utc(), instant(&utc(), 2026, 12, 24, 23, 59)));
    assert!(!active(&s, &utc(), instant(&utc(), 2026, 12, 25, 0, 0)));
    let close = s
        .closes_at(instant(&utc(), 2026, 12, 24, 21, 0), &utc())
        .unwrap();
    assert_eq!(close, instant(&utc(), 2026, 12, 25, 0, 0));
}

#[test]
fn closes_at_finds_the_end_of_overlapping_windows() {
    let s = compile(vec![
        window(&WEEK, "09:00", "12:00"),
        window(&WEEK, "11:00", "14:00"),
        window(&WEEK, "14:00", "15:00"),
    ]);
    let at = instant(&utc(), 2026, 3, 2, 9, 30);
    assert_eq!(
        s.closes_at(at, &utc()),
        Some(instant(&utc(), 2026, 3, 2, 15, 0))
    );
    assert_eq!(
        s.closes_at(instant(&utc(), 2026, 3, 2, 16, 0), &utc()),
        None
    );
    // A schedule that never closes has no close time.
    assert_eq!(compile(vec![]).closes_at(at, &utc()), None);
}

fn facts(time: Option<TrustedTime>, device: Option<&str>, session: Option<&str>) -> ScopeFacts {
    ScopeFacts {
        time,
        device_time_zone: device.map(str::to_owned),
        session_time_zone: session.map(str::to_owned),
        ..ScopeFacts::default()
    }
}

#[test]
fn the_three_time_zone_bases() {
    let schedule = |basis| {
        CompiledSchedule::compile(
            &Schedule {
                timezone_basis: Some(basis),
                windows: vec![window(&WEEK, "09:00", "17:00")],
                ..Schedule::default()
            },
            TimeZoneBasis::DeviceLocal,
        )
    };
    // 10:00 in Sydney is 23:00 UTC the day before, and 19:00 in New York.
    let at = instant(&sydney(), 2026, 7, 1, 10, 0);
    let time = Some(TrustedTime {
        unix_secs: at,
        trusted: true,
    });
    let f = facts(time, Some("Australia/Sydney"), Some("America/New_York"));
    let eval = |basis| schedule(basis).eval(&f, true, Bias::Permissive);
    assert_eq!(eval(TimeZoneBasis::DeviceLocal).0, Tri::Match);
    assert_eq!(eval(TimeZoneBasis::Utc).0, Tri::NoMatch);
    assert_eq!(eval(TimeZoneBasis::UserLocal).0, Tri::NoMatch);
    // Without the session's zone, user_local falls back to the device's.
    let no_session = facts(time, Some("Australia/Sydney"), None);
    let (r, notes) = schedule(TimeZoneBasis::UserLocal).eval(&no_session, true, Bias::Permissive);
    assert_eq!(r, Tri::Match);
    assert!(notes.contains(ScopeNote::TimezoneFallback));
    // The policy's basis applies when the schedule sets none.
    let inherit = CompiledSchedule::compile(
        &Schedule {
            windows: vec![window(&WEEK, "09:00", "17:00")],
            ..Schedule::default()
        },
        TimeZoneBasis::Utc,
    );
    assert_eq!(inherit.eval(&f, true, Bias::Permissive).0, Tri::NoMatch);
}

#[test]
fn untrusted_clocks_keep_allows_inactive_and_denies_active() {
    let s = compile(vec![window(&WEEK, "09:00", "17:00")]);
    let inside = instant(&utc(), 2026, 3, 2, 10, 0);
    for f in [
        facts(
            Some(TrustedTime {
                unix_secs: inside,
                trusted: false,
            }),
            None,
            None,
        ),
        facts(None, None, None),
    ] {
        let (allow, notes) = s.eval(&f, true, Bias::Permissive);
        assert_eq!(allow, Tri::NoMatch);
        assert!(notes.contains(ScopeNote::ClockUntrusted));
        assert_eq!(s.eval(&f, true, Bias::Restrictive).0, Tri::Match);
        // Under `negate`, the reading flips so the outcome is the same.
        assert_eq!(s.eval(&f, false, Bias::Permissive).0, Tri::Match);
        assert_eq!(s.eval(&f, false, Bias::Restrictive).0, Tri::NoMatch);
    }
    // An unknown or malformed zone reads the same way.
    let device = CompiledSchedule::compile(
        &Schedule {
            windows: vec![window(&WEEK, "09:00", "17:00")],
            ..Schedule::default()
        },
        TimeZoneBasis::DeviceLocal,
    );
    let time = Some(TrustedTime {
        unix_secs: inside,
        trusted: true,
    });
    for zone in [None, Some("Mars/Olympus_Mons")] {
        let (r, notes) = device.eval(&facts(time, zone, None), true, Bias::Permissive);
        assert_eq!(r, Tri::NoMatch);
        assert!(notes.contains(ScopeNote::ClockUntrusted));
    }
}

/// A slow reference: is any window that covers `at` started on a day in
/// the week before? Its ends are found by scanning instants
/// ([`compatible`]), not by the library's resolver.
fn reference(windows: &[(u8, u16, u16)], at: i64, tz: &TimeZone) -> bool {
    let today = local(tz, at).date();
    windows.iter().any(|&(days, start, end)| {
        (-1i32..=8).any(|back| {
            let day = today.checked_sub(jiff::Span::new().days(back)).unwrap();
            if days & (1 << (Weekday::of(day) as u8)) == 0 {
                return false;
            }
            let s = compatible(day, start, tz);
            let end_day = if end <= start {
                day.tomorrow().unwrap()
            } else {
                day
            };
            let e = compatible(end_day, end, tz);
            s <= at && at < e
        })
    })
}

/// The compatible rule, the slow way: the first instant whose local time
/// is the wanted one; for a skipped time, the wanted time read with the
/// offset in force just before the gap.
fn compatible(day: civil::Date, minutes: u16, tz: &TimeZone) -> i64 {
    let h = i8::try_from(minutes / 60).unwrap();
    let m = i8::try_from(minutes % 60).unwrap();
    let (y, mo, d) = (day.year(), day.month(), day.day());
    let found = occurrences(tz, y, mo, d, h, m);
    if let Some(first) = found.first() {
        return *first;
    }
    // In a gap: find the last instant before it, and read the wanted
    // local time with that instant's offset.
    let wanted = day.at(h, m, 0, 0);
    let naive = as_utc(wanted);
    let before = (0..1560)
        .map(|k| naive - 1560 * 60 + k * 60)
        .rfind(|&t| local(tz, t) < wanted)
        .unwrap();
    let offset = as_utc(local(tz, before)) - before;
    naive - offset
}

fn zone() -> impl Strategy<Value = TimeZone> {
    proptest::sample::select(vec![
        "UTC",
        "Australia/Sydney",
        "America/New_York",
        "Australia/Adelaide",
        "Asia/Kathmandu",
        "Australia/Lord_Howe",
        "Europe/London",
        "America/Santiago",
    ])
    .prop_map(tz)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Windows given as `end` agree with the slow reference, around DST
    /// changes in both hemispheres.
    #[test]
    fn windows_agree_with_the_reference(
        tz in zone(),
        raw in proptest::collection::vec((1u8..128, 0u16..1440, 0u16..1440), 1..4),
        // Instants in 2026, every minute, around the transitions.
        offset in 0i64..(366 * 1440),
    ) {
        let windows: Vec<Window> = raw.iter().map(|&(days, start, end)| Window {
            days: WEEK.iter().copied().filter(|d| days & (1 << (*d as u8)) != 0).collect(),
            start: TimeOfDay::from_minutes(start).unwrap(),
            end: Some(TimeOfDay::from_minutes(end).unwrap()),
            duration_mins: None,
        }).collect();
        let s = compile(windows);
        let at = instant(&utc(), 2026, 1, 1, 0, 0) + offset * 60;
        prop_assert_eq!(active(&s, &tz, at), reference(&raw, at, &tz));
    }

    /// A schedule is active exactly up to the instant `closes_at` gives.
    #[test]
    fn closes_at_is_the_first_inactive_instant(
        tz in zone(),
        start in 0u16..1440,
        len in 1u32..2000,
        offset in 0i64..(366 * 1440),
    ) {
        let s = CompiledSchedule::compile(&Schedule {
            windows: vec![Window {
                days: WEEK.to_vec(),
                start: TimeOfDay::from_minutes(start).unwrap(),
                end: None,
                duration_mins: Some(len),
            }],
            ..Schedule::default()
        }, TimeZoneBasis::Utc);
        let at = instant(&utc(), 2026, 1, 1, 0, 0) + offset * 60;
        if let Some(close) = s.closes_at(at, &tz) {
            prop_assert!(close > at);
            prop_assert!(!active(&s, &tz, close));
            prop_assert!(active(&s, &tz, close - 1));
            prop_assert!(active(&s, &tz, at + (close - at) / 2));
        }
    }

    /// `HH:MM` and `YYYY-MM-DD` round-trip through their text form.
    #[test]
    fn times_and_dates_round_trip(m in 0u16..=1440, days in 0i32..2_900_000) {
        let time = TimeOfDay::from_minutes(m).unwrap();
        prop_assert_eq!(time.to_string().parse::<TimeOfDay>().unwrap(), time);
        let date = civil::date(1, 1, 1).checked_add(jiff::Span::new().days(days));
        if let Ok(date) = date {
            let date = Date(date);
            prop_assert_eq!(date.to_string().parse::<Date>().unwrap(), date);
        }
    }
}

#[test]
fn time_and_date_text_is_strict() {
    for bad in ["9:00", "09:60", "24:01", "25:00", "0900", "09:00 ", "ab:cd"] {
        assert!(bad.parse::<TimeOfDay>().is_err(), "{bad}");
    }
    assert_eq!(t("24:00").minutes(), 1440);
    for bad in [
        "2026-02-30",
        "2026-13-01",
        "26-01-01",
        "2026/01/01",
        "2026-1-01",
    ] {
        assert!(bad.parse::<Date>().is_err(), "{bad}");
    }
}
