//! Wall-clock helpers: unix milliseconds and the ISO 8601 form the JavaScript node writes
//! (`new Date().toISOString()`), without a calendar dependency.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

pub(crate) fn now_secs() -> u64 {
    now_ms() / 1000
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for a unix millisecond timestamp.
pub(crate) fn iso(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `YYYY-MM-DD` for a unix millisecond timestamp.
pub(crate) fn iso_date(ms: u64) -> String {
    iso(ms).chars().take(10).collect()
}

/// Parse the exact form [`iso`] writes; anything else (another zone, no milliseconds, an
/// out-of-range field) is `None`, the way the JavaScript telemetry code insists on a value
/// that round-trips through `toISOString()`.
pub(crate) fn parse_iso(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 24 || bytes[23] != b'Z' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u64> {
        let slice = text.get(range)?;
        if !slice.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        slice.parse().ok()
    };
    let year = i64::try_from(num(0..4)?).ok()?;
    let month = u32::try_from(num(5..7)?).ok()?;
    let day = u32::try_from(num(8..10)?).ok()?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    let millis = num(20..23)?;
    if &text[4..5] != "-"
        || &text[7..8] != "-"
        || &text[10..11] != "T"
        || &text[13..14] != ":"
        || &text[16..17] != ":"
        || &text[19..20] != "."
    {
        return None;
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = u64::try_from(days).ok()? * 86_400 + hour * 3600 + minute * 60 + second;
    let ms = secs * 1000 + millis;
    (iso(ms) == text).then_some(ms)
}

// howard hinnant's civil calendar algorithms, valid for every date in the proleptic gregorian
// calendar; the node only ever sees timestamps after 1970.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_matches_javascript_to_iso_string() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_791_191_700_779), "2026-10-05T09:15:00.779Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso_date(1_791_191_700_779), "2026-10-05");
    }

    #[test]
    fn parse_is_strict_and_round_trips() {
        assert_eq!(
            parse_iso("2026-10-05T09:15:00.779Z"),
            Some(1_791_191_700_779)
        );
        assert_eq!(parse_iso("2026-10-05T09:15:00Z"), None);
        assert_eq!(parse_iso("2026-10-05T09:15:00.779+00:00"), None);
        assert_eq!(parse_iso("2026-13-05T09:15:00.779Z"), None);
        assert_eq!(parse_iso("2026-02-30T09:15:00.779Z"), None);
        let now = now_ms();
        assert_eq!(parse_iso(&iso(now)), Some(now));
    }
}
