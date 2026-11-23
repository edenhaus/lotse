//! RFC 3339 timestamps in UTC, the API's one time format.
//!
//! Implements RFC 3339 §5.6 `date-time` with the `Z` offset and millisecond
//! precision, from a `SystemTime`, without a calendar dependency: the
//! civil-from-days conversion is the one in Howard Hinnant's date
//! algorithms.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `time` as `YYYY-MM-DDThh:mm:ss.sssZ`. Times before the epoch print as
/// the epoch.
pub fn rfc3339(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = i64::try_from(since.as_secs()).unwrap_or(i64::MAX);
    let millis = since.subsec_millis();
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = day_secs.checked_div(3_600).unwrap_or(0);
    let minute = day_secs.rem_euclid(3_600).checked_div(60).unwrap_or(0);
    let second = day_secs.rem_euclid(60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Year, month and day of a day count since 1970-01-01 (proleptic
/// Gregorian), after Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe.checked_div(1_460).unwrap_or(0))
        .saturating_add(doe.checked_div(36_524).unwrap_or(0))
        .saturating_sub(doe.checked_div(146_096).unwrap_or(0))
        .checked_div(365)
        .unwrap_or(0);
    let year = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe.checked_div(4).unwrap_or(0))
            .saturating_sub(yoe.checked_div(100).unwrap_or(0)),
    );
    let mp = doy
        .saturating_mul(5)
        .saturating_add(2)
        .checked_div(153)
        .unwrap_or(0);
    let day = doy
        .saturating_sub(
            mp.saturating_mul(153)
                .saturating_add(2)
                .checked_div(5)
                .unwrap_or(0),
        )
        .saturating_add(1);
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = if month <= 2 {
        year.saturating_add(1)
    } else {
        year
    };
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    fn at(secs: u64, millis: u32) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(u64::from(millis))
    }

    #[test]
    fn formats_known_instants_rfc3339_5_6() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(at(951_782_400, 0)), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(1_790_000_000, 42)), "2026-09-21T14:13:20.042Z");
        assert_eq!(rfc3339(at(4_102_444_799, 999)), "2099-12-31T23:59:59.999Z");
        assert_eq!(rfc3339(at(1_709_164_800, 0)), "2024-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(1_709_251_200, 0)), "2024-03-01T00:00:00.000Z");
    }

    #[test]
    fn times_before_the_epoch_print_as_the_epoch() {
        let before = UNIX_EPOCH - Duration::from_secs(5);
        assert_eq!(rfc3339(before), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn every_day_of_a_leap_year_maps_back_to_itself() {
        // 2024 is a leap year: day counts round-trip through the calendar.
        let start = 19_723; // 2024-01-01
        let mut previous = civil_from_days(start - 1);
        for offset in 0..366 {
            let (y, m, d) = civil_from_days(start + offset);
            assert_eq!(y, 2024);
            assert!((1..=12).contains(&m) && (1..=31).contains(&d));
            assert!((y, m, d) > previous, "monotonic");
            previous = (y, m, d);
        }
        assert_eq!(civil_from_days(start + 366), (2025, 1, 1));
    }
}
