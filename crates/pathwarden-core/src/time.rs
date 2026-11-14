//! Calendar helpers (no external dependency).

/// Unix seconds for a UTC calendar time, or `None` if out of range.
pub fn unix_from_civil(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> Option<i64> {
    if !(1..=12).contains(&m)
        || !(1..=31).contains(&d)
        || !(0..24).contains(&hh)
        || !(0..60).contains(&mm)
        || !(0..61).contains(&ss)
    {
        return None;
    }
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400 + hh * 3_600 + mm * 60 + ss)
}

/// `YYYY-MM-DD` to Unix seconds at 00:00 UTC.
pub fn parse_date(s: &str) -> Option<i64> {
    let mut parts = s.trim().splitn(3, '-').map(str::parse::<i64>);
    let (y, m, d) = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    unix_from_civil(y, m, d, 0, 0, 0)
}

/// The collection time SharpHound and RustHound-CE put in file names
/// (`20240410083609_users.json`, `CONTOSO_20240410083609_BloodHound.zip`): the
/// first run of exactly 14 digits that forms a plausible date. Collector-local
/// time, so accurate to within the time zone offset.
pub fn timestamp_in_name(name: &str) -> Option<i64> {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i - start == 14 {
            let n = |a: usize, b: usize| name[start + a..start + b].parse::<i64>().ok();
            let y = n(0, 4)?;
            if (2000..2200).contains(&y) {
                if let Some(t) =
                    unix_from_civil(y, n(4, 6)?, n(6, 8)?, n(8, 10)?, n(10, 12)?, n(12, 14)?)
                {
                    return Some(t);
                }
            }
        }
    }
    None
}

/// (year, month 1-12, day, seconds into the day) of Unix time `t`, UTC.
fn civil(t: i64) -> (i64, i64, i64, i64) {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Civil from days (inverse of the above).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, secs)
}

/// `YYYY-MM-DD HH:MM` (UTC): a sortable stamp for machines (IDs, file
/// names). People read [`format_us`] and its kin.
pub fn format_unix(t: i64) -> String {
    let (y, m, d, secs) = civil(t);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        secs / 3_600,
        secs % 3_600 / 60
    )
}

/// `YYYY-MM-DD` (UTC): the date of `t`, for a date field or a file name.
pub fn format_iso_date(t: i64) -> String {
    let (y, m, d, _) = civil(t);
    format!("{y:04}-{m:02}-{d:02}")
}

// ---- Dates and times as people read them (US style) ----
//
// The one place Pathwarden writes a date or a time for a person: "Oct 29,
// 2026" and "Oct 29, 2026, 4:07 PM". Machine formats (JSON, file names,
// IDs, on-disk files) stay ISO 8601 ([`format_rfc3339`], [`format_unix`]).
// The app's pages do the same in the browser (`PathwardenTime`, `app.js`).

/// Short month names, January first.
pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn month_name(m: i64) -> &'static str {
    MONTHS[(m.clamp(1, 12) - 1) as usize]
}

/// "Oct 22, 2026": the UTC calendar day of `t`. A date-only value (a
/// `YYYY-MM-DD` read as its midnight, UTC) is that date, never shifted by
/// a time zone.
pub fn format_day(t: i64) -> String {
    let (y, m, d, _) = civil(t);
    format!("{} {d}, {y}", month_name(m))
}

/// "Oct 22": [`format_day`] without the year.
pub fn format_month_day(t: i64) -> String {
    let (_, m, d, _) = civil(t);
    format!("{} {d}", month_name(m))
}

/// "4:07 PM": the UTC time of day of `t`.
pub fn format_clock(t: i64) -> String {
    clock(t, false)
}

/// "4:07:30 PM": [`format_clock`] with the seconds, to tell apart two
/// times of one minute.
pub fn format_clock_seconds(t: i64) -> String {
    clock(t, true)
}

fn clock(t: i64, seconds: bool) -> String {
    let (_, _, _, secs) = civil(t);
    let (hh, mm) = (secs / 3_600, secs % 3_600 / 60);
    let (h12, half) = match hh {
        0 => (12, "AM"),
        1..=11 => (hh, "AM"),
        12 => (12, "PM"),
        _ => (hh - 12, "PM"),
    };
    if seconds {
        format!("{h12}:{mm:02}:{:02} {half}", secs % 60)
    } else {
        format!("{h12}:{mm:02} {half}")
    }
}

/// "Oct 29, 2026, 4:07 PM": `t` in UTC, US style, without a zone. Show
/// people [`format_utc`] (labeled) or [`format_local`] (this computer's
/// time); this is their common form.
pub fn format_us(t: i64) -> String {
    format!("{}, {}", format_day(t), format_clock(t))
}

/// "Oct 29, 2026, 4:07 PM UTC": a time that must read the same anywhere
/// (log lines, a page's text before its script shows local time).
pub fn format_utc(t: i64) -> String {
    format!("{} UTC", format_us(t))
}

/// "Apr 10, 2024, 8:36 AM": when a collection was made, as its file names
/// say it. The collector writes its own clock with no zone, so the time is
/// shown as written, never moved to UTC or this computer's zone.
pub fn format_collected(t: i64) -> String {
    format_us(t)
}

/// What a page says of a collection time ([`format_collected`]), as its
/// tooltip.
pub const COLLECTED_CLOCK: &str = "The collector's clock, from its file names";

/// "Oct 29, 2026, 11:07 AM": `t` in this computer's time zone, as the
/// command line and the app show times.
pub fn format_local(t: i64) -> String {
    format_us(t + local_offset(t))
}

/// "Oct 29, 2026": the day of `t` in this computer's time zone. Not for
/// date-only values, which are [`format_day`].
pub fn format_local_date(t: i64) -> String {
    format_day(t + local_offset(t))
}

/// Seconds this computer's time zone is ahead of UTC at `t`, daylight
/// saving included; 0 when it can't tell.
pub fn local_offset(t: i64) -> i64 {
    os_offset(t).unwrap_or(0)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn os_offset(t: i64) -> Option<i64> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTimeEx,
    };
    // 100 ns ticks since 1601-01-01 (UTC).
    let ticks = u64::try_from(t.checked_add(11_644_473_600)?)
        .ok()?
        .checked_mul(10_000_000)?;
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let zero = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    let (mut utc, mut local) = (zero, zero);
    let mut back = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: every pointer is to a live local of the right type; a null
    // time zone is the current one, with its daylight saving rules.
    let ok = unsafe {
        FileTimeToSystemTime(&ft, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTimeEx(std::ptr::null(), &utc, &mut local) != 0
            && SystemTimeToFileTime(&local, &mut back) != 0
    };
    if !ok {
        return None;
    }
    let local_ticks = (u64::from(back.dwHighDateTime) << 32) | u64::from(back.dwLowDateTime);
    Some((local_ticks as i64 - ticks as i64).div_euclid(10_000_000))
}

#[cfg(unix)]
#[allow(unsafe_code)]
// `tm_gmtoff` is a C long: i64 on 64-bit Unix (where the conversion is a
// no-op), i32 on 32-bit.
#[allow(clippy::useless_conversion)]
fn os_offset(t: i64) -> Option<i64> {
    let tt = libc::time_t::try_from(t).ok()?;
    // SAFETY: `tm` is plain data that localtime_r fills; both pointers are
    // to live locals.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
        return None;
    }
    Some(i64::from(tm.tm_gmtoff))
}

#[cfg(not(any(windows, unix)))]
fn os_offset(_: i64) -> Option<i64> {
    None
}

/// The day of a stored date or time, as people read it: a `YYYY-MM-DD`
/// date (a review date) as typed, never shifted; an RFC 3339 time (when a
/// risk was accepted or changed) as its day in this computer's time zone
/// ([`format_local_date`]); anything else as written.
pub fn day_of(text: &str) -> String {
    let date_only = text.trim().len() == 10;
    match parse_rfc3339(text) {
        Some(t) if date_only => format_day(t),
        Some(t) => format_local_date(t),
        None => text.to_string(),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` (RFC 3339, UTC), as accepted risks record when
/// they were accepted and changed.
pub fn format_rfc3339(t: i64) -> String {
    let s = format_unix(t); // "YYYY-MM-DD HH:MM"
    format!("{}T{}:{:02}Z", &s[..10], &s[11..16], t.rem_euclid(60))
}

/// Unix seconds for an RFC 3339 time (`2026-10-22T14:03:11Z`, with or
/// without fractions, `Z` or an offset such as `+02:00`). A date alone
/// reads as its midnight (UTC). Anything else: `None`.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() == 10 {
        return parse_date(s).filter(|_| s.as_bytes()[4] == b'-');
    }
    let b = s.as_bytes();
    if b.len() < 20 || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let day = parse_date(s.get(..10)?)?;
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            let (oh, om) = (
                rest[1..3].parse::<i64>().ok()?,
                rest[4..6].parse::<i64>().ok()?,
            );
            sign * (oh * 3_600 + om * 60)
        }
    };
    Some(day + hh * 3_600 + mm * 60 + ss - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_times() {
        let t = unix_from_civil(2026, 10, 29, 16, 7, 30).unwrap();
        assert_eq!(format_us(t), "Oct 29, 2026, 4:07 PM");
        let t = unix_from_civil(2026, 1, 2, 0, 5, 0).unwrap();
        assert_eq!(format_us(t), "Jan 2, 2026, 12:05 AM");
        let t = unix_from_civil(2026, 7, 4, 12, 0, 0).unwrap();
        assert_eq!(format_us(t), "Jul 4, 2026, 12:00 PM");
        let t = unix_from_civil(2026, 7, 4, 9, 59, 0).unwrap();
        assert_eq!(format_us(t), "Jul 4, 2026, 9:59 AM");
    }

    #[test]
    fn us_style_edges() {
        // Midnight and noon.
        let midnight = unix_from_civil(2026, 11, 1, 0, 0, 0).unwrap();
        assert_eq!(format_us(midnight), "Nov 1, 2026, 12:00 AM");
        assert_eq!(format_clock(midnight), "12:00 AM");
        let noon = unix_from_civil(2026, 11, 1, 12, 0, 0).unwrap();
        assert_eq!(format_clock(noon), "12:00 PM");
        assert_eq!(format_utc(noon), "Nov 1, 2026, 12:00 PM UTC");
        // A single-digit day, unpadded.
        let t = unix_from_civil(2026, 3, 7, 21, 7, 0).unwrap();
        assert_eq!(format_day(t), "Mar 7, 2026");
        assert_eq!(format_month_day(t), "Mar 7");
        assert_eq!(format_utc(t), "Mar 7, 2026, 9:07 PM UTC");
        // The last minute of a year and the first of the next.
        let eve = unix_from_civil(2026, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(format_us(eve), "Dec 31, 2026, 11:59 PM");
        assert_eq!(format_us(eve + 1), "Jan 1, 2027, 12:00 AM");
        assert_eq!(format_iso_date(eve + 1), "2027-01-01");
        // A date-only value is its own day, whatever the zone.
        assert_eq!(day_of("2027-01-01"), "Jan 1, 2027");
        // Local time is UTC moved by this computer's offset (a whole number
        // of minutes, under a day).
        let off = local_offset(noon);
        assert!(off.abs() < 86_400 && off % 60 == 0, "{off}");
        assert_eq!(format_local(noon), format_us(noon + off));
        assert_eq!(format_local_date(noon), format_day(noon + off));
    }

    #[test]
    fn dates_and_names() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2026-10-08"), Some(1_791_417_600));
        assert_eq!(parse_date("2026-13-01"), None);
        let t = timestamp_in_name(
            "data/SEVENKINGDOMS_20240410083609_BloodHound-2.3.3.zip!x_users.json",
        )
        .unwrap();
        assert_eq!(format_unix(t), "2024-04-10 08:36");
        assert_eq!(timestamp_in_name("users.json"), None);
        assert_eq!(timestamp_in_name("99999999999999_users.json"), None);
        assert_eq!(format_unix(0), "1970-01-01 00:00");
    }

    #[test]
    fn days() {
        assert_eq!(format_day(1_792_677_791), "Oct 22, 2026");
        assert_eq!(day_of("2027-03-31"), "Mar 31, 2027");
        let t = parse_rfc3339("2026-10-22T23:59:59-02:00").unwrap();
        assert_eq!(day_of("2026-10-22T23:59:59-02:00"), format_local_date(t));
        assert_eq!(day_of("last Tuesday"), "last Tuesday");
    }

    #[test]
    fn rfc3339() {
        let t = 1_792_677_791; // 2026-10-22 14:03:11 UTC
        assert_eq!(format_rfc3339(t), "2026-10-22T14:03:11Z");
        assert_eq!(parse_rfc3339("2026-10-22T14:03:11Z"), Some(t));
        assert_eq!(parse_rfc3339("2026-10-22T14:03:11.250Z"), Some(t));
        assert_eq!(parse_rfc3339("2026-10-22T16:03:11+02:00"), Some(t));
        assert_eq!(
            parse_rfc3339("2026-10-22"),
            Some(t - 14 * 3_600 - 3 * 60 - 11)
        );
        assert_eq!(parse_rfc3339("2026-10-22T14:03Z"), None);
        assert_eq!(parse_rfc3339("yesterday"), None);
        assert_eq!(parse_rfc3339("2026-10-22T14:03:11"), None);
    }
}
