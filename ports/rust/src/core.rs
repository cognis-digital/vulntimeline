//! Core domain logic for the Rust port: date parsing, remediation windows,
//! and risky-pattern flag detection. Mirrors the Python `vulntimeline.core`.

use crate::json::Json;
use std::collections::BTreeSet;

/// Days since the Unix epoch (UTC) — the unit milestone dates are diffed in.
pub type Ordinal = i64;

#[derive(Debug)]
pub struct AdvisoryError(pub String);

impl std::fmt::Display for AdvisoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Convert a Gregorian Y/M/D to days since 1970-01-01 (proleptic, UTC).
pub fn ymd_to_ordinal(y: i64, m: i64, d: i64) -> Ordinal {
    // days from civil algorithm (Howard Hinnant), epoch-shifted to 1970-01-01.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[allow(dead_code)]
pub fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn month_from_name(s: &str) -> Option<i64> {
    let l = s.to_lowercase();
    let table = [
        ("january", 1), ("february", 2), ("march", 3), ("april", 4), ("may", 5),
        ("june", 6), ("july", 7), ("august", 8), ("september", 9), ("october", 10),
        ("november", 11), ("december", 12), ("jan", 1), ("feb", 2), ("mar", 3),
        ("apr", 4), ("jun", 6), ("jul", 7), ("aug", 8), ("sep", 9), ("oct", 10),
        ("nov", 11), ("dec", 12),
    ];
    table.iter().find(|(n, _)| *n == l).map(|(_, v)| *v)
}

fn digits(s: &str) -> Option<i64> {
    s.parse::<i64>().ok()
}

/// Parse a date string into an ordinal. Returns Ok(None) for empty input.
pub fn parse_date(value: Option<&str>) -> Result<Option<Ordinal>, AdvisoryError> {
    let raw = match value {
        None => return Ok(None),
        Some(s) => s.trim(),
    };
    if raw.is_empty() {
        return Ok(None);
    }

    // ISO date / datetime: leading YYYY-MM-DD
    if raw.len() >= 10 {
        let head = &raw[..10];
        let parts: Vec<&str> = head.split('-').collect();
        if parts.len() == 3 && parts[0].len() == 4 && parts[1].len() == 2 && parts[2].len() == 2 {
            if let (Some(y), Some(m), Some(d)) =
                (digits(parts[0]), digits(parts[1]), digits(parts[2]))
            {
                let rest_ok = raw.len() == 10
                    || raw.as_bytes().get(10) == Some(&b'T')
                    || raw.as_bytes().get(10) == Some(&b' ');
                if rest_ok && (1..=12).contains(&m) && (1..=31).contains(&d) {
                    return Ok(Some(ymd_to_ordinal(y, m, d)));
                }
            }
        }
    }

    // YYYY/MM/DD  or  MM/DD/YYYY
    if raw.contains('/') {
        let parts: Vec<&str> = raw.split('/').collect();
        if parts.len() == 3 {
            if parts[0].len() == 4 {
                if let (Some(y), Some(m), Some(d)) =
                    (digits(parts[0]), digits(parts[1]), digits(parts[2]))
                {
                    return Ok(Some(ymd_to_ordinal(y, m, d)));
                }
            } else if parts[2].len() == 4 {
                if let (Some(m), Some(d), Some(y)) =
                    (digits(parts[0]), digits(parts[1]), digits(parts[2]))
                {
                    return Ok(Some(ymd_to_ordinal(y, m, d)));
                }
            }
        }
    }

    // DD-MM-YYYY
    {
        let parts: Vec<&str> = raw.split('-').collect();
        if parts.len() == 3 && parts[2].len() == 4 {
            if let (Some(d), Some(m), Some(y)) =
                (digits(parts[0]), digits(parts[1]), digits(parts[2]))
            {
                return Ok(Some(ymd_to_ordinal(y, m, d)));
            }
        }
    }

    // YYYYMMDD
    if raw.len() == 8 && raw.chars().all(|c| c.is_ascii_digit()) {
        let y = digits(&raw[0..4]).unwrap();
        let m = digits(&raw[4..6]).unwrap();
        let d = digits(&raw[6..8]).unwrap();
        if (1..=12).contains(&m) && (1..=31).contains(&d) {
            return Ok(Some(ymd_to_ordinal(y, m, d)));
        }
    }

    // "Month DD, YYYY"
    if let Some(comma) = raw.find(',') {
        let (left, right) = raw.split_at(comma);
        let right = right[1..].trim();
        let left_parts: Vec<&str> = left.split_whitespace().collect();
        if left_parts.len() == 2 {
            if let (Some(m), Some(d), Some(y)) =
                (month_from_name(left_parts[0]), digits(left_parts[1]), digits(right))
            {
                return Ok(Some(ymd_to_ordinal(y, m, d)));
            }
        }
    }

    Err(AdvisoryError(format!("could not parse date: {:?}", raw)))
}

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub severity: Option<String>,
    pub discovered: Option<Ordinal>,
    pub reported: Option<Ordinal>,
    pub disclosed: Option<Ordinal>,
    pub exploited: Option<Ordinal>,
    pub patched: Option<Ordinal>,
}

fn date_field(obj: &Json, key: &str) -> Result<Option<Ordinal>, AdvisoryError> {
    match obj.get(key) {
        Some(Json::Str(s)) => parse_date(Some(s)),
        Some(Json::Null) | None => Ok(None),
        Some(_) => Err(AdvisoryError(format!("unsupported date type for {}", key))),
    }
}

pub fn advisory_from_json(obj: &Json) -> Result<Advisory, AdvisoryError> {
    let map = obj
        .as_object()
        .ok_or_else(|| AdvisoryError("advisory record must be an object".to_string()))?;
    let id = match map.get("id") {
        Some(Json::Str(s)) if !s.trim().is_empty() => s.trim().to_string(),
        Some(Json::Num(n)) => format!("{}", n),
        _ => return Err(AdvisoryError("advisory record missing required 'id'".to_string())),
    };
    let severity = map
        .get("severity")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    Ok(Advisory {
        id,
        severity,
        discovered: date_field(obj, "discovered")?,
        reported: date_field(obj, "reported")?,
        disclosed: date_field(obj, "disclosed")?,
        exploited: date_field(obj, "exploited")?,
        patched: date_field(obj, "patched")?,
    })
}

pub fn load_advisories(text: &str) -> Result<Vec<Advisory>, AdvisoryError> {
    let root = crate::json::parse(text).map_err(|e| AdvisoryError(format!("invalid JSON: {}", e)))?;
    let records: &Vec<Json> = match &root {
        Json::Arr(a) => a,
        Json::Obj(_) => root
            .get("advisories")
            .and_then(|v| v.as_array())
            .ok_or_else(|| AdvisoryError("JSON object has no 'advisories' key".to_string()))?,
        _ => return Err(AdvisoryError("expected a list of advisory records".to_string())),
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for rec in records {
        let adv = advisory_from_json(rec)?;
        if !seen.insert(adv.id.clone()) {
            return Err(AdvisoryError(format!("duplicate advisory id: {}", adv.id)));
        }
        out.push(adv);
    }
    Ok(out)
}

#[derive(Debug)]
pub struct Window {
    pub id: String,
    pub severity: Option<String>,
    pub time_to_patch: Option<i64>,
    pub disclosure_gap: Option<i64>,
    pub report_latency: Option<i64>,
    pub exposure_window: Option<i64>,
    pub exposure_open: bool,
    pub exploited_before_patch: bool,
    pub unpatched: bool,
}

fn diff(later: Option<Ordinal>, earlier: Option<Ordinal>) -> Option<i64> {
    match (later, earlier) {
        (Some(l), Some(e)) => Some(l - e),
        _ => None,
    }
}

pub fn advisory_windows(a: &Advisory, today: Ordinal) -> Window {
    let mut exposure_window = None;
    let mut exposure_open = false;
    let mut exploited_before_patch = false;
    if let Some(ex) = a.exploited {
        match a.patched {
            Some(p) => {
                exposure_window = Some((p - ex).max(0));
                if ex < p {
                    exploited_before_patch = true;
                }
            }
            None => {
                exposure_window = Some((today - ex).max(0));
                exposure_open = true;
                exploited_before_patch = true;
            }
        }
    }
    Window {
        id: a.id.clone(),
        severity: a.severity.clone(),
        time_to_patch: diff(a.patched, a.disclosed),
        disclosure_gap: diff(a.disclosed, a.reported),
        report_latency: diff(a.reported, a.discovered),
        exposure_window,
        exposure_open,
        exploited_before_patch,
        unpatched: a.patched.is_none(),
    }
}

pub fn median(mut vals: Vec<i64>) -> Option<f64> {
    if vals.is_empty() {
        return None;
    }
    vals.sort_unstable();
    let mid = vals.len() / 2;
    Some(if vals.len() % 2 == 1 {
        vals[mid] as f64
    } else {
        (vals[mid - 1] + vals[mid]) as f64 / 2.0
    })
}

#[derive(Debug, Clone)]
pub struct Flag {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub detail: String,
}

pub fn detect_flags(advs: &[Advisory], max_ttp: Option<i64>, today: Ordinal) -> Vec<Flag> {
    let mut flags = Vec::new();
    for a in advs {
        let w = advisory_windows(a, today);
        if w.exploited_before_patch {
            let detail = if w.unpatched {
                "exploitation observed and advisory remains unpatched"
            } else {
                "exploitation observed before a patch was available"
            };
            flags.push(Flag {
                id: a.id.clone(),
                kind: "exploited_before_patch".into(),
                severity: "high".into(),
                detail: detail.into(),
            });
        }
        if let (Some(mt), Some(ttp)) = (max_ttp, w.time_to_patch) {
            if ttp > mt {
                flags.push(Flag {
                    id: a.id.clone(),
                    kind: "slow_patch".into(),
                    severity: "medium".into(),
                    detail: format!("time-to-patch {}d exceeds threshold {}d", ttp, mt),
                });
            }
        }
        if w.unpatched {
            flags.push(Flag {
                id: a.id.clone(),
                kind: "unpatched".into(),
                severity: "medium".into(),
                detail: "no patch date recorded".into(),
            });
        }
        for (name, val) in [
            ("time_to_patch", w.time_to_patch),
            ("disclosure_gap", w.disclosure_gap),
            ("report_latency", w.report_latency),
        ] {
            if let Some(v) = val {
                if v < 0 {
                    flags.push(Flag {
                        id: a.id.clone(),
                        kind: "negative_window".into(),
                        severity: "low".into(),
                        detail: format!("{} is negative ({}d): check date ordering", name, v),
                    });
                }
            }
        }
    }
    flags
}
