//! vulntimeline (Rust port) — defensive vulnerability-disclosure analytics.
//!
//! A faithful port of the primary Python CLI's core surface: the `metrics` and
//! `flags` subcommands. Same advisory JSON input, same remediation windows,
//! same risky-pattern flags, and the same `--fail-on-any` CI gate (exit 2).
//!
//! Passive / offline / authorized-use only. No network, std-only (a tiny
//! hand-written JSON reader keeps it dependency-free).

mod core;
mod json;

use core::{advisory_windows, detect_flags, load_advisories, median, Advisory, Window};
use std::io::Read;
use std::process::exit;

fn num(v: Option<i64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "-".to_string(),
    }
}

fn med(v: Option<f64>) -> String {
    match v {
        None => "-".to_string(),
        Some(f) if f.fract() == 0.0 => (f as i64).to_string(),
        Some(f) => f.to_string(),
    }
}

fn render_metrics(advs: &[Advisory], today: i64) -> String {
    let mut out = String::from("ID  SEV  TTP  DISC_GAP  REPLAT  EXPOSURE  XBP\n");
    let (mut ttp, mut gap, mut rep, mut exp) = (vec![], vec![], vec![], vec![]);
    let (mut xbp, mut unp) = (0, 0);
    for a in advs {
        let w: Window = advisory_windows(a, today);
        let mut exposure = num(w.exposure_window);
        if w.exposure_open && w.exposure_window.is_some() {
            exposure.push('*');
        }
        out.push_str(&format!(
            "{}  {}  {}  {}  {}  {}  {}\n",
            w.id,
            w.severity.clone().unwrap_or_else(|| "-".into()),
            num(w.time_to_patch),
            num(w.disclosure_gap),
            num(w.report_latency),
            exposure,
            if w.exploited_before_patch { "yes" } else { "no" },
        ));
        if let Some(v) = w.time_to_patch {
            ttp.push(v);
        }
        if let Some(v) = w.disclosure_gap {
            gap.push(v);
        }
        if let Some(v) = w.report_latency {
            rep.push(v);
        }
        if let Some(v) = w.exposure_window {
            exp.push(v);
        }
        if w.exploited_before_patch {
            xbp += 1;
        }
        if w.unpatched {
            unp += 1;
        }
    }
    out.push_str("\nAggregate (days; median):\n");
    out.push_str(&format!("  count                  {}\n", advs.len()));
    out.push_str(&format!("  median time-to-patch   {}\n", med(median(ttp))));
    out.push_str(&format!("  median disclosure gap  {}\n", med(median(gap))));
    out.push_str(&format!("  median report latency  {}\n", med(median(rep))));
    out.push_str(&format!("  median exposure window {}\n", med(median(exp))));
    out.push_str(&format!("  exploited-before-patch {}\n", xbp));
    out.push_str(&format!("  unpatched              {}\n", unp));
    out
}

fn render_flags(flags: &[core::Flag]) -> String {
    if flags.is_empty() {
        return "No flags detected.\n".to_string();
    }
    let mut out = String::from("ID  KIND  SEVERITY  DETAIL\n");
    for f in flags {
        out.push_str(&format!("{}  {}  {}  {}\n", f.id, f.kind, f.severity, f.detail));
    }
    out.push_str(&format!("\n{} flag(s) detected.\n", flags.len()));
    out
}

/// Today as an ordinal. We avoid pulling in time crates: SystemTime since the
/// epoch in seconds / 86400 is the UTC day index, matching the date math.
fn today_ordinal() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() / 86400) as i64,
        Err(_) => 0,
    }
}

fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: vulntimeline <metrics|flags> <advisories.json> [--max-ttp N] [--fail-on-any]");
        return 1;
    }
    let cmd = &args[0];
    let mut path: Option<String> = None;
    let mut fail_on_any = false;
    let mut max_ttp: Option<i64> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--fail-on-any" => fail_on_any = true,
            "--json" => { /* accepted for parity; tables are the default output */ }
            "--max-ttp" => {
                i += 1;
                if i < args.len() {
                    max_ttp = args[i].parse::<i64>().ok();
                }
            }
            other if !other.starts_with("--") => path = Some(other.to_string()),
            other => {
                eprintln!("error: unknown option {}", other);
                return 1;
            }
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("error: missing advisories path");
            return 1;
        }
    };

    let text = if path == "-" {
        let mut s = String::new();
        if std::io::stdin().read_to_string(&mut s).is_err() {
            eprintln!("error: failed to read stdin");
            return 1;
        }
        s
    } else {
        match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {}", e);
                return 1;
            }
        }
    };

    let advs = match load_advisories(&text) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    let today = today_ordinal();

    match cmd.as_str() {
        "metrics" => {
            print!("{}", render_metrics(&advs, today));
            0
        }
        "flags" => {
            let flags = detect_flags(&advs, max_ttp, today);
            print!("{}", render_flags(&flags));
            if fail_on_any && !flags.is_empty() {
                2
            } else {
                0
            }
        }
        other => {
            eprintln!("error: unknown command {}", other);
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    exit(run(&args));
}

#[cfg(test)]
mod tests {
    use super::core::*;

    fn ord(s: &str) -> i64 {
        parse_date(Some(s)).unwrap().unwrap()
    }

    #[test]
    fn parse_date_formats_agree() {
        let iso = ord("2025-02-10");
        assert_eq!(ord("02/10/2025"), iso);
        assert_eq!(ord("2025/02/10"), iso);
        assert_eq!(ord("20250210"), iso);
        assert_eq!(ord("February 10, 2025"), iso);
        assert_eq!(ord("2025-02-10T09:30:00Z"), iso);
    }

    #[test]
    fn parse_date_empty_and_nil() {
        assert_eq!(parse_date(None).unwrap(), None);
        assert_eq!(parse_date(Some("")).unwrap(), None);
        assert!(parse_date(Some("not-a-date")).is_err());
    }

    #[test]
    fn ordinal_diff_is_two_days() {
        assert_eq!(ord("2025-02-12") - ord("2025-02-10"), 2);
    }

    #[test]
    fn load_requires_id() {
        assert!(load_advisories(r#"[{"title":"x"}]"#).is_err());
    }

    #[test]
    fn load_duplicate_id() {
        assert!(load_advisories(r#"[{"id":"A"},{"id":"A"}]"#).is_err());
    }

    #[test]
    fn windows_time_to_patch() {
        let advs = load_advisories(r#"[{"id":"X","disclosed":"2025-02-10","patched":"2025-02-12"}]"#).unwrap();
        let w = advisory_windows(&advs[0], 0);
        assert_eq!(w.time_to_patch, Some(2));
        assert!(!w.unpatched);
    }

    #[test]
    fn windows_exploited_before_patch() {
        let advs = load_advisories(
            r#"[{"id":"X","disclosed":"2025-02-10","exploited":"2025-02-11","patched":"2025-02-12"}]"#,
        )
        .unwrap();
        let w = advisory_windows(&advs[0], 0);
        assert!(w.exploited_before_patch);
        assert_eq!(w.exposure_window, Some(1));
    }

    #[test]
    fn windows_unpatched_open() {
        let advs = load_advisories(r#"[{"id":"X","exploited":"2020-01-01"}]"#).unwrap();
        let w = advisory_windows(&advs[0], ord("2020-01-11"));
        assert!(w.unpatched);
        assert!(w.exposure_open);
        assert_eq!(w.exposure_window, Some(10));
    }

    #[test]
    fn median_even() {
        let advs = load_advisories(
            r#"[{"id":"A","disclosed":"2025-01-01","patched":"2025-01-05"},
                {"id":"B","disclosed":"2025-01-01","patched":"2025-01-11"}]"#,
        )
        .unwrap();
        let ttp: Vec<i64> = advs
            .iter()
            .filter_map(|a| advisory_windows(a, 0).time_to_patch)
            .collect();
        assert_eq!(median(ttp), Some(7.0));
    }

    #[test]
    fn detect_flags_xbp_and_unpatched() {
        let advs = load_advisories(r#"[{"id":"A","disclosed":"2025-01-01","exploited":"2025-01-02"}]"#).unwrap();
        let flags = detect_flags(&advs, None, ord("2025-02-01"));
        let kinds: Vec<&str> = flags.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"exploited_before_patch"));
        assert!(kinds.contains(&"unpatched"));
    }

    #[test]
    fn detect_slow_patch_threshold() {
        let advs = load_advisories(r#"[{"id":"A","disclosed":"2025-01-01","patched":"2025-03-01"}]"#).unwrap();
        assert_eq!(
            detect_flags(&advs, Some(30), 0).iter().filter(|f| f.kind == "slow_patch").count(),
            1
        );
        assert_eq!(
            detect_flags(&advs, Some(90), 0).iter().filter(|f| f.kind == "slow_patch").count(),
            0
        );
    }

    #[test]
    fn detect_negative_window() {
        let advs = load_advisories(r#"[{"id":"A","disclosed":"2025-02-10","patched":"2025-02-01"}]"#).unwrap();
        assert!(detect_flags(&advs, None, 0).iter().any(|f| f.kind == "negative_window"));
    }
}
