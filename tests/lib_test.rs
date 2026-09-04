use log_sieve::{analyze, parse_line, percentile, top_n};

const SAMPLE: &str = r#"203.0.113.7 - - [04/Sep/2026:10:00:00] "GET /api/users HTTP/1.1" 200 1043 "https://ref" "agent" latency=12ms
203.0.113.7 - - [04/Sep/2026:10:00:01] "POST /api/orders HTTP/1.1" 201 512 "-" "agent" latency=34ms
198.51.100.2 - - [04/Sep/2026:10:00:02] "GET /api/users HTTP/1.1" 404 221 "-" "agent" latency=5ms
198.51.100.2 - - [04/Sep/2026:10:00:03] "GET /missing HTTP/1.1" 500 98 "-" "agent" latency=210ms
203.0.113.7 - - [04/Sep/2026:10:00:04] "DELETE /api/orders/42 HTTP/1.1" 204 0 "-" "agent" latency=8ms
"#;

fn sample_entries() -> Vec<log_sieve::EntryOwned> {
    SAMPLE.lines().filter_map(parse_line).collect()
}

#[test]
fn parses_combined_format() {
    let e = parse_line(
        r#"203.0.113.7 - - [04/Sep/2026:10:00:00] "GET /api/users HTTP/1.1" 200 1043 "https://ref" "agent" latency=12ms"#,
    )
    .unwrap();
    assert_eq!(e.ip, "203.0.113.7");
    assert_eq!(e.method, "GET");
    assert_eq!(e.path, "/api/users");
    assert_eq!(e.status, 200);
    assert_eq!(e.bytes, 1043);
    assert_eq!(e.latency_ms, Some(12));
}

#[test]
fn parses_dash_bytes_as_zero() {
    let e = parse_line(
        r#"10.0.0.1 - - [x] "HEAD / HTTP/1.1" 200 - "-" "-""#,
    )
    .unwrap();
    assert_eq!(e.bytes, 0);
}

#[test]
fn rejects_garbage() {
    assert!(parse_line("").is_none());
    assert!(parse_line("total garbage").is_none());
    assert!(parse_line(r#""GET /path" abc 5"#).is_none());
}

#[test]
fn analyze_aggregates() {
    let a = analyze(&sample_entries());
    assert_eq!(a.total, 5);
    assert_eq!(a.errors_4xx, 1);
    assert_eq!(a.errors_5xx, 1);
    assert_eq!(a.bytes_total, 1043 + 512 + 221 + 98 + 0);
    assert_eq!(a.by_status.get(&200), Some(&1));
    assert_eq!(a.by_ip.get("203.0.113.7"), Some(&3));
    assert_eq!(a.by_path.get("/api/users"), Some(&2));
    assert_eq!(a.latencies.len(), 5);
}

#[test]
fn top_n_sorted_desc() {
    let a = analyze(&sample_entries());
    let ips = top_n(&a.by_ip, 5);
    assert_eq!(ips[0].0, "203.0.113.7");
    assert_eq!(ips[0].1, 3);
    assert!(ips.len() <= 5);
}

#[test]
fn percentile_basics() {
    let mut v = vec![10, 20, 30, 40, 100];
    v.sort_unstable();
    assert_eq!(percentile(&v, 50.0), Some(30));
    assert_eq!(percentile(&v, 100.0), Some(100));
    assert_eq!(percentile(&[], 50.0), None);
}

#[test]
fn latency_extraction_handles_trailing_text() {
    let e = parse_line(
        r#"1.2.3.4 - - [x] "GET / HTTP/1.1" 200 1 "-" "-" latency=42ms upstream=cache"#,
    )
    .unwrap();
    assert_eq!(e.latency_ms, Some(42));
}
