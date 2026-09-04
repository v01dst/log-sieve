use std::io::{self, Read};
use std::process::exit;

use log_sieve::{analyze, parse_line, percentile, top_n};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!(
        "log-sieve {VERSION} — HTTP access log analyzer

USAGE:
    log-sieve [OPTIONS] [FILE]        (stdin if no file)

OPTIONS:
    --status CODE     only lines with this status
    --class 4xx|5xx|2xx|3xx  only lines in this status class
    --ip IP           only lines from this IP
    --path PREFIX     only lines whose path starts with PREFIX
    --top N           show top N IPs and paths in the summary (default 5)
    --summary         print aggregate report instead of matching lines
    --json            machine-readable summary
    -h, --help        print help
    -v, --version     print version"
    );
}

struct Options {
    status: Option<u16>,
    class: Option<u16>,
    ip: Option<String>,
    path_prefix: Option<String>,
    top: usize,
    summary: bool,
    json: bool,
    file: Option<String>,
}

fn parse_args() -> Options {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut o = Options {
        status: None,
        class: None,
        ip: None,
        path_prefix: None,
        top: 5,
        summary: false,
        json: false,
        file: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--status" => {
                i += 1;
                o.status = Some(
                    args.get(i)
                        .expect("--status needs a value")
                        .parse()
                        .expect("status must be a number"),
                );
            }
            "--class" => {
                i += 1;
                let v = args.get(i).expect("--class needs a value").to_string();
                o.class = Some(match v.as_str() {
                    "2xx" => 2,
                    "3xx" => 3,
                    "4xx" => 4,
                    "5xx" => 5,
                    other => {
                        eprintln!("error: unknown class '{other}' (use 2xx|3xx|4xx|5xx)");
                        exit(1);
                    }
                });
            }
            "--ip" => {
                i += 1;
                o.ip = Some(args.get(i).expect("--ip needs a value").clone());
            }
            "--path" => {
                i += 1;
                o.path_prefix = Some(args.get(i).expect("--path needs a value").clone());
            }
            "--top" => {
                i += 1;
                o.top = args
                    .get(i)
                    .expect("--top needs a value")
                    .parse()
                    .expect("top must be a number");
            }
            "--summary" => o.summary = true,
            "--json" => {
                o.json = true;
                o.summary = true;
            }
            "-h" | "--help" => {
                print_usage();
                exit(0);
            }
            "-v" | "--version" => {
                println!("log-sieve {VERSION}");
                exit(0);
            }
            other => {
                if other.starts_with('-') && other.len() > 1 {
                    eprintln!("error: unknown flag '{other}'");
                    exit(2);
                }
                o.file = Some(other.to_string());
            }
        }
        i += 1;
    }
    o
}

fn read_lines(opts: &Options) -> Vec<String> {
    let mut content = String::new();
    match &opts.file {
        Some(path) => {
            if std::fs::read_to_string(path)
                .and_then(|c| {
                    content = c;
                    Ok(())
                })
                .is_err()
            {
                eprintln!("error: cannot read file");
                exit(1);
            }
        }
        None => {
            if io::stdin().read_to_string(&mut content).is_err() {
                eprintln!("error: cannot read stdin");
                exit(1);
            }
        }
    }
    content.lines().map(|l| l.to_string()).collect()
}

fn main() {
    let opts = parse_args();
    let lines = read_lines(&opts);

    let entries: Vec<_> = lines.iter().filter_map(|l| parse_line(l)).collect();
    let parsed_count = entries.len();

    let filtered: Vec<&_> = entries
        .iter()
        .filter(|e| {
            if let Some(s) = opts.status {
                if e.status != s {
                    return false;
                }
            }
            if let Some(class) = opts.class {
                if e.status / 100 != class {
                    return false;
                }
            }
            if let Some(ip) = &opts.ip {
                if &e.ip != ip {
                    return false;
                }
            }
            if let Some(prefix) = &opts.path_prefix {
                if !e.path.starts_with(prefix.as_str()) {
                    return false;
                }
            }
            true
        })
        .collect();

    if opts.json {
        let owned: Vec<_> = filtered.iter().map(|e| (*e).clone()).collect();
        let a = analyze(&owned);
        let mut lat_sorted = a.latencies.clone();
        lat_sorted.sort_unstable();
        let status_codes: Vec<String> = {
            let mut codes: Vec<_> = a.by_status.iter().collect();
            codes.sort_by_key(|(k, _)| **k);
            codes
                .iter()
                .map(|(c, n)| format!("    \"{c}\": {n}"))
                .collect::<Vec<_>>()
        };
        let top_ips: Vec<String> = top_n(&a.by_ip, opts.top)
            .iter()
            .map(|(ip, n)| format!("    {}: {}", json_str(ip), n))
            .collect();
        let top_paths: Vec<String> = top_n(&a.by_path, opts.top)
            .iter()
            .map(|(p, n)| format!("    {}: {}", json_str(p), n))
            .collect();
        let lat = |p: f64| -> String {
            match percentile(&lat_sorted, p) {
                Some(v) => v.to_string(),
                None => "null".to_string(),
            }
        };
        println!(
            "{{
  \"parsed\": {parsed_count},
  \"matched\": {matched},
  \"total_bytes\": {bytes},
  \"errors_4xx\": {e4},
  \"errors_5xx\": {e5},
  \"latency_ms\": {{ \"p50\": {p50}, \"p95\": {p95}, \"p99\": {p99} }},
  \"top_ips\": {{\n{ips}\n  }},
  \"top_paths\": {{\n{paths}\n  }},
  \"status_codes\": {{\n{codes}\n  }}
}}",
            matched = filtered.len(),
            bytes = a.bytes_total,
            e4 = a.errors_4xx,
            e5 = a.errors_5xx,
            p50 = lat(50.0),
            p95 = lat(95.0),
            p99 = lat(99.0),
            ips = top_ips.join(
                ",
"
            ),
            paths = top_paths.join(
                ",
"
            ),
            codes = status_codes.join(",\n"),
        );
        return;
    }

    if opts.summary {
        let owned: Vec<_> = filtered.iter().map(|e| (*e).clone()).collect();
        let a = analyze(&owned);
        let mut lat_sorted = a.latencies.clone();
        lat_sorted.sort_unstable();
        println!(
            "matched {}/{} lines, {} bytes, 4xx={} 5xx={}",
            filtered.len(),
            parsed_count,
            a.bytes_total,
            a.errors_4xx,
            a.errors_5xx
        );
        if !lat_sorted.is_empty() {
            println!(
                "latency p50={}ms p95={}ms p99={}ms",
                percentile(&lat_sorted, 50.0).unwrap_or(0),
                percentile(&lat_sorted, 95.0).unwrap_or(0),
                percentile(&lat_sorted, 99.0).unwrap_or(0)
            );
        }
        println!("top IPs:");
        for (ip, count) in top_n(&a.by_ip, opts.top) {
            println!("  {ip:>16}  {count}");
        }
        println!("top paths:");
        for (path, count) in top_n(&a.by_path, opts.top) {
            println!("  {:>28}  {count}", truncate_path(&path, 28));
        }
        println!("status codes:");
        let mut codes: Vec<_> = a.by_status.iter().collect();
        codes.sort_by_key(|(k, _)| **k);
        for (code, count) in codes {
            println!("  {code}: {count}");
        }
        return;
    }

    for e in &filtered {
        match e.latency_ms {
            Some(l) => println!(
                "{} {} {} {} {} {}ms",
                e.ip, e.method, e.path, e.status, e.bytes, l
            ),
            None => println!("{} {} {} {} {}", e.ip, e.method, e.path, e.status, e.bytes),
        }
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn truncate_path(p: &str, max: usize) -> String {
    if p.len() <= max {
        return p.to_string();
    }
    format!("…{}", &p[p.len() - max + 1..])
}
