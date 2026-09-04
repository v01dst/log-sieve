use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub ip: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub status: u16,
    pub bytes: u64,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct EntryOwned {
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    pub latency_ms: Option<u64>,
}

/// Parse a combined-log-format line:
/// IP - - [time] "METHOD path PROTO" status bytes "referer" "agent" [latency]
/// Latency is an optional trailing field: `latency=123ms`.
pub fn parse_line(line: &str) -> Option<EntryOwned> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let open = line.find('"')?;
    let close = line[open + 1..].find('"')? + open + 1;
    let request = &line[open + 1..close];

    let mut req_parts = request.split_whitespace();
    let method = req_parts.next()?.to_string();
    let path = req_parts.next()?.to_string();
    if method.is_empty() || path.is_empty() {
        return None;
    }

    let after = &line[close + 1..];
    let mut tokens = after.split_whitespace();
    let status: u16 = tokens.next()?.parse().ok()?;
    let bytes: u64 = match tokens.next() {
        Some("-") => 0,
        Some(b) => b.parse().ok()?,
        None => 0,
    };

    let latency_ms = line
        .rsplit("latency=")
        .next()
        .and_then(|tail| {
            if tail == line.rsplit("latency=").next()? {
                tail.trim_end_matches("ms").trim().parse::<u64>().ok()
            } else {
                None
            }
        })
        .or_else(|| {
            let idx = line.find("latency=")?;
            let tail = &line[idx + 8..];
            let end = tail
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(tail.len());
            tail[..end].parse::<u64>().ok()
        });

    let ip = line[..open].split_whitespace().next()?.to_string();

    Some(EntryOwned {
        ip,
        method,
        path,
        status,
        bytes,
        latency_ms,
    })
}

#[derive(Debug, Default)]
pub struct Analysis {
    pub total: usize,
    pub by_status: HashMap<u16, usize>,
    pub by_ip: HashMap<String, usize>,
    pub by_path: HashMap<String, usize>,
    pub bytes_total: u64,
    pub latencies: Vec<u64>,
    pub errors_4xx: usize,
    pub errors_5xx: usize,
}

pub fn analyze(entries: &[EntryOwned]) -> Analysis {
    let mut a = Analysis::default();
    for e in entries {
        a.total += 1;
        *a.by_status.entry(e.status).or_insert(0) += 1;
        *a.by_ip.entry(e.ip.clone()).or_insert(0) += 1;
        *a.by_path.entry(e.path.clone()).or_insert(0) += 1;
        a.bytes_total += e.bytes;
        if let Some(l) = e.latency_ms {
            a.latencies.push(l);
        }
        if (400..500).contains(&e.status) {
            a.errors_4xx += 1;
        }
        if e.status >= 500 {
            a.errors_5xx += 1;
        }
    }
    a
}

pub fn top_n(map: &HashMap<String, usize>, n: usize) -> Vec<(String, usize)> {
    let mut pairs: Vec<(String, usize)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    pairs.truncate(n);
    pairs
}

pub fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted.get(idx).copied()
}
