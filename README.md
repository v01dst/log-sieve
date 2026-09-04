<div align="center">

# 🔍 log-sieve

**HTTP access log analyzer — filter by status/IP/path, top-N reports, latency percentiles.**

[![CI](https://github.com/v01dst/log-sieve/actions/workflows/ci.yml/badge.svg)](https://github.com/v01dst/log-sieve/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-8A2BE2)
![Rust](https://img.shields.io/badge/rust-1.96-DEA584?logo=rust&logoColor=white)
![Deps](https://img.shields.io/badge/dependencies-zero-00c853)
![Tests](https://img.shields.io/badge/tests-7%20passing-brightgreen)

`combined format` · `status classes` · `p50/p95/p99` · `json summary` · `stdin pipelines`

</div>

---

## ✨ Features

- **📄 Combined-log parser** — standard access logs, `latency=` extension supported
- **🎯 Filters** — exact status, status class (`2xx`…`5xx`), IP, path prefix
- **📊 Aggregate report** — top IPs, top paths, status histogram, byte totals
- **⏱️ Latency percentiles** — p50 / p95 / p99 when logs carry latency
- **🤖 JSON mode** — hand-rolled, zero dependencies
- **🔁 Unix-native** — stdin or file, perfect for pipes and cron

## 🚀 Quick Start

```bash
git clone https://github.com/v01dst/log-sieve
cd log-sieve
cargo build --release
./target/release/log-sieve --summary access.log
```

Or with Docker:

```bash
docker build -t log-sieve .
docker run --rm -i log-sieve --summary < access.log
```

## 📖 Usage

```
log-sieve [OPTIONS] [FILE]

  --status CODE    only lines with this status
  --class 4xx|5xx  only lines in this status class
  --ip IP          only lines from this IP
  --path PREFIX    only lines whose path starts with PREFIX
  --top N          top N IPs/paths in summary
  --summary        aggregate report
  --json           machine-readable summary
```

### Examples

```bash
$ tail -n 1000 access.log | log-sieve --summary
matched 1000/1000 lines, 4.2 MB, 4xx=37 5xx=3
latency p50=12ms p95=210ms p99=455ms
top IPs:
       203.0.113.7  312
top paths:
                    /api/users  401

$ log-sieve --class 5xx --json access.log | jq '.latency_ms.p99'

$ grep "POST" access.log | log-sieve --summary --top 10
```

## 🧱 Tech Stack

| Layer     | Tech              |
|-----------|-------------------|
| Language  | Rust (zero deps)  |
| Testing   | cargo test        |
| Packaging | Docker (multi-stage) |
| CI        | GitHub Actions    |

---

<div align="center">

Built with ⚡ by **v01dst**

[![GitHub](https://img.shields.io/badge/github-v01dst-181717?logo=github)](https://github.com/v01dst)
[![Discord](https://img.shields.io/badge/discord-9p.1-5865F2?logo=discord&logoColor=white)](https://discord.com/users/9p.1)

</div>
