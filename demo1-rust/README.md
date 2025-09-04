# 🛡️ Pulsar + Kepler Demo (Rust Implementation)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Security](https://img.shields.io/badge/security-vulnerability%20detection-red.svg)](https://exein.io)

Real-Time Vulnerable Process Detection using **Pulsar** (eBPF runtime security monitoring) and **Kepler** (vulnerability database).

This demonstration showcases the integration of two powerful security tools:
- **🔍 Pulsar**: eBPF-powered runtime security monitoring for Linux systems
- **🔗 Kepler**: Vulnerability database and lookup API using NIST NVD data
- **🦀 Demo Application**: Real-time integration built with Rust

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Prerequisites](#prerequisites)
- [Architecture](#-architecture)
- [Live Demo](#-live-demo-instructions)
- [API Documentation](#-web-dashboard)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## ✨ Features

- **🔍 Real-time Process Monitoring**: Cross-platform process detection with version extraction
- **🔗 Vulnerability Correlation**: Integrates with Kepler API for CVE lookups with intelligent caching
- **⚠️ Severity-based Alerting**: Configurable CVSS score thresholds for high-priority alerts
- **🌐 Web Dashboard**: Real-time dashboard with REST API endpoints
- **🎭 Mock Data Support**: Works offline with realistic vulnerability data for demo purposes
- **⚡ High Performance**: Async/await architecture with efficient LRU caching
- **🦀 Memory Safe**: Built with Rust for zero-cost abstractions and safety

## 🚀 Quick Start

### Prerequisites

#### Rust Installation
Install Rust 1.70+ using the official installer:
```bash
# Install Rust via rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow the on-screen instructions, then restart your shell or run:
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

#### Kepler API Server (Optional)
Start the Kepler vulnerability database API:
```bash
# Navigate to kepler directory
cd ../kepler

# Set required environment variable
export CONTAINER_SOCKET=/var/run/docker.sock

# Start with Docker (recommended)
docker compose build
docker compose up -d

# Verify Kepler is running
curl -H "Content-Type: application/json" -d '{"product":"nginx","version":"1.18.0"}' http://localhost:8000/cve/search

# Import vulnerability data (required for first time)
# Note: NIST.gov may be blocked by Cloudflare security measures
# If you encounter access issues, the demo works with mock data
docker exec kepler kepler import_nist 2024 -d /data

# Optional: Import all years (takes longer)
# for year in $(seq 2002 2025); do
#   docker exec kepler kepler import_nist $year -d /data
# done

# Test CVE search endpoint
curl -H "Content-Type: application/json" -d '{"product":"nginx","version":"1.18.0"}' http://localhost:8000/cve/search
```

**Note**: Demo works with mock data when Kepler API is unavailable.

#### Platform Support
- **Cross-platform**: Works on Linux, macOS, and Windows

### Installation & Usage

```bash
# Navigate to demo directory
cd demo1-rust

# Build the project (takes ~2-3 minutes first time)
cargo build --release

# Run the main demo application
cargo run

# Run with custom configuration
cargo run -- --port 8080 --min-cvss-score 5.0 --log-level debug

# Run system tests
cargo run -- --test

# View all options
cargo run -- --help
```

### 🌐 Web Dashboard

Once running, access the dashboard at: **http://localhost:3000**

**Available Endpoints:**
- `GET /` - Interactive dashboard (HTML)
- `GET /api/stats` - Engine statistics (JSON)
- `GET /api/vulnerabilities` - All vulnerability detections
- `GET /api/vulnerabilities?severity=high` - Filter by severity
- `GET /api/summary` - Comprehensive summary report
- `GET /api/events` - Recent events feed
- `GET /health` - Health check endpoint
- `GET /ws` - WebSocket endpoint (basic implementation)

## 🏗️ Architecture

### Core Components

1. **🖥️ Process Monitor** (`process_monitor.rs`)
   - Cross-platform process scanning using `sysinfo` crate
   - Version extraction via `--version` command attempts
   - Configurable process filtering and mock event generation
   - Periodic scanning with configurable intervals

2. **🔌 Kepler Client** (`kepler_client.rs`)
   - HTTP client with automatic retries and timeout handling
   - LRU cache for vulnerability lookups (configurable TTL)
   - Graceful fallback to mock CVE data when API unavailable
   - Support for product search and CVE correlation

3. **🧠 Vulnerability Engine** (`vulnerability_engine.rs`)
   - Event-driven architecture processing Pulsar-style events  
   - CVSS-based severity calculation and alert generation
   - Statistical tracking and historical vulnerability storage
   - Comprehensive reporting with severity breakdowns

4. **🌐 Web Server** (`web_server.rs`)
   - Axum-based HTTP server with CORS support
   - RESTful API with JSON responses
   - Embedded HTML dashboard (no external file dependencies)
   - Basic WebSocket support for future real-time updates

5. **⚙️ Configuration** (`config.rs`)
   - Command-line argument parsing with clap
   - Environment-aware defaults and validation
   - Centralized configuration management

### 📊 Data Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Process Monitor │───▶│ Vulnerability    │───▶│ Web Dashboard   │
│  (sysinfo)      │    │ Engine           │    │   (Axum)        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        │
                       ┌─────────────────┐              │
                       │ Kepler Client   │              │
                       │  (HTTP + Cache) │              │
                       └─────────────────┘              │
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ Kepler API      │    │ REST API        │
                       │ (or Mock Data)  │    │ /WebSocket      │
                       └─────────────────┘    └─────────────────┘
```

## 🧪 Testing

### System Test
```bash
cargo run -- --test
```
**What it tests:**
- Kepler API connectivity and response parsing
- Vulnerability engine event processing pipeline
- Mock process event generation and correlation
- Statistics collection and summary generation

### Unit Tests
```bash
cargo test
```
**Coverage:**
- Version parsing logic validation
- CVE severity calculation algorithms  
- Configuration parameter validation
- Mock data generation consistency

### Integration Testing with Mock Data

The demo includes comprehensive mock vulnerability data:

| **Software** | **Versions** | **CVEs** | **Severity** |
|--------------|--------------|----------|--------------|
| nginx        | 1.14.2, 1.18.0 | CVE-2019-20372, CVE-2021-23017 | MEDIUM, HIGH |
| sshd         | 7.4p1        | CVE-2018-15473, CVE-2020-14145 | MEDIUM |
| mysql        | 8.0.25       | CVE-2021-35604 | MEDIUM |

Even without Kepler API, you'll see realistic vulnerability alerts and dashboard updates.

## ⚙️ Configuration Options

```bash
Usage: demo [OPTIONS]

Options:
      --kepler-url <KEPLER_URL>          Kepler API base URL [default: http://localhost:8000]
      --host <HOST>                      Web server host [default: localhost]
  -p, --port <PORT>                      Web server port [default: 3000]
      --min-cvss-score <MIN_CVSS_SCORE>  Minimum CVSS score for alerts [default: 7.0]
      --cache-ttl <CACHE_TTL>            Cache TTL in seconds [default: 3600]
      --log-level <LOG_LEVEL>            Log level [default: info]
      --test                             Run test mode
  -h, --help                             Print help
```

### Environment Variables
```bash
export RUST_LOG=debug                    # Enable debug logging
export KEPLER_URL=https://api.kepler.io  # Custom Kepler endpoint
export PORT=8080                         # Custom port
```

## 🛠️ Development

### Project Structure
```
src/
├── main.rs                  # Application entry point & CLI handling
├── config.rs               # Configuration management & validation
├── kepler_client.rs        # Kepler API client with caching
├── process_monitor.rs      # Cross-platform process monitoring
├── vulnerability_engine.rs # Core vulnerability detection logic
└── web_server.rs          # Web server & dashboard
```

### Adding New Monitored Process Types

1. **Update Configuration** (`config.rs`):
```rust
monitored_processes: vec![
    "nginx".to_string(),
    "your-process".to_string(), // Add here
],
```

2. **Add Version Detection** (`process_monitor.rs`):
```rust
async fn get_fallback_version(process_name: &str) -> String {
    match process_name {
        "your-process" => "1.2.3".to_string(), // Add fallback version
        _ => "unknown".to_string(),
    }
}
```

3. **Add Mock CVE Data** (`kepler_client.rs`):
```rust
fn get_mock_cve_data(&self, product: &str, version: &str) -> Vec<CVE> {
    match product {
        "your-process" => vec![/* your CVEs */],
        _ => vec![],
    }
}
```

### Extending Vulnerability Sources

1. Create new API client similar to `KeplerClient`
2. Update `VulnerabilityEngine` to query multiple sources  
3. Implement result deduplication and merging logic
4. Add configuration for additional endpoints

### Custom Alert Channels

1. **Modify Alert Generation** (`vulnerability_engine.rs`):
```rust
async fn generate_alerts(&self, detection: &VulnerabilityDetection) {
    // Add your custom notification logic:
    // - Email via SMTP
    // - Slack webhooks  
    // - Discord notifications
    // - PagerDuty integration
}
```

## 🚀 Production Considerations

### Performance Optimization
- **Cache Tuning**: Adjust `cache_ttl` and `max_cache_size` based on environment
- **Scan Intervals**: Increase `scan_interval` for high-process-count systems
- **Process Filtering**: Use `monitored_processes` to focus on critical software
- **Memory Monitoring**: Track RSS usage in long-running deployments

### Security Best Practices
- **Principle of Least Privilege**: Run with minimal required permissions
- **Input Validation**: All API responses are validated and sanitized
- **Rate Limiting**: Kepler client implements retry backoff to prevent API abuse
- **TLS Termination**: Use reverse proxy (nginx/Caddy) for HTTPS in production

### Deployment Options

#### Docker Deployment
```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/demo /usr/local/bin/demo
EXPOSE 3000
CMD ["demo"]
```

#### Systemd Service
```ini
[Unit]
Description=Pulsar-Kepler Vulnerability Detection Demo
After=network.target

[Service]
Type=simple
User=vulnmonitor  
ExecStart=/usr/local/bin/demo --port 3000
Restart=always
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

### Monitoring & Observability

#### Metrics Collection
```bash
# Health check endpoint
curl http://localhost:3000/health

# Statistics API
curl http://localhost:3000/api/stats | jq
```

#### Log Analysis
```bash
# Enable structured logging
RUST_LOG=info,pulsar_kepler_demo=debug ./demo

# Key log patterns to monitor:
# - "🚨 HIGH SEVERITY VULNERABILITY ALERT" (critical issues)
# - "⚠️ Kepler API unavailable" (connectivity issues) 
# - "📱 New WebSocket client connected" (dashboard usage)
```

## 🔧 Troubleshooting

### Common Build Issues

**Error: "could not compile `pulsar-kepler-demo`"**
```bash
# Clean build cache and retry
cargo clean
cargo build --release
```

**Error: "linking with cc failed"**
```bash
# Install build dependencies (Ubuntu/Debian)
sudo apt-get install build-essential pkg-config libssl-dev

# macOS
xcode-select --install
```

### Runtime Issues

**"Permission denied" reading processes**
- **Linux**: Some process info requires elevated privileges
- **Solution**: Run with `sudo` or filter monitored processes

**"Kepler API connection failed"**  
- **Expected**: Demo works with mock data when API unavailable
- **Solution**: Start Kepler API or verify URL with `curl http://localhost:8000/health`

**High memory usage**
- **Cause**: Large cache or many processes
- **Solution**: Reduce `cache_ttl`, limit `monitored_processes`, or increase `scan_interval`

**Web dashboard not accessible**
- **Check**: Firewall rules allowing port 3000
- **Test**: `curl http://localhost:3000/health`
- **Solution**: Use `--host 0.0.0.0` for external access

### Debug Mode
```bash
# Enable debug logging for detailed troubleshooting
RUST_LOG=debug cargo run

# Trace HTTP requests
RUST_LOG=trace,tower_http=debug cargo run
```

## 📈 Roadmap & Future Enhancements

- [ ] **Real Pulsar Integration**: Replace process simulation with actual eBPF probes
- [ ] **Advanced WebSocket**: Full real-time dashboard updates
- [ ] **Multiple Vulnerability Sources**: Support for additional CVE databases  
- [ ] **Machine Learning**: Anomaly detection and threat scoring
- [ ] **Container Support**: Docker/Kubernetes process monitoring
- [ ] **Compliance Reporting**: Generate reports for security audits
- [ ] **Alert Channels**: Email, Slack, Discord, PagerDuty notifications

## 🤝 Contributing

1. **Fork & Clone**: `git clone https://github.com/your-fork/demo1-rust`
2. **Create Branch**: `git checkout -b feature/your-feature`
3. **Test Changes**: `cargo test && cargo run -- --test`
4. **Format Code**: `cargo fmt`
5. **Check Lints**: `cargo clippy`
6. **Submit PR**: Include tests and documentation

## 📄 License

Apache-2.0 - see [LICENSE](../LICENSE) file for details.

---

## 🎯 Quick Demo Commands

```bash
# 1. Build (one-time setup)
cargo build --release

# 2. Run demo  
cargo run

# 3. Open dashboard
open http://localhost:3000

# 4. Watch logs for vulnerability alerts
# Look for: 🚨 HIGH SEVERITY VULNERABILITY ALERT
```

**Expected Output**: The demo will detect running processes, correlate them with vulnerability data, and display real-time alerts in both console logs and web dashboard! 🛡️

## 🎭 Step-by-Step Dashboard Demo Instructions

Follow this comprehensive demo flow to showcase the Pulsar + Kepler integration:

### **PHASE 1: Setup & Initial State**

#### **Step 1: Start the Demo**
```bash
# Terminal 1: Start with logging
cd demo1-rust
RUST_LOG=info cargo run --release
```
**Show:** Clean startup with all components initializing, Kepler API fallback to mock data, all counters at zero.

#### **Step 2: Open Dashboard**
```bash
# Open browser to
open http://localhost:3000
# or visit http://localhost:3000 manually
```
**Show:** Real-time dashboard interface with WebSocket auto-refresh every 2 seconds.

---

### **PHASE 2: API Endpoints Tour**

#### **Step 3: Demonstrate REST API**
```bash
# Terminal 2: API exploration
curl -s http://localhost:3000/api/stats | python3 -m json.tool
curl -s http://localhost:3000/api/summary | python3 -m json.tool  
curl -s http://localhost:3000/health
curl -s http://localhost:3000/api/vulnerabilities | python3 -m json.tool
curl -s "http://localhost:3000/api/vulnerabilities?severity=high" | python3 -m json.tool
```
**Show:** Clean JSON responses, health check status, comprehensive data structure.

---

### **PHASE 3: Generate Live Activity**

#### **Step 4: Trigger Vulnerability Detection**
```bash
# Terminal 3: Run test mode for immediate results
cargo run -- --test
```

**Expected Demo Flow:**
1. **Kepler API Test**: Shows connection attempt and fallback to mock data
2. **Process Simulation**: Creates mock nginx process event  
3. **Vulnerability Detection**: Finds CVE-2019-20372 (CVSS 5.3, MEDIUM)
4. **Event Processing**: Shows real-time event correlation
5. **Statistics Update**: Updates counters and severity breakdown

#### **Step 5: Verify Updated Data**
```bash
# Check updated statistics
curl -s http://localhost:3000/api/stats | python3 -m json.tool
```

**Expected Results:**
```json
{
    "events_processed": 1,
    "processes_scanned": 1,
    "vulnerabilities_found": 1,
    "high_severity_alerts": 0,
    "unique_vulnerable_processes": 1,
    "cache_hits": 0,
    "cache_misses": 1
}
```

---

### **PHASE 4: Key Features Showcase**

#### **Step 6: WebSocket Real-Time Updates**
**Watch Terminal 1 logs for:**
- `📱 New WebSocket client connected` (shows dashboard auto-refresh)
- `🔍 Checking vulnerabilities for [process] v[version]`
- `⚠️ Vulnerabilities detected in [process]`

#### **Step 7: Configuration Flexibility**
```bash
# Show different options
cargo run -- --help

# Example custom configurations  
cargo run -- --port 8080 --min-cvss-score 5.0 --log-level debug
```

---

### **PHASE 5: Demo Highlights**

#### **🔧 Technical Excellence**
- **Cross-platform**: Works on macOS, Linux, Windows
- **Memory Safe**: Rust zero-cost abstractions
- **High Performance**: Async/await with efficient caching
- **Graceful Fallback**: Offline operation with realistic mock data

#### **🎯 Business Value** 
- **Real-time Monitoring**: Immediate vulnerability detection
- **Risk Assessment**: CVSS-based severity scoring  
- **Integration Ready**: Complete REST API
- **Scalable Architecture**: Event-driven design

#### **🛡️ Security Focus**
- **Vulnerability Correlation**: Links processes to known CVEs
- **Severity-based Alerting**: Configurable CVSS thresholds
- **Comprehensive Reporting**: Detailed vulnerability breakdowns
- **Historical Tracking**: Process and vulnerability trends

#### **📊 Mock Data Examples**
The demo includes realistic vulnerability data:
- **nginx 1.14.2**: CVE-2019-20372 (CVSS 5.3, MEDIUM)
- **nginx 1.18.0**: CVE-2021-23017 (CVSS 8.1, HIGH)  
- **sshd 7.4p1**: 2 CVEs (MEDIUM severity)
- **mysql 8.0.25**: CVE-2021-35604 (CVSS 4.4, MEDIUM)

---

### **PHASE 6: Stop Demo**
```bash
# Press Ctrl+C in Terminal 1
# Observe graceful shutdown with proper cleanup
```

### **🎯 Demo Success Metrics**
✅ WebSocket connectivity (real-time updates)  
✅ API responsiveness (sub-100ms responses)  
✅ Vulnerability detection (CVE correlation)  
✅ Mock data fallback (offline operation)  
✅ Cross-platform compatibility  
✅ Configuration flexibility

**Key Message:** *"This demo showcases how Pulsar's eBPF runtime monitoring combines with Kepler's vulnerability database to create a comprehensive, real-time security solution built with Rust for maximum performance and safety."*