/// Metrics collector — in-memory ring buffer for request and pipeline metrics.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::Instant;

pub struct Metrics {
    pub requests_total: AtomicU64,
    pub requests_by_status: RwLock<HashMap<u16, u64>>,
    pub requests_by_path: RwLock<HashMap<String, u64>>,
    pub latencies_ms: RwLock<Vec<f64>>,
    pub errors_total: AtomicU64,
    pub pipeline_runs: AtomicU64,
    pub pipeline_latencies_ms: RwLock<Vec<f64>>,
    pub active_connections: AtomicUsize,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub start_time: Instant,
}

pub static GLOBAL_METRICS: once_cell::sync::Lazy<Metrics> =
    once_cell::sync::Lazy::new(|| Metrics {
        requests_total: AtomicU64::new(0),
        requests_by_status: RwLock::new(HashMap::new()),
        requests_by_path: RwLock::new(HashMap::new()),
        latencies_ms: RwLock::new(Vec::with_capacity(10000)),
        errors_total: AtomicU64::new(0),
        pipeline_runs: AtomicU64::new(0),
        pipeline_latencies_ms: RwLock::new(Vec::with_capacity(10000)),
        active_connections: AtomicUsize::new(0),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        start_time: Instant::now(),
    });

impl Metrics {
    pub fn record_request(&self, status: u16, path: &str, latency_ms: f64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        if status >= 400 {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }

        if let Ok(mut map) = self.requests_by_status.write() {
            *map.entry(status).or_insert(0) += 1;
        }

        // Normalize path: strip query params and numeric IDs
        let normalized = normalize_path(path);
        if let Ok(mut map) = self.requests_by_path.write() {
            // L1 FIX: Evict when map grows too large to prevent memory leak
            if map.len() > 500 {
                // Keep only the top 250 by count
                let mut entries: Vec<_> = map.drain().collect();
                entries.sort_by_key(|item| std::cmp::Reverse(item.1));
                entries.truncate(250);
                map.extend(entries);
            }
            *map.entry(normalized).or_insert(0) += 1;
        }

        if let Ok(mut latencies) = self.latencies_ms.write() {
            latencies.push(latency_ms);
            if latencies.len() > 10000 {
                latencies.drain(0..5000);
            }
        }
    }

    pub fn record_pipeline_run(&self, latency_ms: f64) {
        self.pipeline_runs.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut latencies) = self.pipeline_latencies_ms.write() {
            latencies.push(latency_ms);
            if latencies.len() > 1000 {
                latencies.drain(0..500);
            }
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let latencies = self.latencies_ms.read().unwrap_or_else(|e| e.into_inner());
        let data = &*latencies;

        let pipeline_latencies = self
            .pipeline_latencies_ms
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let pdata = &*pipeline_latencies;

        let status_map = self
            .requests_by_status
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let sdata = &*status_map;

        let path_map = self
            .requests_by_path
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let patdata = &*path_map;

        let p50 = percentile(data, 50.0);
        let p95 = percentile(data, 95.0);
        let p99 = percentile(data, 99.0);
        let pipeline_p50 = percentile(pdata, 50.0);

        MetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            requests_by_status: sdata.clone(),
            top_paths: top_n(patdata, 10),
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            pipeline_runs: self.pipeline_runs.load(Ordering::Relaxed),
            pipeline_latency_p50_ms: pipeline_p50,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub requests_total: u64,
    pub errors_total: u64,
    pub requests_by_status: HashMap<u16, u64>,
    pub top_paths: Vec<(String, u64)>,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub pipeline_runs: u64,
    pub pipeline_latency_p50_ms: f64,
    pub active_connections: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let mut v: Vec<f64> = sorted.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((p / 100.0) * (v.len() as f64)) as usize;
    v[idx.min(v.len() - 1)]
}

fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut entries: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by_key(|item| std::cmp::Reverse(item.1));
    entries.truncate(n);
    entries
}

fn normalize_path(path: &str) -> String {
    let base = path.split('?').next().unwrap_or(path);
    let parts: Vec<&str> = base.split('/').collect();
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i >= 3 && p.parse::<u64>().is_ok() {
                ":id"
            } else if i >= 3 && p.len() > 20 {
                ":param"
            } else {
                p
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
