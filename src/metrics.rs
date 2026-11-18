use std::time::SystemTime;

use crate::config::IPVersion;

/// Métriques et statistiques du client DDNS.
#[derive(Clone, Debug)]
pub struct DDNSMetrics {
    pub start_time: SystemTime,
    pub total_checks: u64,
    pub successful_updates: u64,
    pub failed_updates: u64,
    pub skipped_updates: u64,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_update_time: Option<SystemTime>,
    pub last_error: Option<String>,
    pub consecutive_errors: u64,
}

impl DDNSMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_check(&mut self) {
        self.total_checks += 1;
    }

    pub fn record_success(&mut self, ip_version: IPVersion, ip: &str) {
        self.successful_updates += 1;
        self.consecutive_errors = 0;
        self.last_update_time = Some(SystemTime::now());
        self.last_error = None;

        match ip_version {
            IPVersion::IPv4 => self.last_ipv4 = Some(ip.to_string()),
            IPVersion::IPv6 => self.last_ipv6 = Some(ip.to_string()),
        }
    }

    pub fn record_failure(&mut self, error: &str) {
        self.failed_updates += 1;
        self.consecutive_errors += 1;
        self.last_error = Some(error.to_string());
    }

    pub fn record_skip(&mut self) {
        self.skipped_updates += 1;
    }

    pub fn uptime_seconds(&self) -> f64 {
        SystemTime::now()
            .duration_since(self.start_time)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    pub fn summary(&self) -> String {
        let uptime_hours = self.uptime_seconds() / 3600.0;
        format!(
            "Uptime: {:.1}h | Checks: {} | Updates: {} OK, {} KO, {} skip | IPv4: {} | IPv6: {}",
            uptime_hours,
            self.total_checks,
            self.successful_updates,
            self.failed_updates,
            self.skipped_updates,
            self.last_ipv4.as_deref().unwrap_or("N/A"),
            self.last_ipv6.as_deref().unwrap_or("N/A"),
        )
    }
}

impl Default for DDNSMetrics {
    fn default() -> Self {
        Self {
            start_time: SystemTime::now(),
            total_checks: 0,
            successful_updates: 0,
            failed_updates: 0,
            skipped_updates: 0,
            last_ipv4: None,
            last_ipv6: None,
            last_update_time: None,
            last_error: None,
            consecutive_errors: 0,
        }
    }
}
