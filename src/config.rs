use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use regex::Regex;

/// Constantes du client DDNS Infomaniak.
pub const USER_AGENT: &str =
    "Infomaniak-DDNS/2.0 (+https://github.com/axioneer-studio/ddns-infomaniak)";
pub const INFOMANIAK_API_URL: &str = "https://infomaniak.com/nic/update";
pub const MIN_INTERVAL_SECONDS: u64 = 15;

/// Services de détection IP publique (avec failover), par version IP.
pub const IPV4_SERVICES: &[&str] = &[
    "https://api.ipify.org?format=json",
    "https://api.my-ip.io/v2/ip.json",
    "https://ipv4.icanhazip.com",
];
pub const IPV6_SERVICES: &[&str] = &[
    "https://api64.ipify.org?format=json",
    "https://api6.my-ip.io/v2/ip.json",
    "https://ipv6.icanhazip.com",
];

/// Serveurs DNS publics externes (avec failover) pour la résolution du hostname.
pub const DNS_SERVERS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"];

/// Version du protocole IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPVersion {
    IPv4,
    IPv6,
}

impl IPVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            IPVersion::IPv4 => "IPv4",
            IPVersion::IPv6 => "IPv6",
        }
    }
}

impl std::fmt::Display for IPVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Statut d'une tentative de mise à jour DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    Success,
    NoChange,
    Error,
    Skipped,
}

/// Résultat d'une tentative de mise à jour DNS.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub status: UpdateStatus,
    pub ip_version: IPVersion,
    pub ip_address: Option<String>,
    pub message: String,
    pub timestamp: std::time::SystemTime,
}

impl UpdateResult {
    pub fn success(ip_version: IPVersion, ip_address: impl Into<String>) -> Self {
        Self {
            status: UpdateStatus::Success,
            ip_version,
            ip_address: Some(ip_address.into()),
            message: "DNS mis à jour avec succès".to_string(),
            timestamp: std::time::SystemTime::now(),
        }
    }

    pub fn no_change(ip_version: IPVersion, ip_address: impl Into<String>) -> Self {
        Self {
            status: UpdateStatus::NoChange,
            ip_version,
            ip_address: Some(ip_address.into()),
            message: "IP identique".to_string(),
            timestamp: std::time::SystemTime::now(),
        }
    }

    pub fn error(
        ip_version: IPVersion,
        ip_address: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status: UpdateStatus::Error,
            ip_version,
            ip_address,
            message: message.into(),
            timestamp: std::time::SystemTime::now(),
        }
    }

    pub fn skipped(ip_version: IPVersion, message: impl Into<String>) -> Self {
        Self {
            status: UpdateStatus::Skipped,
            ip_version,
            ip_address: None,
            message: message.into(),
            timestamp: std::time::SystemTime::now(),
        }
    }
}

/// Configuration du client DDNS Infomaniak.
#[derive(Clone, Debug)]
pub struct DDNSConfig {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub interval_seconds: u64,
    pub enable_ipv6: bool,
    pub log_level: String,
    pub request_timeout: u64,
    pub max_retries: u32,
    pub retry_backoff_factor: f32,
}

impl DDNSConfig {
    /// Crée une configuration à partir de la première entrée d'environnement trouvée.
    pub fn from_env() -> Result<Self, String> {
        let configs = Self::from_env_list()?;
        configs
            .into_iter()
            .next()
            .ok_or_else(|| "Aucune configuration DDNS trouvée dans l'environnement".to_string())
    }

    /// Crée une liste de configurations à partir des variables d'environnement.
    ///
    /// Supporte le mode multi-domaines (INFOMANIAK_DDNS_HOSTNAME_1, ..._2, etc.)
    /// et le mode simple legacy (INFOMANIAK_DDNS_HOSTNAME sans indice).
    pub fn from_env_list() -> Result<Vec<Self>, String> {
        let interval = parse_u64("DDNS_INTERVAL_SECONDS", "300")?;
        let enable_ipv6 = parse_bool("DDNS_ENABLE_IPV6", false);
        let log_level = std::env::var("DDNS_LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
        let timeout = parse_u64("DDNS_REQUEST_TIMEOUT", "15")?;
        let max_retries = parse_u32("DDNS_MAX_RETRIES", "3")?;
        let backoff = parse_f32("DDNS_RETRY_BACKOFF", "1.0")?;

        // Détection des indices configurés (mode multi-domaines).
        let hostname_re = Regex::new(r"^INFOMANIAK_DDNS_HOSTNAME_(\d+)$").unwrap();
        let mut indexed_ids: HashSet<u32> = HashSet::new();
        for (key, _) in std::env::vars() {
            if let Some(captures) = hostname_re.captures(&key) {
                if let Ok(id) = captures[1].parse::<u32>() {
                    indexed_ids.insert(id);
                }
            }
        }

        let mut configs = Vec::new();

        if !indexed_ids.is_empty() {
            let mut ids: Vec<u32> = indexed_ids.into_iter().collect();
            ids.sort_unstable();

            for config_id in ids {
                let hostname = clean_env(&std::env::var(&format!("INFOMANIAK_DDNS_HOSTNAME_{config_id}")).unwrap_or_default());
                let username = clean_env(&std::env::var(&format!("INFOMANIAK_DDNS_USERNAME_{config_id}")).unwrap_or_default());
                let password = clean_env(&std::env::var(&format!("INFOMANIAK_DDNS_PASSWORD_{config_id}")).unwrap_or_default());

                let mut missing = Vec::new();
                if hostname.is_empty() {
                    missing.push(format!("INFOMANIAK_DDNS_HOSTNAME_{config_id}"));
                }
                if username.is_empty() {
                    missing.push(format!("INFOMANIAK_DDNS_USERNAME_{config_id}"));
                }
                if password.is_empty() {
                    missing.push(format!("INFOMANIAK_DDNS_PASSWORD_{config_id}"));
                }

                if !missing.is_empty() {
                    return Err(format!(
                        "Configuration DDNS #{config_id} incomplète: {}",
                        missing.join(", ")
                    ));
                }

                configs.push(Self {
                    hostname: hostname.trim().to_lowercase(),
                    username: username.trim().to_string(),
                    password,
                    interval_seconds: interval,
                    enable_ipv6,
                    log_level: log_level.clone(),
                    request_timeout: timeout,
                    max_retries,
                    retry_backoff_factor: backoff,
                });
            }

            return Ok(configs);
        }

        // Mode simple (legacy, un seul domaine).
        let hostname = clean_env(&std::env::var("INFOMANIAK_DDNS_HOSTNAME").unwrap_or_default());
        let username = clean_env(&std::env::var("INFOMANIAK_DDNS_USERNAME").unwrap_or_default());
        let password = clean_env(&std::env::var("INFOMANIAK_DDNS_PASSWORD").unwrap_or_default());

        configs.push(Self {
            hostname: hostname.trim().to_lowercase(),
            username: username.trim().to_string(),
            password,
            interval_seconds: interval,
            enable_ipv6,
            log_level,
            request_timeout: timeout,
            max_retries,
            retry_backoff_factor: backoff,
        });

        Ok(configs)
    }
}

/// Nettoie une valeur d'environnement (supprime guillemets et espaces).
pub fn clean_env(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let first = value.chars().next().unwrap();
        let last = value.chars().last().unwrap();
        if first == last && (first == '"' || first == '\'') {
            return value[1..value.len() - 1].trim().to_string();
        }
    }
    value.to_string()
}

fn parse_u64(key: &str, default: &str) -> Result<u64, String> {
    std::env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Variable d'environnement invalide: {key}"))
}

fn parse_u32(key: &str, default: &str) -> Result<u32, String> {
    std::env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("Variable d'environnement invalide: {key}"))
}

fn parse_f32(key: &str, default: &str) -> Result<f32, String> {
    std::env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .trim()
        .parse::<f32>()
        .map_err(|_| format!("Variable d'environnement invalide: {key}"))
}

fn parse_bool(key: &str, default: bool) -> bool {
    let default_str = if default { "true" } else { "false" };
    let value = std::env::var(key)
        .unwrap_or_else(|_| default_str.to_string())
        .trim()
        .to_lowercase();
    matches!(value.as_str(), "1" | "true" | "yes" | "on")
}

/// Drapeau d'arrêt partagé entre la boucle principale et le gestionnaire de signaux.
#[derive(Default)]
pub struct RunningFlag {
    inner: AtomicBool,
}

impl RunningFlag {
    pub fn new() -> Self {
        Self {
            inner: AtomicBool::new(true),
        }
    }

    pub fn set_running(&self, value: bool) {
        self.inner.store(value, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

