use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use log::{debug, error, info, warn};
use reqwest::blocking::{Client, Response};
use serde_json::Value;

use crate::config::{
    IPVersion, INFOMANIAK_API_URL, IPV4_SERVICES, IPV6_SERVICES, RunningFlag, USER_AGENT,
};
use crate::metrics::DDNSMetrics;
use crate::{UpdateResult, UpdateStatus};

macro_rules! debug_log {
    ($($arg:tt)*) => {
        debug!($($arg)*)
    };
}

/// Client DDNS Infomaniak pour un seul hostname.
///
/// Fonctionnalités:
///   - Support IPv4 et IPv6
///   - Retry avec backoff exponentiel
///   - Failover entre plusieurs services de détection IP
///   - Arrêt gracieux sur signaux système
///   - Métriques et statistiques
///   - Logging structuré
pub struct InfomaniakDDNSClient {
    pub config: crate::config::DDNSConfig,
    pub metrics: DDNSMetrics,
    pub running: Arc<RunningFlag>,
    http_client: Client,
    attempted_ips: HashMap<IPVersion, Option<String>>,
}

impl InfomaniakDDNSClient {
    pub fn new(config: crate::config::DDNSConfig) -> Result<Self, reqwest::Error> {
        let http_client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(config.request_timeout))
            .build()?;

        Ok(Self {
            config,
            metrics: DDNSMetrics::new(),
            running: Arc::new(RunningFlag::new()),
            http_client,
            attempted_ips: HashMap::from([
                (IPVersion::IPv4, None),
                (IPVersion::IPv6, None),
            ]),
        })
    }

    pub fn setup_signal_handlers(running: Arc<RunningFlag>) {
        let running_clone = running.clone();
        ctrlc::set_handler(move || {
            info!("Signal SIGINT/SIGTERM reçu, arrêt gracieux...");
            running_clone.set_running(false);
        })
        .expect("Impossible d'installer le gestionnaire de signaux");
    }

    pub fn run_forever(&mut self) {
        info!("{}", "=".repeat(60));
        info!("DDNS Infomaniak - Démarrage du service");
        info!("{}", "=".repeat(60));
        info!("Hostname: {}", self.config.hostname);
        info!("IPv6: {}", if self.config.enable_ipv6 { "activé" } else { "désactivé" });
        info!("Intervalle: {}s", self.config.interval_seconds);
        info!("{}", "=".repeat(60));

        let running = Arc::clone(&self.running);

        Self::setup_signal_handlers(Arc::clone(&running));

        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            while running.is_running() {
                self._run_cycle();

                if self.metrics.total_checks % 10 == 0 && self.metrics.total_checks > 0 {
                    info!("📊 {}", self.metrics.summary());
                }

                self._interruptible_sleep(self.config.interval_seconds, &running);
            }
            Ok(())
        })();

        if let Err(exc) = result {
            error!("Erreur fatale non gérée: {exc}");
        }

        info!("Service arrêté. {}", self.metrics.summary());
    }

    pub fn check_and_update(&mut self, ip_version: IPVersion) -> UpdateResult {
        info!("--- Vérification {} ---", ip_version);

        // 1. Obtenir l'IP publique
        let public_ip = match self._get_public_ip(ip_version) {
            Some(ip) => ip,
            None => {
                if ip_version == IPVersion::IPv6 {
                    info!("Aucune IPv6 publique détectée, {ip_version} ignoré");
                    self.metrics.record_skip();
                    return UpdateResult::skipped(
                        ip_version,
                        "Aucune IPv6 publique détectée",
                    );
                }
                warn!("Impossible d'obtenir l'IP publique {ip_version}");
                return UpdateResult::error(
                    ip_version,
                    None,
                    "Échec récupération IP publique",
                );
            }
        };

        // 2. Valider l'IP
        if !self._validate_ip(&public_ip, ip_version) {
            warn!("IP {ip_version} invalide: {public_ip}");
            return UpdateResult::error(ip_version, Some(public_ip.clone()), "IP invalide");
        }

        info!("IP publique {ip_version}: {public_ip}");

        // 3. Résoudre l'IP actuelle dans le DNS
        let current_dns_ip = self._resolve_hostname(ip_version);
        if let Some(ref dns_ip) = current_dns_ip {
            info!("IP DNS actuelle: {dns_ip}");
        } else {
            info!(
                "Aucun enregistrement {ip_version} existant pour {}",
                self.config.hostname
            );
        }

        // 4. Comparer et décider (comparaison d'adresses IP, pas de chaînes brutes)
        let public_ip_addr = public_ip.parse::<IpAddr>().ok();
        let current_dns_ip_addr = current_dns_ip.as_ref().and_then(|ip| ip.parse::<IpAddr>().ok());

        if public_ip_addr.is_some() && public_ip_addr == current_dns_ip_addr {
            info!("IP inchangée, aucune mise à jour nécessaire");
            self.attempted_ips.insert(ip_version, Some(public_ip.clone()));
            return UpdateResult::no_change(ip_version, public_ip);
        }

        // 5. Anti-boucle: éviter de retenter la même IP
        if self.attempted_ips.get(&ip_version) == Some(&Some(public_ip.clone())) {
            debug_log!("IP déjà tentée récemment, on attend le prochain cycle");
            self.metrics.record_skip();
            return UpdateResult::skipped(ip_version, "Déjà tentée");
        }

        // 6. Mise à jour
        self._update_dns(&public_ip, ip_version)
    }

    fn _run_cycle(&mut self) {
        self.metrics.record_check();

        let result_v4 = self.check_and_update(IPVersion::IPv4);
        self._process_result(result_v4);

        if self.config.enable_ipv6 {
            let result_v6 = self.check_and_update(IPVersion::IPv6);
            self._process_result(result_v6);
        }
    }

    fn _process_result(&mut self, result: UpdateResult) {
        match result.status {
            UpdateStatus::Success => {
                if let Some(ref ip) = result.ip_address {
                    self.metrics.record_success(result.ip_version, ip);
                }
            }
            UpdateStatus::Error => {
                self.metrics.record_failure(&result.message);
            }
            UpdateStatus::Skipped => {
                self.metrics.record_skip();
            }
            UpdateStatus::NoChange => {}
        }
    }

    fn _interruptible_sleep(&self, seconds: u64, running: &Arc<RunningFlag>) {
        let end_time = SystemTime::now() + Duration::from_secs(seconds);
        while running.is_running() && SystemTime::now() < end_time {
            let remaining = end_time.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
            let step = remaining.min(Duration::from_secs(1));
            std::thread::sleep(step);
        }
    }

    fn _get_public_ip(&self, ip_version: IPVersion) -> Option<String> {
        let services = match ip_version {
            IPVersion::IPv4 => IPV4_SERVICES,
            IPVersion::IPv6 => IPV6_SERVICES,
        };

        for service_url in services {
            match self._fetch_ip_from_service(service_url) {
                Ok(Some(ip)) if self._validate_ip(&ip, ip_version) => return Some(ip),
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(exc) => {
                    debug_log!("Service {service_url} échec: {exc}");
                }
            }
        }

        None
    }

    fn _fetch_ip_from_service(&self, url: &str) -> Result<Option<String>, reqwest::Error> {
        let response = self.http_client.get(url).send()?;
        let status = response.status();
        if !status.is_success() {
            return Ok(None);
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("json") {
            let data: Value = response.json()?;
            let ip = data
                .get("ip")
                .or_else(|| data.get("origin"))
                .or_else(|| data.get("address"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(ip)
        } else {
            let text = response.text()?;
            let ip = text.trim();
            if ip.is_empty() {
                Ok(None)
            } else {
                Ok(Some(ip.to_string()))
            }
        }
    }

    fn _validate_ip(&self, ip: &str, ip_version: IPVersion) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(addr) => match ip_version {
                IPVersion::IPv4 => addr.is_ipv4(),
                IPVersion::IPv6 => addr.is_ipv6(),
            },
            Err(_) => false,
        }
    }

    fn _resolve_hostname(&self, ip_version: IPVersion) -> Option<String> {
        let query_type = match ip_version {
            IPVersion::IPv4 => 1u16,   // A
            IPVersion::IPv6 => 28u16,  // AAAA
        };

        for dns_server in crate::config::DNS_SERVERS {
            match self._query_dns(dns_server, &self.config.hostname, query_type) {
                Ok(Some(ip)) => return Some(ip),
                Ok(None) => continue,
                Err(exc) => {
                    debug_log!("DNS {dns_server} échec: {exc}");
                }
            }
        }

        None
    }

    fn _query_dns(
        &self,
        server: &str,
        hostname: &str,
        query_type: u16,
    ) -> Result<Option<String>, std::io::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        let mut query = Vec::with_capacity(256);
        // ID de transaction
        query.extend_from_slice(&[0x00, 0x01]);
        // Flags : requête standard, récursion désirée (0x0100)
        query.extend_from_slice(&[0x01, 0x00]);
        // QDCOUNT = 1
        query.extend_from_slice(&[0x00, 0x01]);
        // ANCOUNT = 0
        query.extend_from_slice(&[0x00, 0x00]);
        // NSCOUNT = 0
        query.extend_from_slice(&[0x00, 0x00]);
        // ARCOUNT = 0
        query.extend_from_slice(&[0x00, 0x00]);

        // Question : nom encodé en étiquettes longueur-préfixe
        for label in hostname.split('.') {
            if !label.is_empty() {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
        }
        query.push(0x00); // racine (fin du nom)

        // Type de requête (A ou AAAA)
        query.extend_from_slice(&query_type.to_be_bytes());
        // Classe IN = 1
        query.extend_from_slice(&[0x00, 0x01]);

        socket.send_to(&query, server)?;

        let mut buf = [0u8; 512];
        let (n, _) = socket.recv_from(&mut buf)?;

        Self::_parse_dns_response(&buf[..n], query_type)
    }

    fn _parse_dns_response(buf: &[u8], query_type: u16) -> Result<Option<String>, std::io::Error> {
        if buf.len() < 12 {
            return Ok(None);
        }

        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);

        // Sauter l'en-tête (12 octets) puis la section question
        let mut offset = 12;
        Self::_skip_dns_name(buf, &mut offset)?;
        offset += 4; // type + classe de la question

        for _ in 0..answer_count {
            Self::_skip_dns_name(buf, &mut offset)?;

            if offset + 10 > buf.len() {
                break;
            }

            let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let _rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let _ttl = u32::from_be_bytes([
                buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]);
            offset += 10;

            if rtype == query_type && offset + rdlength as usize <= buf.len() {
                match query_type {
                    1 if rdlength == 4 => {
                        return Ok(Some(format!(
                            "{}.{}.{}.{}",
                            buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]
                        )));
                    }
                    28 if rdlength == 16 => {
                        let mut ip = String::new();
                        for i in 0..8 {
                            if i > 0 {
                                ip.push(':');
                            }
                            ip.push_str(&format!(
                                "{:02x}{:02x}",
                                buf[offset + i * 2],
                                buf[offset + i * 2 + 1]
                            ));
                        }
                        return Ok(Some(ip));
                    }
                    _ => {}
                }
            }

            offset += rdlength as usize;
        }

        Ok(None)
    }

    fn _skip_dns_name(buf: &[u8], offset: &mut usize) -> Result<(), std::io::Error> {
        loop {
            if *offset >= buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "DNS name truncated",
                ));
            }

            let len = buf[*offset] as usize;
            *offset += 1;

            if len == 0 {
                break;
            }

            if (len & 0xC0) == 0xC0 {
                    // Pointeur de compression DNS (2 octets) : on saute juste le pointeur
                    *offset += 1;
                    break;
            }

            *offset += len;
        }

        Ok(())
    }

    fn _update_dns(&mut self, ip: &str, ip_version: IPVersion) -> UpdateResult {
        let url = format!(
            "{}?hostname={}&myip={}",
            INFOMANIAK_API_URL, self.config.hostname, ip
        );

        info!("Mise à jour DNS: {} -> {}", self.config.hostname, ip);

        let result = (|| -> Result<Response, reqwest::Error> {
            self.http_client
                .get(&url)
                .basic_auth(&self.config.username, Some(&self.config.password))
                .send()
        })();

        match result {
            Ok(response) => {
                let status = response.status();
                let text = response.text().unwrap_or_default();
                let text_lower = text.trim().to_lowercase();
                debug_log!("Réponse API [{status}]: {text_lower}");

                let result = self._parse_api_response(&text_lower, ip, ip_version);

                // Mémoriser l'IP tentée
                self.attempted_ips.insert(ip_version, Some(ip.to_string()));

                result
            }
            Err(exc) if exc.is_timeout() => {
                error!("Timeout de la requête");
                self.attempted_ips.insert(ip_version, Some(ip.to_string()));
                UpdateResult::error(
                    ip_version,
                    Some(ip.to_string()),
                    "Timeout de la requête",
                )
            }
            Err(exc) => {
                error!("Erreur HTTP: {exc}");
                self.attempted_ips.insert(ip_version, Some(ip.to_string()));
                UpdateResult::error(
                    ip_version,
                    Some(ip.to_string()),
                    format!("Erreur HTTP: {exc}"),
                )
            }
        }
    }

    fn _parse_api_response(
        &self,
        text: &str,
        ip: &str,
        ip_version: IPVersion,
    ) -> UpdateResult {
        // Mapping des réponses Infomaniak
        let responses: &[(&str, UpdateStatus, &str, &str)] = &[
            (
                "good",
                UpdateStatus::Success,
                "DNS mis à jour avec succès",
                "✅ DNS mis à jour",
            ),
            (
                "nochg",
                UpdateStatus::NoChange,
                "IP déjà configurée",
                "✅ IP déjà à jour",
            ),
            ("nohost", UpdateStatus::Error, "Hostname inconnu", "❌ Hostname inconnu chez Infomaniak"),
            (
                "badauth",
                UpdateStatus::Error,
                "Identifiants invalides",
                "❌ Identifiants invalides",
            ),
            ("abuse", UpdateStatus::Error, "Limite/abuse détecté", "❌ Abuse détecté"),
            (
                "badagent",
                UpdateStatus::Error,
                "User-Agent rejeté",
                "❌ User-Agent non accepté",
            ),
            (
                "911",
                UpdateStatus::Error,
                "Erreur serveur temporaire",
                "⚠️ Erreur serveur, réessayer plus tard",
            ),
        ];

        for (keyword, status, message, log_action) in responses {
            if text.contains(keyword) {
                info!("{log_action}");
                return UpdateResult {
                    status: *status,
                    ip_version,
                    ip_address: Some(ip.to_string()),
                    message: message.to_string(),
                    timestamp: SystemTime::now(),
                };
            }
        }

        // Réponse non reconnue
        warn!("Réponse non reconnue: {text}");
        UpdateResult::error(
            ip_version,
            Some(ip.to_string()),
            format!("Réponse inconnue: {text}"),
        )
    }

    pub fn close(&mut self) {
        // reqwest::Client n'a pas de méthode close explicite; il est libéré avec le client.
    }
}

/// Orchestrateur pour exécuter plusieurs clients DDNS.
pub struct InfomaniakDDNSService {
    pub clients: Vec<InfomaniakDDNSClient>,
}

impl InfomaniakDDNSService {
    pub fn new(clients: Vec<InfomaniakDDNSClient>) -> Result<Self, String> {
        if clients.is_empty() {
            return Err("Aucune configuration DDNS valide trouvée".to_string());
        }
        Ok(Self { clients })
    }

    pub fn run_forever(&mut self) {
        let hostnames: Vec<String> = self.clients.iter().map(|c| c.config.hostname.clone()).collect();
        info!("Configurations DDNS chargées: {}", self.clients.len());
        info!("Hostnames: {}", hostnames.join(", "));

        let intervals: Vec<u64> = self.clients.iter().map(|c| c.config.interval_seconds).collect();
        let interval_seconds = intervals.iter().min().copied().unwrap_or(300);

        if intervals.iter().any(|&i| i != intervals[0]) {
            warn!(
                "Intervalles différents détectés ({:?}), utilisation du minimum: {}s",
                intervals,
                interval_seconds
            );
        }

        let running_flags: Vec<Arc<RunningFlag>> = self
            .clients
            .iter()
            .map(|c| Arc::clone(&c.running))
            .collect();

        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            while running_flags.iter().any(|f| f.is_running()) {
                for client in &mut self.clients {
                    if !client.running.is_running() {
                        continue;
                    }

                    client._run_cycle();

                    if client.metrics.total_checks % 10 == 0 && client.metrics.total_checks > 0 {
                        info!(
                            "📊 [{}] {}",
                            client.config.hostname,
                            client.metrics.summary()
                        );
                    }
                }

                let running_any = running_flags.iter().any(|f| f.is_running());
                if running_any {
                    let end_time = SystemTime::now() + Duration::from_secs(interval_seconds);
                    while running_flags.iter().any(|f| f.is_running()) && SystemTime::now() < end_time {
                        let remaining = end_time.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
                        let step = remaining.min(Duration::from_secs(1));
                        std::thread::sleep(step);
                    }
                }
            }
            Ok(())
        })();

        if let Err(exc) = result {
            error!("Erreur fatale non gérée dans le service multi-DDNS: {exc}");
        }

        for client in &mut self.clients {
            client.close();
        }
    }
}

/// Crée une liste de clients DDNS depuis les variables d'environnement.
pub fn from_env_clients() -> Result<Vec<InfomaniakDDNSClient>, String> {
    let configs = crate::config::DDNSConfig::from_env_list()?;
    configs
        .into_iter()
        .map(|config| InfomaniakDDNSClient::new(config).map_err(|e| e.to_string()))
        .collect()
}

/// Crée un service DDNS (mono ou multi-domaines) depuis les variables d'environnement.
pub fn from_env() -> Result<InfomaniakDDNSService, String> {
    let clients = from_env_clients()?;
    InfomaniakDDNSService::new(clients)
}

