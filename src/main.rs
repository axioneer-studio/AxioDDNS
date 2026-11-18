use std::path::Path;

use axioddns::{from_env, DDNSConfig};
use dotenvy::from_path;
use log::error;

/// Point d'entrée principal du service DDNS Infomaniak.
///
/// Charge le fichier `.env` s'il existe (pour exécution locale),
/// puis crée le service DDNS depuis les variables d'environnement
/// et lance la boucle de mise à jour.
fn main() {
    // Charger le fichier .env s'il existe (pour exécution locale)
    let env_path = Path::new(".env");
    if env_path.exists() {
        if let Err(e) = from_path(env_path) {
            eprintln!("⚠️  Impossible de charger .env: {e}");
        }
    }

    // Initialiser le logging (niveau depuis DDNS_LOG_LEVEL, défaut INFO)
    let log_level = std::env::var("DDNS_LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
    env_logger::Builder::from_env(env_logger::Env::default().filter_or(
        env_logger::DEFAULT_FILTER_ENV,
        &log_level,
    ))
    .format(|buf, record| {
        use std::io::Write;
        writeln!(buf, "{:<7} | {}", record.level(), record.args())
    })
    .init();

    match run() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            error!("❌ Erreur de configuration: {e}");
            eprintln!("\nVariables d'environnement requises:");
            eprintln!("  - Mode simple:");
            eprintln!("    INFOMANIAK_DDNS_HOSTNAME");
            eprintln!("    INFOMANIAK_DDNS_USERNAME");
            eprintln!("    INFOMANIAK_DDNS_PASSWORD");
            eprintln!("  - Mode multi-domaines:");
            eprintln!("    INFOMANIAK_DDNS_HOSTNAME_X");
            eprintln!("    INFOMANIAK_DDNS_USERNAME_X");
            eprintln!("    INFOMANIAK_DDNS_PASSWORD_X");
            eprintln!("    (X = 1, 2, 3, ...)");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    // Valider la configuration avant de lancer le service (affiche une erreur claire si manquante)
    let _ = DDNSConfig::from_env()?;

    let mut service = from_env()?;
    service.run_forever();
    Ok(())
}
