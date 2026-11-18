pub mod client;
pub mod config;
pub mod metrics;

pub use client::{from_env, from_env_clients, InfomaniakDDNSClient, InfomaniakDDNSService};
pub use config::{DDNSConfig, IPVersion, UpdateResult, UpdateStatus};
pub use metrics::DDNSMetrics;
