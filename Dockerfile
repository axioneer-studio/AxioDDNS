# =============================================================================
# Infomaniak DDNS Updater - Dockerfile (Rust)
# - Image multi-stage pour une taille minimale
# - Utilisateur non-root pour la sécurité
# - Labels OCI standards
# =============================================================================

# Stage 1: Build
FROM rust:slim AS builder

WORKDIR /build

# Outils de compilation (SSL pour reqwest)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release


# Stage 2: Image runtime minimale
FROM debian:bookworm-slim AS runtime

# Labels OCI
LABEL org.opencontainers.image.title="Infomaniak DDNS Updater" \
    org.opencontainers.image.description="Service de mise à jour DNS dynamique pour Infomaniak (Rust)" \
    org.opencontainers.image.authors="axioneer-studio" \
    org.opencontainers.image.source="https://github.com/axioneer-studio/ddns-infomaniak" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.version="2.0.0"

# Certificats CA pour les requêtes HTTPS + procps pour pgrep (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non-root
RUN groupadd --gid 1000 ddns && \
    useradd --uid 1000 --gid ddns --shell /bin/false ddns

WORKDIR /app

# Binaire compilé
COPY --from=builder /build/target/release/axioddns /usr/local/bin/axioddns

USER ddns

# Healthcheck - vérifie que le processus Rust tourne
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f "axioddns" > /dev/null || exit 1

# Point d'entrée
ENTRYPOINT ["/usr/local/bin/axioddns"]
