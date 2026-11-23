mod api;
mod config;
mod crypto;
mod error;
mod models;
mod repository;
mod service;
mod state;

use std::net::SocketAddr;

use sqlx::postgres::PgPoolOptions;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("sealbase=info".parse()?))
        .init();

    let config = Config::from_env();

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    let migrator = sqlx::migrate!("./migrations");
    accept_reworded_migrations(&pool, &migrator).await?;
    migrator.run(&pool).await?;

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let state = AppState::new(pool, config);
    let app = api::router(state);

    tracing::info!(%addr, "starting sealbase");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Migrations whose text changed after they shipped *without any SQL change*
/// (only comments were reworded), with the checksum of the original text.
/// sqlx refuses to start when an applied migration's checksum differs, so a
/// database that applied the original gets its recorded checksum updated —
/// only when it matches that exact original, never otherwise.
const REWORDED_MIGRATIONS: &[(i64, &str)] = &[(
    1,
    "8f9bf459803e6c82de0e5308fd06e22af74209c80c1f7959a9beb61526866d624661e252a33fde7b91e54e8247a06274",
)];

async fn accept_reworded_migrations(pool: &sqlx::PgPool, migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
    let table_exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    if !table_exists {
        return Ok(());
    }
    for (version, original_hex) in REWORDED_MIGRATIONS {
        let Some(current) = migrator.iter().find(|m| m.version == *version) else {
            continue;
        };
        let original = (0..original_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&original_hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        let updated = sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2 AND checksum = $3")
            .bind(current.checksum.as_ref())
            .bind(version)
            .bind(&original)
            .execute(pool)
            .await?
            .rows_affected();
        if updated > 0 {
            tracing::info!(version, "accepted reworded migration (comments only)");
        }
    }
    Ok(())
}
