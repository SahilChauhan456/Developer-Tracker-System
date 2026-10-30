use bb8::Pool;
use bb8_tiberius::ConnectionManager;
use std::env;
use tiberius::Config;

pub type DbPool = Pool<ConnectionManager>;

pub async fn create_pool() -> DbPool {
    let conn_str = env::var("MSSQL_CONN_STR").expect("MSSQL_CONN_STR must be set in .env");

    // Parse ADO.NET string into a Tiberius Config
    let mut config = Config::from_ado_string(&conn_str).expect("Invalid MSSQL connection string");

    // Trust local dev certificates
    config.trust_cert();

    let manager = ConnectionManager::new(config);

    Pool::builder()
        .max_size(10)
        .build(manager)
        .await
        .expect("Failed to create MSSQL connection pool")
}
