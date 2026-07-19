pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod accounting;
pub mod actuator;
pub mod billing;
pub mod canary;
pub mod enforcement_loader;
pub mod health;
pub mod identity;
pub mod judge;
pub mod observation;
pub mod passive;
pub mod profile;
pub mod protocol;
mod provenance_digest;
pub mod proxy;
pub mod quality_writer;
pub mod serving_lease;
pub mod state_backend;
pub mod supervisor;
pub mod writer;

pub use proxy::{
    serve, serve_with_runtime_factory, serve_with_shutdown, GatewayDeps, GatewayState,
};
