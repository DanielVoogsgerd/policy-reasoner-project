//! No-op policy reasoner
//! This reasoner does a little as possible and functions as base for other implementations of the
//! policy reasoner.
use std::env;
use std::fs::File;
use std::net::SocketAddr;

use clap::Parser;
use error_trace::ErrorTrace as _;
use humanlog::{DebugMode, HumanLogger};
use log::{error, info};
use policy_reasoner::{auth::{KidResolver, JwtConfig, JwtResolver}, logger::FileLogger, sqlite::SqlitePolicyDataStore, state, no_op::NoOpReasonerConnector};
use reasonerconn::ReasonerConnector;
use srv::Srv;

/***** HELPER FUNCTIONS *****/
fn get_pauth_resolver() -> policy_reasoner::auth::JwtResolver<KidResolver> {
    let kid_resolver = KidResolver::new("./examples/config/jwk_set_expert.json").unwrap();
    let r = File::open("./examples/config/jwt_resolver.yaml").unwrap();
    let jwt_cfg: JwtConfig = serde_yaml::from_reader(r).unwrap();
    JwtResolver::new(jwt_cfg, kid_resolver).unwrap()
}
fn get_dauth_resolver() -> policy_reasoner::auth::JwtResolver<KidResolver> {
    let kid_resolver = KidResolver::new("./examples/config/jwk_set_delib.json").unwrap();
    let r = File::open("./examples/config/jwt_resolver.yaml").unwrap();
    let jwt_cfg: JwtConfig = serde_yaml::from_reader(r).unwrap();
    JwtResolver::new(jwt_cfg, kid_resolver).unwrap()
}

/***** ARGUMENTS *****/
/// Defines the arguments for the `policy-reasoner` server.
#[derive(Debug, Parser, Clone)]
struct Arguments {
    /// Whether to enable full debugging
    #[clap(long, global = true, help = "If given, enables more verbose debugging.")]
    trace: bool,

    /// The address on which to bind ourselves.
    #[clap(short, long, env, default_value = "127.0.0.1:3030", help = "The address on which to bind the server.")]
    address: SocketAddr,
}

/***** PLUGINS *****/
/// The plugin used to do the audit logging.
type AuditLogPlugin = FileLogger;

/// The plugin used to do authentication for the policy expert API.
type PolicyAuthResolverPlugin = JwtResolver<KidResolver>;
/// The plugin used to do authentication for the deliberation API.
type DeliberationAuthResolverPlugin = JwtResolver<KidResolver>;

/// The plugin used to interact with the policy store.
type PolicyStorePlugin = SqlitePolicyDataStore;

/// The plugin used to resolve policy input state.
#[cfg(feature = "brane-api-resolver")]
type StateResolverPlugin = crate::state::BraneApiResolver;
#[cfg(not(feature = "brane-api-resolver"))]
type StateResolverPlugin = state::FileStateResolver;

/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    let args: Arguments = Arguments::parse();

    let rconn = NoOpReasonerConnector::new();

    // Setup a logger
    if let Err(err) = HumanLogger::terminal(if args.trace { DebugMode::Full } else { DebugMode::Debug }).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
    }

    info!("{} - v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    run_app(args, rconn).await;
}

async fn run_app<R>(args: Arguments, rconn: R)
where
    R: ReasonerConnector<AuditLogPlugin> + Send + Sync + 'static,
{
    // Initialize the plugins
    let logger: AuditLogPlugin = FileLogger::new("./audit-log.log", env!("CARGO_BIN_NAME"));
    let pauthresolver: PolicyAuthResolverPlugin = get_pauth_resolver();
    let dauthresolver: DeliberationAuthResolverPlugin = get_dauth_resolver();
    let pstore: PolicyStorePlugin = SqlitePolicyDataStore::new("./data/policy.db");

    let sresolve: StateResolverPlugin = match StateResolverPlugin::new(String::new()) {
        Ok(sresolve) => sresolve,
        Err(err) => {
            error!("{}", err.trace());
            std::process::exit(1);
        },
    };

    // Run them!
    let server = Srv::new(args.address, logger, rconn, pstore, sresolve, pauthresolver, dauthresolver);

    server.run().await;
}
