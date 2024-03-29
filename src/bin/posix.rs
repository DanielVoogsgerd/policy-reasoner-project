//  MAIN.rs
//    by Lut99
//
//  Created:
//    09 Jan 2024, 13:32:03
//  Last edited:
//    07 Feb 2024, 18:08:43
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the main `policy-reasoner` binary.
//

use std::env;
use std::fs::File;
use std::net::SocketAddr;

use clap::Parser;
use error_trace::ErrorTrace as _;
use humanlog::{DebugMode, HumanLogger};
use log::{error, info};
use policy_reasoner::{auth::{KidResolver, JwtConfig, JwtResolver}, logger::FileLogger, sqlite::SqlitePolicyDataStore, posix, state};
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

    /// Shows the help menu for the state resolver.
    #[clap(long, help = "If given, shows the possible arguments to pass to the state resolver plugin in '--state-resolver'.")]
    help_state_resolver: bool,
    /// Arguments specific to the state resolver.
    #[clap(
        short,
        long,
        env,
        help = "Arguments to pass to the current state resolver plugin. To find which are possible, see '--help-state-resolver'."
    )]
    state_resolver: Option<String>,

    /// Shows the help menu for the reasoner connector.
    #[clap(long, help = "If given, shows the possible arguments to pass to the reasoner connector plugin in '--reasoner-connector'.")]
    help_reasoner_connector: bool,
    /// Arguments specific to the state resolver.
    #[clap(
        short,
        long,
        env,
        help = "Arguments to pass to the current reasoner connector plugin. To find which are possible, see '--help-reasoner-connector'."
    )]
    reasoner_connector: Option<String>,
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

// TODO: Might need to support cfg.
type PosixReasonerConnectorPlugin = posix::PosixReasonerConnector;

/// The plugin used to resolve policy input state.
#[cfg(feature = "brane-api-resolver")]
type StateResolverPlugin = crate::state::BraneApiResolver;
#[cfg(not(feature = "brane-api-resolver"))]
type StateResolverPlugin = state::FileStateResolver;

/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    // Parse arguments
    let args: Arguments = Arguments::parse();

    let data_index = brane_shr::utilities::create_data_index_from("tests/data");
    let rconn = PosixReasonerConnectorPlugin::new(data_index);

    // Setup a logger
    if let Err(err) = HumanLogger::terminal(if args.trace { DebugMode::Full } else { DebugMode::Debug }).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
    }
    info!("{} - v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // Handle help
    // TODO: This should be refactored a bit, as we are creating multiple reasoners now, we probably want to use dynamic dispatch
    let mut exit: bool = false;
    // if args.help_reasoner_connector {
    //     println!("{}", rconn::help('r', "reasoner-connector"));
    //     exit = true;
    // }
    if args.help_state_resolver {
        println!("{}", StateResolverPlugin::help('s', "state-resolver"));
        exit = true;
    }
    if exit {
        std::process::exit(0);
    }

    run_app(args, rconn).await; // TODO: Add cfg support
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

    let sresolve: StateResolverPlugin = match StateResolverPlugin::new(args.state_resolver.unwrap_or_else(String::new)) {
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
