//  MAIN.rs
//    by Lut99
//
//  Created:
//    12 Mar 2024, 14:13:29
//  Last edited:
//    12 Mar 2024, 14:39:11
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint for the `key-manager` binary.
//

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use error_trace::ErrorTrace as _;
use humanlog::{DebugMode, HumanLogger};
use humantime::Duration;
use jsonwebtoken::jwk::KeyAlgorithm;
use log::{error, info};


/***** ARGUMENTS *****/
/// The toplevel arguments!
#[derive(Debug, Parser)]
struct Arguments {
    /// If given, enables additional INFO- and DEBUG-level statements.
    #[clap(long, global = true, help = "If given, enables additional INFO- and DEBUG-level statements.")]
    debug: bool,
    /// If given, enables additional TRACE-level statements (implies '--debug').
    #[clap(long, global = true, help = "If given, enables additional TRACE-level statements (implies '--debug')")]
    trace: bool,

    /// The toplevel subcommand to execute.
    #[clap(subcommand)]
    action: Subcommands,
}

/// The toplevel subcommands.
#[derive(Debug, Subcommand)]
enum Subcommands {
    #[clap(name = "generate", about = "Generates keys/tokens for the policy reasoner.")]
    Generate(GenerateArguments),
}



/// Generate-level arguments.
#[derive(Debug, Parser)]
struct GenerateArguments {
    /// Defines the furtherly nested subcommand
    #[clap(subcommand)]
    action: GenerateSubcommands,
}

/// Generate-level subcommands
#[derive(Debug, Subcommand)]
enum GenerateSubcommands {
    #[clap(name = "key", alias = "jwk", about = "Generates a private key (as a JWK) for the policy reasoner.")]
    Key(GenerateKeyArguments),
    #[clap(name = "token", alias = "jwt", about = "Generates a token (as a JWT) for the policy reasoner using an existing key (JWK).")]
    Token(GenerateTokenArguments),
}



/// Defines the arguments for the `generate key`-subcommand.
#[derive(Debug, Parser)]
struct GenerateKeyArguments {
    /// The path to export the key to.
    #[clap(name = "OUTPUT_PATH", help = "The path of the file to write the new JWK to.")]
    output: PathBuf,

    /// If given, fixes missing directories before attempting to create the output file.
    #[clap(short, long, help = "If given, fixes missing directories before attempting to create the output file.")]
    fix_dirs: bool,
    /// The identifier of the key set, if useful.
    #[clap(short, long, default_value = "foo", help = "The identifier of this key in the key set. In case this matters.")]
    id: String,
    /// The algorithm for which this key is suitable.
    #[clap(short, long, default_value = "HS256", help = "The algorithm for which this key will be suitable. Determines the length of the key etc.")]
    alg: KeyAlgorithm,
}

/// Defines the arguments for the `generate token`-subcommand.
#[derive(Debug, Parser)]
struct GenerateTokenArguments {
    /// The path to export the key to.
    #[clap(name = "OUTPUT_PATH", help = "The path of the file to write the new JWK to.")]
    output:   PathBuf,
    /// The name of the user that will be using the JWT.
    #[clap(name = "USER", help = "The name of the user that will be using the JWT.")]
    user:     String,
    /// The name of the system that is used to access the reasoner through, in case this matters. Omit to default to the same value as `USER`.
    #[clap(
        name = "SYSTEM",
        help = "The name of the system that is used to access the reasoner through, in case this matters. Omit to default to the same value as \
                `USER`."
    )]
    system:   Option<String>,
    /// The duration for which this token is valid. You can use postfixes (e.g., `d` for days, `y` for years, etc)
    #[clap(
        name = "DURATION",
        default_value = "31d",
        help = "The name of the The duration for which this token is valid. You can use postfixes (e.g., `d` for days, `y` for years, etc)."
    )]
    duration: Duration,

    /// If given, fixes missing directories before attempting to create the output file.
    #[clap(short, long, help = "If given, fixes missing directories before attempting to create the output file.")]
    fix_dirs: bool,
    /// The path to the key to use.
    #[clap(short, long, help = "The path to the private key (JWK) to use.")]
    key:      PathBuf,
}





/***** ENTRYPOINT *****/
fn main() {
    // Parse arguments
    let args = Arguments::parse();

    // Initialize the logger
    if let Err(err) = HumanLogger::terminal(DebugMode::from_flags(args.trace, args.debug)).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
    }
    info!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));

    // Match on the subcommand
    match args.action {
        Subcommands::Generate(generate) => match generate.action {
            GenerateSubcommands::Key(GenerateKeyArguments { output, fix_dirs, id, alg }) => {
                if let Err(err) = brane_ctl::generate::policy_secret(fix_dirs, output, id, alg) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
            GenerateSubcommands::Token(GenerateTokenArguments { output, user, system, duration, fix_dirs, key }) => {
                let system: String = system.unwrap_or_else(|| user.clone());
                if let Err(err) = brane_ctl::generate::policy_token(fix_dirs, output, key, user, system, *duration) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },
    }
}
