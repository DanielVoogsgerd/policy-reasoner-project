//! Policy reasoner
//!
//! An interface for defining policy reasoners for the Brane framework
//!
//! Some examples of policy reasoners are included in this binary:
//! - eFlint reasoner:
//!   The main reasoner based on the eFlint language (see also <https://dl.acm.org/doi/10.1145/3425898.3426958>)
//! - POSIX reasoner:
//!   A simple reasoner based on POSIX file permissions
//! - No-Op reasoner:
//!   A very simple base implementation that focusses on being as minimal as possible

pub mod auth;
pub mod logger;
pub mod models;
pub mod schema;
pub mod sqlite;
pub mod state;
pub mod posix;
pub mod eflint;
pub mod no_op;
