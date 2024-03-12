//  BUILD.rs
//    by Lut99
//
//  Created:
//    13 Dec 2023, 11:45:11
//  Last edited:
//    12 Mar 2024, 13:53:16
//  Auto updated?
//    Yes
//
//  Description:
//!   Build script for the main `policy-reasoner` executable.
//!
//!   In particular, charged with compiling the eFLINT interface to eFLINT JSON before it can be included in the executable.
//

use std::env::VarError;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::{env, fs};

use diesel::{Connection as _, SqliteConnection};
use diesel_migrations::{FileBasedMigrations, MigrationHarness};
use eflint_to_json::compile;
use error_trace::trace;
use sha2::{Digest as _, Sha256};


/***** HELPERS *****/
/// Wraps around another Writer to always Write while updating a hash of whatever we write.
struct HashWriter<W>(W, Sha256);
impl<W> HashWriter<W> {
    /// Constructor for the HashWriter that initializes its digest.
    ///
    /// # Arguments
    /// - `writer`: The [`Write`]r to wrap.
    ///
    /// # Returns
    /// A new instance of a HashWriter.
    #[inline]
    fn new(writer: W) -> Self { Self(writer, Sha256::new()) }

    /// Finalizes the HashWriter and returns the digest.
    ///
    /// # Returns
    /// The raw digest bytes encoded as Base64 (in constant time yay).
    #[inline]
    fn finalize(self) -> String { base16ct::lower::encode_string(&self.1.finalize()) }
}
impl<W: Write> Write for HashWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Update the hasher first before passing to the wrapper impl
        self.1.update(buf);
        self.0.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        // Flush only
        self.0.flush()
    }
}





/***** TASKS *****/
/// Compile & embed the eFLINT base definitions.
fn compile_eflint() {
    // Read some environment variables
    let src_dir: PathBuf = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let eflint_to_json_exe: Option<PathBuf> = match env::var("EFLINT_TO_JSON_PATH") {
        Ok(path) => {
            let path: PathBuf = path.into();
            if path.is_relative() { Some(src_dir.join(path)) } else { Some(path) }
        },
        Err(VarError::NotPresent) => None,
        Err(err) => panic!("{}", trace!(("Failed to get environment variable 'EFLINT_TO_JSON_PATH'"), err)),
    };

    // Mark the input files as source-dependent
    let interface_dir: PathBuf = src_dir.join("policy").join("eflint").join("interface");
    println!("cargo:rerun-if-changed={}", interface_dir.display());
    println!("cargo:rerun-if-env-changed=EFLINT_TO_JSON_PATH");

    // Compute the concrete input- and output paths
    let main_path: PathBuf = interface_dir.join("main.eflint");
    let output_file: PathBuf = PathBuf::from(env::var("OUT_DIR").unwrap()).join("base-defs.eflint.json");
    println!("cargo:rustc-env=BASE_DEFS_EFLINT_JSON={}", output_file.display());

    // Alright attempt to open the output file
    let handle: File = match File::create(&output_file) {
        Ok(handle) => handle,
        Err(err) => panic!("{}", trace!(("Failed to create output file '{}'", output_file.display()), err)),
    };
    let mut handle: HashWriter<File> = HashWriter::new(handle);

    // Alright run the compiler, after which we reset the handle
    if let Err(err) = compile(&main_path, &mut handle, eflint_to_json_exe.as_ref().map(|p| p.as_path())) {
        panic!("{}", trace!(("Failed to compile input file '{}'", main_path.display()), err));
    }

    // Also set the found hash
    let hash: String = handle.finalize();
    println!("cargo:rustc-env=BASE_DEFS_EFLINT_JSON_HASH={hash}");

    // Done
}



/// Runs the Diesel migrations for the database.
fn build_database() {
    // Setup the triggers for running this script
    let src_dir: PathBuf = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", src_dir.join("migrations").display());

    // See if the output file already exists
    let data_dir: PathBuf = src_dir.join("data");
    let data_file: PathBuf = data_dir.join("policy.db");
    if !data_file.exists() {
        // Touch the database file
        if !data_dir.exists() {
            if let Err(err) = fs::create_dir(&data_dir) {
                panic!("{}", trace!(("Failed to create data directory '{}'", data_dir.display()), err));
            }
        }
        if let Err(err) = fs::File::create(&data_file) {
            panic!("{}", trace!(("Failed to create policy database file '{}'", data_file.display()), err));
        }

        // Get the migrations defined
        let migrations: FileBasedMigrations = match FileBasedMigrations::find_migrations_directory_in_path(&src_dir) {
            Ok(migrations) => migrations,
            Err(err) => panic!("{}", trace!(("Failed to find migration in source directory '{}'", src_dir.display()), err)),
        };

        // Apply them by connecting to the database
        let mut conn: SqliteConnection = match SqliteConnection::establish(&data_file.display().to_string()) {
            Ok(conn) => conn,
            Err(err) => panic!("{}", trace!(("Failed to connect to database file '{}'", data_file.display()), err)),
        };
        if let Err(err) = conn.run_pending_migrations(migrations) {
            panic!("Failed to apply migrations to database '{}': {}", data_file.display(), err);
        }
    }
}





/***** ENTRYPOINT *****/
fn main() {
    // 1. Compile the eFLINT base spec
    compile_eflint();

    // 2. Build the database
    build_database();
}
