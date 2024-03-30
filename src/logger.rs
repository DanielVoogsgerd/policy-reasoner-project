use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::path::PathBuf;

use audit_logger::{AuditLogger, ConnectorWithContext, Error as AuditLoggerError, LogStatement, ReasonerConnectorAuditLogger};
use auth_resolver::AuthContext;
use deliberation::spec::Verdict;
use enum_debug::EnumDebug;
use error_trace::ErrorTrace as _;
use log::debug;
use policy::Policy;
use state_resolver::State;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use workflow::Workflow;


/***** HELPER MACROS *****/
/// Wraps a [`write!`]-macro to return its error as a [`FileLoggerError`].
macro_rules! write_file {
    ($path:expr, $handle:expr, $($t:tt)+) => {
        // Psych we actually don't wrap that macro, since we're doing async ofc
        async {
            use tokio::io::AsyncWriteExt as _;
            let contents: String = format!($($t)+);
            $handle.write_all(contents.as_bytes()).await.map_err(|err| FileLoggerError::FileWrite { path: ($path), err })
        }
    };
}

/// Wraps a [`writeln!`]-macro to return its error as a [`FileLoggerError`].
macro_rules! writeln_file {
    ($path:expr, $handle:expr) => {
        // Psych we actually don't wrap that macro, since we're doing async ofc
        async {
            use tokio::io::AsyncWriteExt as _;
            $handle.write_all(b"\n").await.map_err(|err| FileLoggerError::FileWrite { path: ($path), err })
        }
    };
    ($path:expr, $handle:expr, $($t:tt)+) => {
        // Psych we actually don't wrap that macro, since we're doing async ofc
        async {
            use tokio::io::AsyncWriteExt as _;
            let mut contents: String = format!($($t)*);
            contents.push('\n');
            $handle.write_all(contents.as_bytes()).await.map_err(|err| FileLoggerError::FileWrite { path: ($path), err })
        }
    };
}





/***** ERRORS *****/
/// Defines errors originating from the [`FileLogger`].
#[derive(Debug)]
pub enum FileLoggerError {
    /// Failed to create a new logfile.
    FileCreate { path: PathBuf, err: std::io::Error },
    /// Failed to open an existing logfile.
    FileOpen { path: PathBuf, err: std::io::Error },
    /// Failed to seek in the logfile.
    FileSeek { path: PathBuf, err: std::io::Error },
    /// Failed to flush the given logfile.
    FileShutdown { path: PathBuf, err: std::io::Error },
    /// Failed to write to the logfile.
    FileWrite { path: PathBuf, err: std::io::Error },
    /// Failed to serialize a statement.
    StatementSerialize { kind: String, err: serde_json::Error },
}
impl Display for FileLoggerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use FileLoggerError::*;
        match self {
            FileCreate { path, .. } => write!(f, "Failed to create new log file '{}'", path.display()),
            FileOpen { path, .. } => write!(f, "Failed to open existing log file '{}'", path.display()),
            FileSeek { path, .. } => write!(f, "Failed to seek in log file '{}'", path.display()),
            FileShutdown { path, .. } => write!(f, "Failed to flush log file '{}'", path.display()),
            FileWrite { path, .. } => write!(f, "Failed to write to log file '{}'", path.display()),
            StatementSerialize { kind, .. } => write!(f, "Failed to serialize {kind}"),
        }
    }
}
impl Error for FileLoggerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use FileLoggerError::*;
        match self {
            FileCreate { err, .. } => Some(err),
            FileOpen { err, .. } => Some(err),
            FileSeek { err, .. } => Some(err),
            FileShutdown { err, .. } => Some(err),
            FileWrite { err, .. } => Some(err),
            StatementSerialize { err, .. } => Some(err),
        }
    }
}

/***** LIBRARY *****/
/// A mock version of the logger that simply ignores all logged statements.
///
/// Just here for testing purposes.
pub struct MockLogger {}
impl MockLogger {
    pub fn new() -> Self { MockLogger {} }
}
impl Clone for MockLogger {
    fn clone(&self) -> Self { Self {} }
}
#[async_trait::async_trait]
impl AuditLogger for MockLogger {
    async fn log_exec_task_request(
        &self,
        _reference: &str,
        _auth: &AuthContext,
        _policy: i64,
        _state: &State,
        _workflow: &Workflow,
        _task: &str,
    ) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_exec_task_request");
        Ok(())
    }

    async fn log_data_access_request(
        &self,
        _reference: &str,
        _auth: &AuthContext,
        _policy: i64,
        _state: &State,
        _workflow: &Workflow,
        _data: &str,
        _task: &Option<String>,
    ) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_data_access_request");
        Ok(())
    }

    async fn log_validate_workflow_request(
        &self,
        _reference: &str,
        _auth: &AuthContext,
        _policy: i64,
        _state: &State,
        _workflow: &Workflow,
    ) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_validate_workflow_request");
        Ok(())
    }

    async fn log_verdict(&self, _reference: &str, _verdict: &Verdict) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_verdict");
        Ok(())
    }

    async fn log_add_policy_request<C: ConnectorWithContext>(&self, _auth: &AuthContext, _policy: &Policy) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_add_policy_request");
        Ok(())
    }

    async fn log_set_active_version_policy(&self, _auth: &AuthContext, _policy: &Policy) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_set_active_version_policy");
        Ok(())
    }

    async fn log_deactivate_policy(&self, _auth: &AuthContext) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_deactivate_policy");
        Ok(())
    }

    async fn log_reasoner_context<C: ConnectorWithContext>(&self) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_reasoner_context");
        Ok(())
    }
}

#[async_trait::async_trait]
impl ReasonerConnectorAuditLogger for MockLogger {
    async fn log_reasoner_response(&self, _reference: &str, _response: &str) -> Result<(), AuditLoggerError> {
        println!("AUDIT LOG: log_reasoner_response");
        Ok(())
    }
}

/// A more serious version of a logger that logs to a file.
///
/// Note that this logger is not exactly the perfect audit log, as it does nothing w.r.t. ensuring that the file is the same as last time or signing changes or w/e.
#[derive(Clone)]
pub struct FileLogger {
    /// The name of the binary, is static for the lifetime of the binary
    binary_name: &'static str,

    /// The path of the file to log to.
    path: PathBuf,
}
impl FileLogger {
    /// Constructor for the FileLogger that initializes it pointing to the given file.
    ///
    /// # Arguments
    /// - `path`: The path to the file to log to.
    ///
    /// # Returns
    /// A new instance of self, ready for action.
    #[inline]
    pub fn new(binary_name: &'static str, path: impl Into<PathBuf>) -> Self { Self { binary_name, path: path.into() } }

    /// Writes a log statement to the logging file.
    ///
    /// # Arguments
    /// - `stmt`: The [`LogStatement`] that determines what we're gonna log.
    ///
    /// # Errors
    /// This function errors if we failed to perform the logging completely (i.e., either write or flush).
    pub async fn log(&self, stmt: LogStatement<'_>) -> Result<(), FileLoggerError> {
        // Step 1: Open the log file
        let mut handle: File = if !self.path.exists() {
            debug!("Creating new log file at '{}'...", self.path.display());
            match File::create(&self.path).await {
                Ok(handle) => handle,
                Err(err) => return Err(FileLoggerError::FileCreate { path: self.path.clone(), err }),
            }
        } else {
            debug!("Opening existing log file at '{}'...", self.path.display());
            match OpenOptions::new().write(true).append(true).open(&self.path).await {
                Ok(handle) => handle,
                Err(err) => return Err(FileLoggerError::FileOpen { path: self.path.clone(), err }),
            }
        };

        // // Navigate to the end of the file
        // let end_pos: u64 = match handle.seek(SeekFrom::End(0)).await {
        //     Ok(pos) => pos,
        //     Err(err) => return Err(FileLoggerError::FileSeek { path: self.path.clone(), err }),
        // };
        // debug!("End of file is after {end_pos} bytes");

        // Write the message
        debug!("Writing {}-statement to logfile...", stmt.variant());
        // Write who wrote it
        write_file!(self.path.clone(), &mut handle, "[{binary_name} v{version}]",
            binary_name=self.binary_name,
            version=env!("CARGO_PKG_VERSION")
        ).await?;
        // Print the timestamp
        write_file!(self.path.clone(), &mut handle, "[{}]", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")).await?;
        // Then write the logged message
        match serde_json::to_string(&stmt) {
            Ok(message) => writeln_file!(self.path.clone(), &mut handle, " {message}").await?,
            Err(err) => return Err(FileLoggerError::StatementSerialize { kind: format!("{:?}", stmt.variant()), err }),
        }

        // Finally flush the file
        debug!("Flushing log file...");
        if let Err(err) = handle.shutdown().await {
            return Err(FileLoggerError::FileShutdown { path: self.path.clone(), err });
        }
        drop(handle);

        // Done, a smashing success
        Ok(())
    }
}
#[async_trait::async_trait]
impl AuditLogger for FileLogger {
    async fn log_exec_task_request(
        &self,
        reference: &str,
        auth: &AuthContext,
        policy: i64,
        state: &State,
        workflow: &Workflow,
        task: &str,
    ) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log execute_task request");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt: LogStatement = LogStatement::execute_task(reference, auth, policy, state, workflow, task);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_data_access_request(
        &self,
        reference: &str,
        auth: &AuthContext,
        policy: i64,
        state: &State,
        workflow: &Workflow,
        data: &str,
        task: &Option<String>,
    ) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log data_access request");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt = LogStatement::asset_access(reference, auth, policy, state, workflow, data, task);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_validate_workflow_request(
        &self,
        reference: &str,
        auth: &AuthContext,
        policy: i64,
        state: &State,
        workflow: &Workflow,
    ) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log workflow_validate request");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt = LogStatement::workflow_validate(reference, auth, policy, state, workflow);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_verdict(&self, reference: &str, verdict: &Verdict) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log reasoner verdict");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt = LogStatement::reasoner_verdict(reference, verdict);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_reasoner_context<C: ConnectorWithContext>(&self) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log reasoner connector context");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt: LogStatement = LogStatement::reasoner_context::<C>();
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_add_policy_request<C: ConnectorWithContext>(&self, auth: &AuthContext, policy: &Policy) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log policy add");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt: LogStatement = LogStatement::policy_add::<C>(auth, policy);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_set_active_version_policy(&self, auth: &AuthContext, policy: &Policy) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log policy activate");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt = LogStatement::policy_activate(auth, policy);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }

    async fn log_deactivate_policy(&self, auth: &AuthContext) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log policy deactivation");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt = LogStatement::policy_deactivate(auth);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }
}

#[async_trait::async_trait]
impl ReasonerConnectorAuditLogger for FileLogger {
    async fn log_reasoner_response(&self, reference: &str, response: &str) -> Result<(), AuditLoggerError> {
        debug!("Handling request to log reasoner response");

        // Construct the full message that we want to log, then log it (simple as that)
        let stmt = LogStatement::reasoner_response(reference, response);
        self.log(stmt).await.map_err(|err| AuditLoggerError::CouldNotDeliver(format!("{}", err.trace())))
    }
}
