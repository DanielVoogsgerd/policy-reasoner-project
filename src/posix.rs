use std::error;

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use log::{debug, info};
use nested_cli_parser::map_parser::MapParser;
use nested_cli_parser::NestedCliParserHelpFormatter;
use policy::Policy;
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use state_resolver::State;
use workflow::spec::Workflow;


pub struct PosixPermission {
    pub user: String,
    pub group: String,
    pub other: String,
}

pub struct PosixFile {
    pub path: String,
    pub permissions: PosixPermission,
}

/***** LIBRARY *****/
pub struct PosixReasonerConnector {

}

impl PosixReasonerConnector {
  pub fn new(_cli_args: String) -> Result<Self, Box<dyn error::Error>> {
      info!("Creating new PosixReasonerConnector with {} plugin", std::any::type_name::<Self>());

      debug!("Parsing nested arguments for PosixReasonerConnector<{}>", std::any::type_name::<Self>());

      Ok(PosixReasonerConnector {})
  }

  /// Returns a formatter that can be printed to understand the arguments to this connector.
  ///
  /// # Arguments
  /// - `short`: A shortname for the argument that contains the nested arguments we parse.
  /// - `long`: A longname for the argument that contains the nested arguments we parse.
  ///
  /// # Returns
  /// A [`NestedCliParserHelpFormatter`] that implements [`Display`].
  pub fn help<'l>(_short: char, _long: &'l str) -> NestedCliParserHelpFormatter<'static, 'l, MapParser> {
    todo!()
  }

  #[inline]
  fn cli_args() -> Vec<(char, &'static str, &'static str)> {
    todo!()
  }

}
#[async_trait::async_trait]
impl<L: ReasonerConnectorAuditLogger + Send + Sync + 'static> ReasonerConnector<L>
    for PosixReasonerConnector
{
    async fn execute_task(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        _policy: Policy,
        _state: State,
        _workflow: Workflow,
        _task: String,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        return Ok(ReasonerResponse::new(true, vec![]));
    }

    async fn access_data_request(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        _policy: Policy,
        _state: State,
        _workflow: Workflow,
        _data: String,
        _task: Option<String>,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        return Ok(ReasonerResponse::new(true, vec![]));
    }


    async fn workflow_validation_request(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        _policy: Policy,
        _state: State,
        _workflow: Workflow,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        return Ok(ReasonerResponse::new(true, vec![]));
    }
}


#[derive(Debug, Clone, serde::Serialize)]
pub struct PosixReasonerConnectorContext {
    #[serde(rename = "type")]
    pub t: String,
    pub version: String,
}

impl std::hash::Hash for PosixReasonerConnectorContext {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.t.hash(state);
        self.version.hash(state);
    }
}

impl ConnectorContext for PosixReasonerConnectorContext {
    fn r#type(&self) -> String {
        self.t.clone()
    }

    fn version(&self) -> String {
        self.version.clone()
    }
}

impl ConnectorWithContext for PosixReasonerConnector {
    type Context = PosixReasonerConnectorContext;

    #[inline]
    fn context() -> Self::Context {
        PosixReasonerConnectorContext {
            t: "posix".into(),
            version: "0.1.0".into(),
        }
    }
}
