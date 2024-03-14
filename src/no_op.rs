
use std::error;


use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};


use log::{debug, info};
use nested_cli_parser::map_parser::MapParser;
use nested_cli_parser::{NestedCliParser as _, NestedCliParserHelpFormatter};
use policy::{Policy};
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use state_resolver::State;
use workflow::spec::Workflow;

pub struct NoOpReasonerConnector;

impl NoOpReasonerConnector {
  pub fn new(_cli_args: String) -> Result<Self, Box<dyn error::Error>> {
      info!("Creating new NoOpReasonerConnector with {} plugin", std::any::type_name::<Self>());

      debug!("Parsing nested arguments for NoOpReasonerConnector<{}>", std::any::type_name::<Self>());

      Ok(NoOpReasonerConnector {})
  }


  pub fn help<'l>(short: char, long: &'l str) -> NestedCliParserHelpFormatter<'static, 'l, MapParser> {
      MapParser::new(Self::cli_args()).into_help("NoOpReasonerConnector plugin", short, long)
  }

  #[inline]
  fn cli_args() -> Vec<(char, &'static str, &'static str)> {
      vec![]
  }


}
#[async_trait::async_trait]
impl<L: ReasonerConnectorAuditLogger + Send + Sync + 'static> ReasonerConnector<L>
    for NoOpReasonerConnector
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
        workflow: Workflow,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        debug!("NoOpReasonerConnector: Workflow validation request received");
        println!("Workflow: {:#?}", workflow);
        return Ok(ReasonerResponse::new(true, vec![]));
    }
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct NoOpReasonerConnectorContext { // TODO: Might want to make this generic or a trait to allow checking the type.
    #[serde(rename = "type")]
    pub t: String,
    pub version: String,
}

impl std::hash::Hash for NoOpReasonerConnectorContext {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.t.hash(state);
        self.version.hash(state);
    }
}

impl ConnectorContext for NoOpReasonerConnectorContext {
    fn r#type(&self) -> String {
        self.t.clone()
    }

    fn version(&self) -> String {
        self.version.clone()
    }
}

impl ConnectorWithContext for NoOpReasonerConnector {
    type Context = NoOpReasonerConnectorContext;

    #[inline]
    fn context() -> Self::Context {
        NoOpReasonerConnectorContext {
            t: "posix".into(),
            version: "0.1.0".into(),
        }
    }
}