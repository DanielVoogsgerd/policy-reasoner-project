use std::collections::HashMap;
use std::error;
use std::fmt::{Display, Formatter, Result as FResult};

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use eflint_json::spec::auxillary::Version;
use eflint_json::spec::{
    ConstructorInput, Expression, ExpressionConstructorApp, ExpressionPrimitive, Phrase, PhraseCreate, PhraseResult, Request, RequestCommon,
    RequestPhrases,
};
use log::{debug, error, info};
use nested_cli_parser::map_parser::MapParser;
use nested_cli_parser::{NestedCliParser as _, NestedCliParserHelpFormatter};
use policy::{Policy, PolicyContent};
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use state_resolver::State;
use workflow::spec::Workflow;

pub struct NoOpReasonerConnector;

impl NoOpReasonerConnector {
  pub fn new(cli_args: String) -> Result<Self, Box<dyn error::Error>> {
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
        logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        state: State,
        workflow: Workflow,
        task: String,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        return Ok(ReasonerResponse::new(true, vec![]));
    }

    async fn access_data_request(
        &self,
        logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        state: State,
        workflow: Workflow,
        data: String,
        task: Option<String>,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        return Ok(ReasonerResponse::new(true, vec![]));
    }


    async fn workflow_validation_request(
        &self,
        logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        state: State,
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