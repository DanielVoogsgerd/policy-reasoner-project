//! A minimal policy reasoner implementation that can be used as a base for new policy reasoners.
//!
//! This no-operation reasoner is meant to be an example, and can be used as a base to build new reasoners on top of.
//! Furthermore it can be used for testing. The reasoner approves all workflow validation requests by default (it does
//! not perform any permission checks, and thus never rejects a request).
use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};

use log::debug;
use policy::Policy;
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use state_resolver::State;
use workflow::spec::Workflow;

/// The minimal no-operation reasoner connector, that approves all validation requests by default (it does not check any
/// policy/permissions).
#[derive(Default)]
pub struct NoOpReasonerConnector;

impl NoOpReasonerConnector {
  pub fn new() -> Self {
      Default::default()
  }
}

/***** LIBRARY *****/
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
        debug!("NoOpReasonerConnector: Execute task request received");
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
        debug!("NoOpReasonerConnector: Access data request received");
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

/// The context for the no-operation reasoner connector.
/// See the [`ConnectorContext`] and [`ConnectorWithContext`] traits for more information.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NoOpReasonerConnectorContext {
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
            t: "noop".into(),
            version: "0.1.0".into(),
        }
    }
}
