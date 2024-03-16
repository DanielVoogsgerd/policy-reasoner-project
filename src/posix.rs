use std::error;

use std::os::unix::fs::PermissionsExt;

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use log::{debug, info};
use nested_cli_parser::map_parser::MapParser;
use nested_cli_parser::NestedCliParserHelpFormatter;
use policy::Policy;
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use state_resolver::State;
use workflow::{spec::Workflow, Dataset, Elem};

/***** LIBRARY *****/
pub struct PosixReasonerConnector {}

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
impl<L: ReasonerConnectorAuditLogger + Send + Sync + 'static> ReasonerConnector<L> for PosixReasonerConnector {
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
        let datasets = find_datasets_in_workflow(workflow);

        let data_index = brane_shr::utilities::create_data_index_from("tests/data");

        let paths = datasets
            .iter()
            .map(|dataset| data_index.get(&dataset.name).expect("Could not find dataset in dataindex"))
            .flat_map(|datainfo| {
                datainfo.access.values().map(|kind| match kind {
                    specifications::data::AccessKind::File { path } => path.clone(),
                })
            })
            .collect::<Vec<_>>();

        let is_allowed =
            paths.iter().map(|path| std::fs::metadata(path).expect("Could not get file metadata").permissions().mode()).all(|x| x & 004 == 004);

        info!("We need to evaluate the permissions of the following files {:#?}", paths);

        info!("Found: {} datasets", datasets.len());
        for dataset in &datasets {
            debug!("Dataset: {}", dataset.name);
        }

        if !is_allowed {
            return Ok(ReasonerResponse::new(false, vec!["We do not have sufficient permissions".to_owned()]));
        }
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
        PosixReasonerConnectorContext { t: "posix".into(), version: "0.1.0".into() }
    }
}

fn find_datasets_in_workflow(workflow: Workflow) -> Vec<Dataset> {
    let mut datasets: Vec<Dataset> = Vec::new();
    debug!("Walking the workflow in order to find datasets. Starting with {:?}", &workflow.start);
    find_datasets(&workflow.start, &mut datasets);

    datasets
}

fn find_datasets(elem: &Elem, datasets: &mut Vec<Dataset>) {
    match elem {
        Elem::Task(task) => {
            debug!("Visiting task");
            datasets.extend(task.input.iter().cloned());
            if let Some(output) = &task.output {
                datasets.push(output.clone());
            }

            find_datasets(&task.next, datasets);
        },
        Elem::Commit(commit) => {
            debug!("Visiting task");
            // TODO: Maybe we should handle `data_name`
            datasets.extend(commit.input.iter().cloned());

            find_datasets(&commit.next, datasets);
        },
        Elem::Branch(branch) => {
            debug!("Visiting task");
            for elem in &branch.branches {
                find_datasets(elem, datasets);
            }

            find_datasets(&branch.next, datasets);
        },
        Elem::Parallel(parallel) => {
            debug!("Visiting task");
            for elem in &parallel.branches {
                find_datasets(elem, datasets);
            }

            find_datasets(&parallel.next, datasets);
        },
        Elem::Loop(loope) => {
            debug!("Visiting task");
            find_datasets(&loope.body, datasets);
            find_datasets(&loope.next, datasets);
        },
        Elem::Next => {
            debug!("Visiting task");
            return;
        },
        Elem::Stop(stop) => {
            debug!("Visiting task");
            datasets.extend(stop.iter().cloned());
        },
    }
}
