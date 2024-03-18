use std::error;

use std::os::unix::fs::PermissionsExt;

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use log::{debug, info, error};
use nested_cli_parser::map_parser::MapParser;
use nested_cli_parser::NestedCliParserHelpFormatter;
use policy::{Policy, PolicyContent};
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use serde::Deserialize;
use serde_json::value::RawValue;
use state_resolver::State;
use workflow::{spec::Workflow, Dataset, Elem};

/***** LIBRARY *****/
pub struct PosixReasonerConnector {}


#[derive(Deserialize, Debug)]
pub struct PosixPolicy {
    datasets: Vec<PosixPolicyDataset>,
}

#[derive(Deserialize, Debug)]
pub struct PosixPolicyDataset {
    name: String,
    user_mappings: Vec<PosixPolicyUserMapping>,
}

#[derive(Deserialize, Debug)]
pub struct PosixPolicyUserMapping {
    global_username: String,
    local_username: String,
}

impl PosixPolicy {
    /// Given a dataset identifier (e.g., "umc_utrecht_ect") and a global username (e.g., "test"), returns the local
    /// triad (file_owner, group, or others) that this combination maps to.
    fn get_local_name(&self, dataset_identifier: String, global_username: String) -> String {
        self.datasets
            .iter()
            .find(|&dataset| dataset.name == dataset_identifier)
            .expect(&format!("the following dataset should be in the policy: {:}", &dataset_identifier))
            .user_mappings
            .iter()
            .find(|&user_mapping| user_mapping.global_username == global_username)
            .expect(&format!("the user mapping should contain a mapping for the following user: {:}", &global_username))
            .local_username.clone()
    }
}

// Unix permissions (see: https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation)
// Symbolic     Numeric       English
// ----------   0000          no permissions
// -rwx------   0700          read, write, & execute only for owner
// -rwxrwx---   0770          read, write, & execute for owner and group
// -rwxrwxrwx   0777          read, write, & execute for owner, group and others
// ---x--x--x   0111          execute
// --w--w--w-   0222          write
// --wx-wx-wx   0333          write & execute
// -r--r--r--   0444          read
// -r-xr-xr-x   0555          read & execute
// -rw-rw-rw-   0666          read & write
// -rwxr-----   0740          owner can read, write, & execute; group can only read; others have no permissions

#[derive(Deserialize)]
enum UserType {
    FileOwner,
    Group,
    Others,
}

impl UserType {
    fn from_string(user_type: &str) -> Result<Self, &'static str> {
        match user_type {
            "file_owner" => Ok(UserType::FileOwner),
            "group" => Ok(UserType::Group),
            "others" => Ok(UserType::Others),
            _ => Err("The user type provided does not exist.")
        }
    }
}

#[derive(Debug, Clone)]
enum PosixPermission {
    Read,
    Write,
    Execute,
}

impl PosixPermission {
    /// Called on a `PosixPermission` and passed a `user_type` will return the numeric notation that denotes being in
    /// possession of this permission for this user_type/triad. E.g., `Read` for `file_owner` maps to `400`, `Execute`
    /// for `others` maps to `001`.
    fn to_numeric_notation(&self, user_type: &UserType) -> u32 {
        let alignment_multiplier = match user_type {
            UserType::FileOwner => 100, // .00
            UserType::Group => 10,      // 0.0
            UserType::Others => 1,      // 00.
        };
        match self {
            PosixPermission::Read => 4 * alignment_multiplier,
            PosixPermission::Write => 2 * alignment_multiplier,
            PosixPermission::Execute => 1 * alignment_multiplier,
        }
    }
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

/// A simple test policy. TODO: Set up, parse and use the policy passed in via the framework.
fn get_test_policy() -> PosixPolicy {
    let raw_test_policy = String::from(
        r#"
        {
            "datasets": [
                {
                    "name": "st_antonius_ect",
                    "user_mappings": [
                        {
                            "global_username": "test",
                            "local_username": "others"
                        }, 
                        {
                            "global_username": "halli",
                            "local_username": "others"
                        }
                    ]
                },
                {
                    "name": "umc_utrecht_ect",
                    "user_mappings": [
                        {
                            "global_username": "test",
                            "local_username": "others"
                        },
                        {
                            "global_username": "test2",
                            "local_username": "others"
                        }
                    ]
                }
            ]
        }
        "#,
    );

    let raw_test_policy = PolicyContent {
        reasoner: String::from("posix"),
        reasoner_version: String::from("0.0.1"),
        content: RawValue::from_string(raw_test_policy).unwrap(),
    };
    
    // Note: IIUC for eFLINT there is a completely separate parser: https://gitlab.com/eflint/json-spec-rs.
    let test_policy: PosixPolicy = serde_json::from_str(raw_test_policy.content.get()).unwrap();
    test_policy
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
        // The datasets used in the workflow. E.g., "st_antonius_ect".
        let datasets = find_datasets_in_workflow(workflow);

        // A data index, which contains dataset identifiers and their underlying files.
        // E.g., the "st_antonius_ect" dataset contains the "text.txt" file. See: tests/data/*
        let data_index = brane_shr::utilities::create_data_index_from("tests/data");

        // Contains the file paths of the files that are used in the workflow. E.g., if we use "st_antonius_ect" in the
        // workflow, then `paths` includes: "tests/data/umc_utrecht_ect/./test.txt"
        let paths = datasets
            .iter()
            .map(|dataset| data_index.get(&dataset.name).expect("Could not find dataset in dataindex"))
            .flat_map(|datainfo| {
                datainfo.access.values().map(|kind| match kind {
                    specifications::data::AccessKind::File { path } => path.clone(),
                })
            })
            .collect::<Vec<_>>();

        // Given the file `paths`, check if the current process has read permissions for each file.
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

fn find_datasets_in_workflow(workflow: &Workflow, task_name: &Option<String>) -> Vec<Dataset> {
    let mut datasets: Vec<Dataset> = Vec::new();
    debug!("Walking the workflow in order to find datasets. Starting with {:?}", &workflow.start);
    find_datasets(&workflow.start, &mut datasets, task_name);

    datasets
}

fn find_datasets(elem: &Elem, datasets: &mut Vec<Dataset>, task_name: &Option<String>) {
    match elem {
        Elem::Task(task) => {
            debug!("Visiting task");
            if (task_name.is_some() && *task_name.as_ref().unwrap() == task.name) || !task_name.is_some() {
                datasets.extend(task.input.iter().cloned());
                if let Some(output) = &task.output {
                    datasets.push(output.clone());
                }
                find_datasets(&task.next, datasets, task_name);
            }
        },
        Elem::Commit(commit) => {
            debug!("Visiting task");
            // TODO: Maybe we should handle `data_name`
            if !task_name.is_some() {
                datasets.extend(commit.input.iter().cloned());
            }
            find_datasets(&commit.next, datasets, task_name);
        },
        Elem::Branch(branch) => {
            debug!("Visiting task");
            for elem in &branch.branches {
                find_datasets(elem, datasets, task_name);
            }

            find_datasets(&branch.next, datasets, task_name);
        },
        Elem::Parallel(parallel) => {
            debug!("Visiting task");
            for elem in &parallel.branches {
                find_datasets(elem, datasets, task_name);
            }

            find_datasets(&parallel.next, datasets, task_name);
        },
        Elem::Loop(loope) => {
            debug!("Visiting task");
            find_datasets(&loope.body, datasets, task_name);
            find_datasets(&loope.next, datasets, task_name);
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
