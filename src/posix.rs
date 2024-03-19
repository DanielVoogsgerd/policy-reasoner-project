use std::path::Path;
use std::{collections::HashMap, error};

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use log::{debug, error, info};
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

type DatasetIdentifier = String;
type GlobalUsername = String;
type PosixPolicyUserMapping = HashMap<GlobalUsername, PosixUser>;
// type PosixPolicy = HashMap<DatasetIdentifier, PosixPolicyUserMapping>;

#[derive(Deserialize, Debug)]
pub struct PosixPolicy {
    datasets: HashMap<DatasetIdentifier, PosixPolicyUserMapping>,
}

#[derive(Deserialize, Debug)]
struct PosixUser {
    uid: u32,
    gids: Vec<u32>,
}

impl PosixPolicy {
    /// Given a dataset identifier (e.g., "umc_utrecht_ect") and a global username (e.g., "test"), returns the local
    /// triad (file_owner, group, or others) that this combination maps to.
    fn get_local_name(&self, dataset_identifier: &str, workflow_user: &str) -> Option<&PosixUser> {
        self.datasets.get(dataset_identifier)?.get(workflow_user)
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

#[derive(Copy, Clone, Deserialize)]
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
            _ => Err("The user type provided does not exist."),
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum PosixPermission {
    Read,
    Write,
    Execute,
}

impl PosixPermission {
    fn to_mode_bit(&self) -> u32 {
        match self {
            PosixPermission::Read => 4,
            PosixPermission::Write => 2,
            PosixPermission::Execute => 1,
        }
    }
}

impl UserType {
    /// Called on a `PosixPermission` and passed a `user_type` will return the numeric notation that denotes being in
    /// possession of this permission for this user_type/triad. E.g., `Read` for `file_owner` maps to `400`, `Execute`
    /// for `others` maps to `001`.
    fn get_mode_bitmask(&self, required_permissions: &[PosixPermission]) -> u32 {
        let alignment_multiplier = match self {
            UserType::FileOwner => 0o100,
            UserType::Group => 0o10,
            UserType::Others => 0o1,
        };
        required_permissions.iter().fold(0, |acc, f| acc | acc | alignment_multiplier * f.to_mode_bit())
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
                            "uid": 1000,
                            "gid"s: [1001, 1002, 1003]
                        },
                        {
                            "global_username": "halli",
                            "uid": 1001,
                            "gid": [1001]
                        },
                    ]
                },
                {
                    "name": "umc_utrecht_ect",
                    "user_mappings": [
                        {
                            "global_username": "test",
                            "uid": 1000,
                            "gid": [1001, 1002, 1003]
                        },
                        {
                            "global_username": "halli",
                            "uid": 1001,
                            "gid"s: [1001]
                        },
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

fn satisfies_posix_permissions(path: impl AsRef<Path>, user: &PosixUser, permissions: &[PosixPermission]) -> bool {
    let mode_bits = std::fs::metadata(&path).expect("Could not get file metadata").permissions().mode();
    let file_uid = std::fs::metadata(&path).expect("Could not get file metadata").uid();
    let file_gid = std::fs::metadata(&path).expect("Could not get file metadata").uid();
    if file_uid == user.uid {
        let mask = UserType::FileOwner.get_mode_bitmask(permissions);
        if mode_bits & mask == mask {
            return true;
        }
    }

    if user.gids.contains(&file_gid) {
        let mask = UserType::Group.get_mode_bitmask(permissions);
        if mode_bits & mask == mask {
            return true;
        }
    }

    let mask = UserType::Others.get_mode_bitmask(permissions);
    mode_bits & mask == mask
}

fn validate_dataset_permissions(workflow: &Workflow, policy: &PosixPolicy, task_name: Option<&str>) -> bool {
    // The datasets used in the workflow. E.g., "st_antonius_ect".
    let datasets: Vec<(Vec<PosixPermission>, Dataset)> =
        find_datasets_in_workflow(&workflow, task_name).into_iter().map(|x| (vec![PosixPermission::Read], x)).collect();

    // A data index, which contains dataset identifiers and their underlying files.
    // E.g., the "st_antonius_ect" dataset contains the "text.txt" file. See: tests/data/*
    let data_index = brane_shr::utilities::create_data_index_from("tests/data");

    // Contains the file paths of the files that are used in the workflow. The dataset identifier is included as the
    // first element in the returned tuples. E.g., if we use "st_antonius_ect" in the workflow, then `paths` includes:
    // Vec[("st_antonius_ect", "tests/data/umc_utrecht_ect/./test.txt")]
    let info_with_paths = datasets
        .iter()
        .flat_map(|(permission, dataset)| {
            let dataset = data_index.get(&dataset.name).expect("Could not find dataset in dataindex");
            dataset.access.values().map(|kind| match kind {
                specifications::data::AccessKind::File { path } => (permission.clone(), dataset.name.clone(), path.clone()),
            })
        })
        .collect::<Vec<_>>();

    info!("We need to evaluate the permissions of the following files {:#?}", info_with_paths);
    // Given the file `paths`, check if the current process has the required permissions for each file.
    let is_allowed = info_with_paths
        .into_iter()
        .map(|(permission, dataset_identifier, path)| {
            // TODO: Unneeded expect
            let user = policy.get_local_name(&dataset_identifier, &workflow.user.name).expect("Could not find user");
            return (path.clone(), satisfies_posix_permissions(&path, user, &permission));
        })
        .inspect(|(path, result)| {
            if !result {
                error!("The global user '{:}' does not have required permissions on {:?}", workflow.user.name.clone(), path);
            }
        })
        .all(|(_, result)| result);

    info!("Found: {} datasets", datasets.len());
    for (_, dataset) in &datasets {
        debug!("Dataset: {:?}", dataset.name);
    }
    is_allowed
}

#[async_trait::async_trait]
impl<L: ReasonerConnectorAuditLogger + Send + Sync + 'static> ReasonerConnector<L> for PosixReasonerConnector {
    async fn execute_task(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        _state: State,
        workflow: Workflow,
        task: String,
    ) -> Result<ReasonerResponse, ReasonerConnError> {

        //TODO: Only extract the first policy for now
        let policy_content: PolicyContent = policy.content.get(0).expect("Failed to parse PolicyContent").clone();
        let content_str = policy_content.content.get().trim();
        let posix_policy: PosixPolicy = PosixPolicy { datasets: serde_json::from_str(content_str).expect("Failed to parse PosixPolicy") };


        println!("JSON String: {}", content_str);

        // let posix_policy: PosixPolicy = serde_json::from_str(content_str).expect("Failed to parse the content into PosixPolicy");

        let is_allowed = validate_dataset_permissions(&workflow, &posix_policy, Some(&task));
        if !is_allowed {
            return Ok(ReasonerResponse::new(false, vec!["We do not have sufficient permissions".to_owned()]));
        }
        return Ok(ReasonerResponse::new(true, vec![]));
    }

    async fn access_data_request(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        _state: State,
        workflow: Workflow,
        _data: String,
        task: Option<String>,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        let policy_content: PolicyContent = policy.content.get(0).expect("Failed to parse PolicyContent").clone();
        let content_str = policy_content.content.get().trim();
        let posix_policy: PosixPolicy = PosixPolicy { datasets: serde_json::from_str(content_str).expect("Failed to parse PosixPolicy") };
        // TODO: `task` is optional. What are the semantics here?
        let Some(task) = task else {
            return Ok(ReasonerResponse::new(true, vec![]));
        };
        let is_allowed = validate_dataset_permissions(&workflow, &posix_policy, Some(&task));
        if !is_allowed {
            return Ok(ReasonerResponse::new(false, vec!["We do not have sufficient permissions".to_owned()]));
        }
        return Ok(ReasonerResponse::new(true, vec![]));
    }

    async fn workflow_validation_request(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        _state: State,
        workflow: Workflow,
    ) -> Result<ReasonerResponse, ReasonerConnError> {

        let policy_content: PolicyContent = policy.content.get(0).expect("Failed to parse PolicyContent").clone();
        let content_str = policy_content.content.get().trim();
        let posix_policy: PosixPolicy = PosixPolicy { datasets: serde_json::from_str(content_str).expect("Failed to parse PosixPolicy") };

        info!("Local user name: {:?}", posix_policy.get_local_name("umc_utrecht_ect", "test"));
        info!("Workflow user name: {}", workflow.user.name);

        // TODO: What are the semantics of this endpoint? What permissions should the user have? Read + Execute on all
        // datasets for now.
        let is_allowed = validate_dataset_permissions(&workflow, &posix_policy, None);
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

fn find_datasets_in_workflow(workflow: &Workflow, task_name: Option<&str>) -> Vec<Dataset> {
    let mut datasets: Vec<Dataset> = Vec::new();
    debug!("Walking the workflow in order to find datasets. Starting with {:?}", &workflow.start);
    find_datasets(&workflow.start, &mut datasets, task_name);

    datasets
}

// TODO: Might be preferable to use references to the datasets
fn find_datasets(elem: &Elem, datasets: &mut Vec<Dataset>, task_name: Option<&str>) {
    // TODO: Split this into the read / write / execute datasets
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
