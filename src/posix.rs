use std::path::Path;
use std::{
    collections::{HashMap, HashSet},
    error,
};

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use log::{debug, error, info};
use nested_cli_parser::map_parser::MapParser;
use nested_cli_parser::NestedCliParserHelpFormatter;
use policy::{Policy, PolicyContent};
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use serde::Deserialize;
use state_resolver::State;
use workflow::utils::{walk_workflow_preorder, WorkflowVisitor};
use workflow::{spec::Workflow, Dataset};

/***** LIBRARY *****/
pub struct PosixReasonerConnector {}

type DatasetIdentifier = String;
type GlobalUsername = String;
type PosixPolicyUserMapping = HashMap<GlobalUsername, PosixUser>;

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
    Owner,
    Group,
    Others,
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
            UserType::Owner => 0o100,
            UserType::Group => 0o10,
            UserType::Others => 0o1,
        };
        required_permissions.iter().fold(0, |acc, f| acc | acc | (alignment_multiplier * f.to_mode_bit()))
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

/// Verifies whether the passed users has the requested permissions on a particular file
fn satisfies_posix_permissions(path: impl AsRef<Path>, user: &PosixUser, requested_permissions: &[PosixPermission]) -> bool {
    let metadata = std::fs::metadata(&path).expect("Could not get file metadata");

    let mode_bits = metadata.permissions().mode();
    let file_uid = metadata.uid();
    let file_gid = metadata.gid();

    if file_uid == user.uid {
        let mask = UserType::Owner.get_mode_bitmask(requested_permissions);
        if mode_bits & mask == mask {
            return true;
        }
    }

    if user.gids.contains(&file_gid) {
        let mask = UserType::Group.get_mode_bitmask(requested_permissions);
        if mode_bits & mask == mask {
            return true;
        }
    }

    let mask = UserType::Others.get_mode_bitmask(requested_permissions);
    mode_bits & mask == mask
}

/// Check if all the data accesses in the workflow are done on behalf of users with the required
/// permissions
fn validate_dataset_permissions(workflow: &Workflow, policy: &PosixPolicy, task_name: Option<&str>) -> bool {
    // The datasets used in the workflow. E.g., "st_antonius_ect".
    let datasets = find_datasets_in_workflow(&workflow, task_name);

    // A data index, which contains dataset identifiers and their underlying files.
    // E.g., the "st_antonius_ect" dataset contains the "text.txt" file. See: tests/data/*
    // TODO: Pass data index in using params
    let data_index = brane_shr::utilities::create_data_index_from("tests/data");

    // FIXME: We can spare some copying here by using a reference
    std::iter::empty()
        .chain(datasets.read_sets.iter().zip(std::iter::repeat(vec![PosixPermission::Read])))
        .chain(datasets.write_sets.iter().zip(std::iter::repeat(vec![PosixPermission::Write])))
        .chain(datasets.execute_sets.iter().zip(std::iter::repeat(vec![PosixPermission::Read, PosixPermission::Execute])))
        .flat_map(|(dataset, permission)| {
            let dataset = data_index.get(&dataset.name).expect("Could not find dataset in dataindex");
            dataset.access.values().map(move |kind| match kind {
                specifications::data::AccessKind::File { path } => (permission.clone(), dataset.name.clone(), path.clone()),
            })
        })
        .map(|(permission, dataset_identifier, path)| {
            // TODO: Unneeded expect
            let user = policy.get_local_name(&dataset_identifier, &workflow.user.name).expect("Could not find user");
            (path.clone(), satisfies_posix_permissions(&path, user, &permission))
        })
        .inspect(|(path, result)| {
            if !result {
                error!("The global user '{:}' does not have required permissions on {:?}", workflow.user.name.clone(), path);
            }
        })
        .all(|(_, result)| result)
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

        Ok(ReasonerResponse::new(true, vec![]))
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

struct WorkflowDatasets {
    read_sets: Vec<Dataset>,
    write_sets: Vec<Dataset>,
    execute_sets: Vec<Dataset>,
}

fn find_datasets_in_workflow(workflow: &Workflow, task_name: Option<&str>) -> WorkflowDatasets {
    debug!("Walking the workflow in order to find datasets. Starting with {:?}", &workflow.start);
    // find_datasets(&workflow.start, &mut datasets, task_name);
    let mut visitor = DatasetCollectorVisitor {
        read_sets: Default::default(),
        write_sets: Default::default(),
        execute_sets: Default::default(),
        task_name: task_name.map(|x| x.to_owned()),
    };

    walk_workflow_preorder(&workflow.start, &mut visitor);

    // TODO: Return all datasets
    WorkflowDatasets { read_sets: visitor.read_sets, write_sets: visitor.write_sets, execute_sets: visitor.execute_sets }
}

struct DatasetCollectorVisitor {
    pub read_sets: Vec<Dataset>,
    pub write_sets: Vec<Dataset>,
    pub execute_sets: Vec<Dataset>,

    pub task_name: Option<String>,
}

impl WorkflowVisitor for DatasetCollectorVisitor {
    fn visit_task(&mut self, task: &workflow::ElemTask) {
        if let Some(output) = &task.output {
            self.read_sets.push(output.clone());
        }
    }

    fn visit_commit(&mut self, commit: &workflow::ElemCommit) {
        if !&self.task_name.is_some() {
            self.write_sets.extend(commit.input.iter().cloned());
        }
    }

    fn visit_stop(&mut self, stop_sets: &HashSet<Dataset>) {
        self.write_sets.extend(stop_sets.iter().cloned());
    }
}
