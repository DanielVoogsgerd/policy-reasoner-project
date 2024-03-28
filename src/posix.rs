//! A policy reasoner implementation based on POSIX file permissions
//!
//! TODO: This is a module right now, but should be part of the binary.
//! this is because right now documenting binaries is tricky in rust. As soon as we find a better
//! solution this documentation should be moved to the binary itself.
//! This might be useful in general, but particularly it is important to document reference
//! implementations

use std::collections::HashSet;
use std::iter::repeat;
use std::path::Path;
use std::collections::HashMap;

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use audit_logger::{ConnectorContext, ConnectorWithContext, ReasonerConnectorAuditLogger, SessionedConnectorAuditLogger};
use itertools::{Either, Itertools};
use log::{debug, error, info};
use policy::{Policy, PolicyContent};
use reasonerconn::{ReasonerConnError, ReasonerConnector, ReasonerResponse};
use serde::Deserialize;
use specifications::data::{DataIndex, Location};
use state_resolver::State;
use workflow::utils::{walk_workflow_preorder, WorkflowVisitor};
use workflow::{spec::Workflow, Dataset};

/// This location is an assumption right now, and is needed as long as the location is not passed
/// to the workflow validator
static ASSUMED_LOCATION: &str = "surf";

/***** LIBRARY *****/
pub struct PosixReasonerConnector {
    data_index: DataIndex,
}
type LocationIdentifier = String;
type GlobalUsername = String;
type PosixPolicyUserMapping = HashMap<GlobalUsername, PosixUser>;

#[derive(Deserialize, Debug)]
pub struct PosixPolicy {
    datasets: HashMap<LocationIdentifier, PosixPolicyUserMapping>,
}

#[derive(Deserialize, Debug)]
struct PosixUser {
    uid: u32,
    gids: Vec<u32>,
}

#[derive(thiserror::Error, Debug)]
enum PolicyError {
    #[error("Missing location: {0}")]
    MissingLocation(String),
    #[error("Missing user: {0} for location: {1}")]
    MissingUser(String, String),
}

impl PosixPolicy {
    /// Given a dataset identifier (e.g., "umc_utrecht_ect") and a global username (e.g., "test"), returns the local
    /// triad (file_owner, group, or others) that this combination maps to.
    fn get_local_name(&self, location: &str, workflow_user: &str) -> Result<&PosixUser, PolicyError> {
        self.datasets
            .get(location)
            .ok_or_else(|| PolicyError::MissingLocation(location.to_owned()))?
            .get(workflow_user)
            .ok_or_else(|| PolicyError::MissingUser(workflow_user.to_owned(), location.to_owned()))
    }
}

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
    pub fn new(data_index: DataIndex) -> Self {
        info!("Creating new PosixReasonerConnector with {} plugin", std::any::type_name::<Self>());
        debug!("Parsing nested arguments for PosixReasonerConnector<{}>", std::any::type_name::<Self>());

        PosixReasonerConnector { data_index }
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

enum ValidationOutput {
    Ok,
    // The string here represents a Dataset.name, we might want to encapsulate the Dataset itself
    Fail(Vec<String>),
}

#[derive(thiserror::Error, Debug)]
enum ValidationError {
    #[error("Policy Error: {0}")]
    PolicyError(PolicyError),
    #[error("Unknown dataset: {0}")]
    UnknownDataset(String),
}

/// Check if all the data accesses in the workflow are done on behalf of users with the required permissions
fn validate_dataset_permissions(
    workflow: &Workflow,
    data_index: &DataIndex,
    policy: &PosixPolicy,
) -> Result<ValidationOutput, Vec<ValidationError>> {
    // The datasets used in the workflow. E.g., "st_antonius_ect".
    let datasets = find_datasets_in_workflow(&workflow);

    let (forbidden, errors): (Vec<_>, Vec<_>) = std::iter::empty()
        .chain(datasets.read_sets.iter().zip(repeat(vec![PosixPermission::Read])))
        .chain(datasets.write_sets.iter().zip(repeat(vec![PosixPermission::Write])))
        .chain(datasets.execute_sets.iter().zip(repeat(vec![PosixPermission::Read, PosixPermission::Execute])))
        .flat_map(|((location, dataset), permission)| {
            let Some(dataset) = data_index.get(&dataset.name) else {
                return Either::Left(std::iter::once(Err(ValidationError::UnknownDataset(dataset.name.clone()))));
            };
            Either::Right(dataset.access.values().map(move |kind| match kind {
                specifications::data::AccessKind::File { path } => {
                    info!("Contents of the DataInfo object:\n{:#?}", dataset);
                    let user = policy.get_local_name(&location, &workflow.user.name).map_err(|e| ValidationError::PolicyError(e))?;
                    let result = satisfies_posix_permissions(&path, user, &permission);
                    return Ok((dataset.name.clone(), path, result));
                },
            }))
        })
        // From where we are gonna focus on the problems that occurred in the validation
        // These can be seperated into groups: Errors (e.g. Non-existing users / files), and
        // validation failures.
        .filter(|res| match res {
            // Filter out what was okay in either sense.
            Ok((_, _, true)) => false,
            _ => true,
        })
        .partition_map(|elem| match elem {
            Ok((dataset_identifier, _, _)) => Either::Left(dataset_identifier),
            Err(x) => Either::Right(x),
        });

    if !errors.is_empty() {
        return Err(errors);
    } else if forbidden.is_empty() {
        return Ok(ValidationOutput::Ok);
    } else {
        return Ok(ValidationOutput::Fail(forbidden));
    }
}

//Function that extracts the posix policy from the policy object
fn extract_policy(policy: Policy) -> PosixPolicy {
    let policy_content: PolicyContent = policy.content.get(0).expect("Failed to parse PolicyContent").clone();
    let content_str = policy_content.content.get().trim();
    let posix_policy: PosixPolicy = PosixPolicy { datasets: serde_json::from_str(content_str).expect("Failed to parse PosixPolicy") };
    posix_policy
}

/***** LIBRARY *****/
#[async_trait::async_trait]
impl<L: ReasonerConnectorAuditLogger + Send + Sync + 'static> ReasonerConnector<L> for PosixReasonerConnector {
    async fn execute_task(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        _state: State,
        workflow: Workflow,
        _task: String,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        let posix_policy = extract_policy(policy);
        match validate_dataset_permissions(&workflow, &self.data_index, &posix_policy) {
            Ok(ValidationOutput::Ok) => Ok(ReasonerResponse::new(true, vec![])),
            Ok(ValidationOutput::Fail(datasets)) => Ok(ReasonerResponse::new(
                false,
                datasets.into_iter().map(|dataset| format!("We do not have sufficient permissions for dataset: {dataset}")).collect(),
            )),
            Err(errors) => Ok(ReasonerResponse::new(false, errors.into_iter().map(|error| error.to_string()).collect())),
        }
    }

    async fn access_data_request(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        _state: State,
        workflow: Workflow,
        _data: String,
        _task: Option<String>,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        let posix_policy = extract_policy(policy);
        match validate_dataset_permissions(&workflow, &self.data_index, &posix_policy) {
            Ok(ValidationOutput::Ok) => Ok(ReasonerResponse::new(true, vec![])),
            Ok(ValidationOutput::Fail(datasets)) => Ok(ReasonerResponse::new(
                false,
                datasets.into_iter().map(|dataset| format!("We do not have sufficient permissions for dataset: {dataset}")).collect(),
            )),
            Err(errors) => Ok(ReasonerResponse::new(false, errors.into_iter().map(|error| error.to_string()).collect())),
        }
    }

    async fn workflow_validation_request(
        &self,
        _logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        _state: State,
        workflow: Workflow,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        let posix_policy = extract_policy(policy);
        match validate_dataset_permissions(&workflow, &self.data_index, &posix_policy) {
            Ok(ValidationOutput::Ok) => Ok(ReasonerResponse::new(true, vec![])),
            Ok(ValidationOutput::Fail(datasets)) => Ok(ReasonerResponse::new(
                false,
                datasets.into_iter().map(|dataset| format!("We do not have sufficient permissions for dataset: {dataset}")).collect(),
            )),
            Err(errors) => Ok(ReasonerResponse::new(false, errors.into_iter().map(|error| error.to_string()).collect())),
        }
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
    read_sets: Vec<(Location, Dataset)>,
    write_sets: Vec<(Location, Dataset)>,
    execute_sets: Vec<(Location, Dataset)>,
}

fn find_datasets_in_workflow(workflow: &Workflow) -> WorkflowDatasets {
    debug!("Walking the workflow in order to find datasets. Starting with {:?}", &workflow.start);
    let mut visitor = DatasetCollectorVisitor {
        read_sets: Default::default(),
        write_sets: Default::default(),
        execute_sets: Default::default(),
    };

    walk_workflow_preorder(&workflow.start, &mut visitor);

    WorkflowDatasets { read_sets: visitor.read_sets, write_sets: visitor.write_sets, execute_sets: visitor.execute_sets }
}

struct DatasetCollectorVisitor {
    pub read_sets: Vec<(Location, Dataset)>,
    pub write_sets: Vec<(Location, Dataset)>,
    pub execute_sets: Vec<(Location, Dataset)>,
}

impl WorkflowVisitor for DatasetCollectorVisitor {
    fn visit_task(&mut self, task: &workflow::ElemTask) {
        // FIXME: Location is not currently sent as part of the workflow validation request,
        // this makes this not really possible to do now. To ensure the code is working
        // however, we will for the mean time assume the location

        let location = task.location.clone().unwrap_or_else(|| String::from(ASSUMED_LOCATION));
        if let Some(output) = &task.output {
            self.read_sets.push((location.clone(), output.clone()));
        }
    }

    fn visit_commit(&mut self, commit: &workflow::ElemCommit) {
        let location = commit.location.clone().unwrap_or_else(|| String::from(ASSUMED_LOCATION));
        self.read_sets.extend(repeat(location.clone()).zip(commit.input.iter().cloned()));

        // TODO: Maybe create a dedicated enum type for this e.g. NewDataset for datasets that will be
        // created, might fail if one already exists.
        let location = commit.location.clone().unwrap_or_else(|| String::from(ASSUMED_LOCATION));
        self.write_sets.push((location.clone(), Dataset { name: commit.data_name.clone(), from: None }));
    }

    // TODO: We do not really have a location for this one right now, we should figure out how to
    // interpret this
    fn visit_stop(&mut self, stop_sets: &HashSet<Dataset>) {
        let location = String::from(ASSUMED_LOCATION);
        self.write_sets.extend(repeat(location).zip(stop_sets.iter().cloned()));
    }
}
