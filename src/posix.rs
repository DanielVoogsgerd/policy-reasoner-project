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

/// This location is an assumption right now, and is needed as long as the location is not passed to the workflow
/// validator.
static ASSUMED_LOCATION: &str = "surf";

/***** LIBRARY *****/
/// E.g., `st_antonius_etc`.
type LocationIdentifier = String;
/// The global username as defined in [`Workflow.user`]. E.g., `test`.
type GlobalUsername = String;

/// The overarching POSIX policy. Check out the module documentation for an overview.
#[derive(Deserialize, Debug)]
pub struct PosixPolicy {
    datasets: HashMap<LocationIdentifier, PosixPolicyLocation>,
}

impl PosixPolicy {
    /// Extracts and parses a [`PosixPolicy`] from a generic [`Policy`] object. Expects the policy to be specified and
    /// expects it to adhere to the [`PosixPolicy`] YAML structure. See [`PosixPolicy`].
    fn from_policy(policy: Policy) -> Self {
        let policy_content: PolicyContent = policy.content.get(0).expect("Failed to parse PolicyContent").clone();
        let content_str = policy_content.content.get().trim();
        PosixPolicy { 
            datasets: serde_json::from_str(content_str).expect("Failed to parse PosixPolicy") 
        }
    }

    /// Given a location (e.g., `st_antonius_ect`) and the workflow user's name (e.g., `test`), returns the
    /// [`PosixLocalIdentity`] for that user.
    /// 
    /// The returned identity is used for file permission checks. For more about this permissions check see
    /// [`validate_dataset_permissions`].
    fn get_local_identity(&self, location: &str, workflow_user: &str) -> Result<&PosixLocalIdentity, PolicyError> {
        self.datasets
            .get(location)
            .ok_or_else(|| PolicyError::MissingLocation(location.to_owned()))?
            .user_map
            .get(workflow_user)
            .ok_or_else(|| PolicyError::MissingUser(workflow_user.to_owned(), location.to_owned()))
    }
}

#[derive(thiserror::Error, Debug)]
enum PolicyError {
    #[error("Missing location: {0}")]
    MissingLocation(String),
    #[error("Missing user: {0} for location: {1}")]
    MissingUser(String, String),
}

/// Part of the [`PosixPolicy`]. Represents a location (e.g., `st_antonius_etc`) and contains the global workflow
/// username to local identity mappings for this location.
#[derive(Deserialize, Debug)]
pub struct PosixPolicyLocation {
    user_map: HashMap<GlobalUsername, PosixLocalIdentity>,
}

/// The local identity defines a user id and a list of group ids. The local identity is used on the machine on which a
/// dataset resides to check the local file permissions. For more about this permissions check see
/// [`validate_dataset_permissions`].
/// 
/// This identity is defined in the Posix policy file. Global usernames in the Posix policy map to these local
/// identities.
///
/// Example, given the Posix policy file below, then for the `st_antonius_ect` location, the `test` global username maps
/// to a local identity that contains the uid and gids.
/// ``` yaml
///  # file: posix-policy.yml
///  content:
///    st_antonius_ect:
///      user_map:
///        test:
///          uid: 1000
///          gids:
///            - 1001
///            - 1002
///            - 1003
/// ```
#[derive(Deserialize, Debug)]
struct PosixLocalIdentity {
    /// The user identifier of a Linux user.
    uid: u32,
    /// A list of Linux group identifiers.
    gids: Vec<u32>,
}

/// Represents a POSIX file permission. See: <https://en.wikipedia.org/wiki/File-system_permissions#Permissions>.
#[derive(Debug, Copy, Clone)]
enum PosixFilePermission {
    Read,
    Write,
    Execute,
}

impl PosixFilePermission {
    /// Returns this permission's mode bit.
    /// - `Read` → `4`
    /// - `Write` → `2`
    /// - `Execute` → `1`.
    ///
    /// For more about POSIX permission bits see:
    /// <https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation>.
    ///
    /// Also see the related [`UserType::get_mode_bitmask`].
    fn to_mode_bit(&self) -> u32 {
        match self {
            PosixFilePermission::Read => 4,
            PosixFilePermission::Write => 2,
            PosixFilePermission::Execute => 1,
        }
    }
}

/// Represents a POSIX file class, also known as a scope. See:
/// <https://en.wikipedia.org/wiki/File-system_permissions#Classes>.
#[derive(Copy, Clone, Deserialize)]
enum PosixFileClass {
    Owner,
    Group,
    Others,
}

impl PosixFileClass {
    /// Given a list of [`PosixFilePermission`]s will return an octal mode bitmask for this [`PosixFileClass`].
    /// 
    /// This bitmask represents what mode bits should be set on a file such that this class (e.g., `Owner`) satisfies
    /// the permissions (e.g, `Read`, `Write`). In this case it would be `0o400` (Read for Owner) and `0o200` (Write for
    /// Owner), which sums to the returned `0o600` (Read and Write for Owner).
    fn get_mode_bitmask(&self, required_permissions: &[PosixFilePermission]) -> u32 {
        let alignment_multiplier = match self {
            PosixFileClass::Owner => 0o100,
            PosixFileClass::Group => 0o10,
            PosixFileClass::Others => 0o1,
        };
        required_permissions.iter().fold(0, |acc, f| acc | acc | (alignment_multiplier * f.to_mode_bit()))
    }
}

/// Verifies whether the passed [`PosixLocalIdentity`] has all of the requested permissions (e.g., `Read` and `Write`)
/// on a particular file (defined by the `path`). The identity's user id and group ids are checked against the file
/// owner's user id and group id respectively. Additionally, the `Others` class permissions are also checked.
fn satisfies_posix_permissions(path: impl AsRef<Path>, local_identity: &PosixLocalIdentity, requested_permissions: &[PosixFilePermission]) -> bool {
    let metadata = std::fs::metadata(&path).expect("Could not get file metadata");

    let mode_bits = metadata.permissions().mode();
    let file_owner_uid = metadata.uid();
    let file_owner_gid = metadata.gid();

    if file_owner_uid == local_identity.uid {
        let mask = PosixFileClass::Owner.get_mode_bitmask(requested_permissions);
        if mode_bits & mask == mask {
            return true;
        }
    }

    if local_identity.gids.contains(&file_owner_gid) {
        let mask = PosixFileClass::Group.get_mode_bitmask(requested_permissions);
        if mode_bits & mask == mask {
            return true;
        }
    }

    let mask = PosixFileClass::Others.get_mode_bitmask(requested_permissions);
    mode_bits & mask == mask
}

enum ValidationOutput {
    Ok,
    // Below we might want to encapsulate the Dataset itself.
    /// The string here represents a `Dataset.name`.
    Fail(Vec<String>),
}

#[derive(thiserror::Error, Debug)]
enum ValidationError {
    #[error("Policy Error: {0}")]
    PolicyError(PolicyError),
    #[error("Unknown dataset: {0}")]
    UnknownDataset(String),
}

/// Check if all the data accesses performed in the `workflow` are done on behalf of users that have the required
/// permissions. If not all permissions are met, then [`ValidationError`]s are returned. These errors contain more
/// information about the problems that occurred during validation.
fn validate_dataset_permissions(
    workflow: &Workflow,
    data_index: &DataIndex,
    policy: &PosixPolicy,
) -> Result<ValidationOutput, Vec<ValidationError>> {
    // The datasets used in the workflow. E.g., `st_antonius_ect`.
    let datasets = find_datasets_in_workflow(&workflow);

    let (forbidden, errors): (Vec<_>, Vec<_>) = std::iter::empty()
        .chain(datasets.read_sets.iter().zip(repeat(vec![PosixFilePermission::Read])))
        .chain(datasets.write_sets.iter().zip(repeat(vec![PosixFilePermission::Write])))
        .chain(datasets.execute_sets.iter().zip(repeat(vec![PosixFilePermission::Read, PosixFilePermission::Execute])))
        .flat_map(|((location, dataset), permission)| {
            let Some(dataset) = data_index.get(&dataset.name) else {
                return Either::Left(std::iter::once(Err(ValidationError::UnknownDataset(dataset.name.clone()))));
            };
            Either::Right(dataset.access.values().map(move |kind| match kind {
                specifications::data::AccessKind::File { path } => {
                    info!("Contents of the DataInfo object:\n{:#?}", dataset);
                    let local_identity = policy.get_local_identity(&location, &workflow.user.name).map_err(|e| ValidationError::PolicyError(e))?;
                    let result = satisfies_posix_permissions(&path, local_identity, &permission);
                    return Ok((dataset.name.clone(), path, result));
                },
            }))
        })
        // This is where we are going to focus on the problems that occurred in the validation
        // These can be separated into groups: Errors (e.g. Non-existing users / files), and
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

pub struct PosixReasonerConnector {
    data_index: DataIndex,
}

impl PosixReasonerConnector {
    pub fn new(data_index: DataIndex) -> Self {
        info!("Creating new PosixReasonerConnector with {} plugin", std::any::type_name::<Self>());
        debug!("Parsing nested arguments for PosixReasonerConnector<{}>", std::any::type_name::<Self>());

        PosixReasonerConnector { data_index }
    }
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
        let posix_policy = PosixPolicy::from_policy(policy);
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
        let posix_policy = PosixPolicy::from_policy(policy);
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
        let posix_policy = PosixPolicy::from_policy(policy);
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
