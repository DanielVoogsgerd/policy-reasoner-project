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

/***** HELPER MACROS *****/
/// Shortcut for creating an eFLINT JSON Specification [`Phrase::Create`].
///
/// # Arguments
/// - `inst`: A single eFLINT [`Expression`] that is an instance expression determining what to create; i.e., `foo(Amy, Bob)` in `+foo(Amy, Bob).`.
///
/// # Returns
/// A new [`Phrase::Create`] (or rather, the Rust code to create it).
macro_rules! create {
    ($inst:expr) => {
        Phrase::Create(PhraseCreate { operand: $inst })
    };
}

/// Shortcut for creating an eFLINT JSON Specification [`Expression::ConstructorApp`].
///
/// # Arguments
/// - _array syntax_
///   - `id`: The (string) identifier of the relation to construct; i.e., `foo` in `foo(Amy, Bob)`.
///   - `args...`: Zero or more addinitional [`Expression`]s that make up the arguments of the constructor application; i.e., `Amy` or `Bob` in `foo(Amy, Bob)`.
///
/// # Returns
/// A new [`Expression::ConstructorApp`] (or rather, the Rust code to create it).
macro_rules! constr_app {
    ($id:expr $(, $args:expr)* $(,)?) => {
        Expression::ConstructorApp(ExpressionConstructorApp {
            identifier: ($id).into(),
            operands:   ConstructorInput::ArraySyntax(vec![ $($args),* ]),
        })
    };
}

/// Shortcut for creating an eFLINT JSON Specification [`Expression::Primitive(ExpressionPrimitive::String)`].
///
/// # Arguments
/// - `val`: The string value to put in the string primitive. Note that this is automatically `into()`d; so passing a `&str` will work, for example.
///
/// # Returns
/// A new [`Expression::Primitive(ExpressionPrimitive::String)`] (or rather, the Rust code to create it).
macro_rules! str_lit {
    ($val:expr) => {
        Expression::Primitive(ExpressionPrimitive::String(($val).into()))
    };
}

/***** CONSTANTS *****/
/// The identifier used for this connector backend.
pub const EFLINT_JSON_ID: &'static str = "eflint-json";

// Externalized "constants"
/// The entire base specification, already serialized as eFLINT JSON. See `build.rs` to find how the `BASE_DEFS_EFLINT_JSON` environment variable is populated.
const JSON_BASE_SPEC: &str = include_str!(env!("BASE_DEFS_EFLINT_JSON"));
/// A hash of the entire base specification, precomputed by `build.rs`.
const JSON_BASE_SPEC_HASH: &str = env!("BASE_DEFS_EFLINT_JSON_HASH");

/***** ERRORS *****/
/// Main error that originates from the [`EFlintReasonerConnector`].
#[derive(Debug)]
pub enum Error<E> {
    /// Failed to parse the CLI arguments to the eFLINT reasoner connector.
    CliArgumentsParse { raw: String, err: nested_cli_parser::map_parser::Error },
    /// Failed to construct the nested ErrorHandler plugin.
    ErrorHandler { name: &'static str, err: E },
}
impl<E> Display for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            CliArgumentsParse { raw, .. } => write!(f, "Failed to parse '{raw}' as CLI argument string for an EFlintReasonerConnector"),
            ErrorHandler { name, .. } => write!(f, "Failed to initialize error handler plugin '{name}'"),
        }
    }
}
impl<E: 'static + error::Error> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            CliArgumentsParse { err, .. } => Some(err),
            ErrorHandler { err, .. } => Some(err),
        }
    }
}

/// Error that originates from the [`EFlintLeakPrefixErrors`].
#[derive(Debug)]
pub enum EFlintLeakPrefixErrorsError {
    /// Failed to parse the CLI arguments to the EFlintLeakPrefixErrors.
    CliArgumentsParse { raw: String, err: nested_cli_parser::map_parser::Error },
}
impl Display for EFlintLeakPrefixErrorsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use EFlintLeakPrefixErrorsError::*;
        match self {
            CliArgumentsParse { raw, .. } => write!(f, "Failed to parse '{raw}' as CLI argument string for an EFlintLeakPrefixErrors"),
        }
    }
}
impl error::Error for EFlintLeakPrefixErrorsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use EFlintLeakPrefixErrorsError::*;
        match self {
            CliArgumentsParse { err, .. } => Some(err),
        }
    }
}

/***** ERROR HANDLERS *****/
pub trait EFlintErrorHandler {
    type Error: error::Error;

    fn new(cli_args: &HashMap<String, Option<String>>) -> Result<Self, Self::Error>
    where
        Self: Sized;

    #[inline]
    fn extract_errors(&self, _: Option<&PhraseResult>) -> Vec<String> {
        vec![]
    }

    #[inline]
    fn nested_args() -> Vec<(char, &'static str, &'static str)> {
        vec![]
    }
}

pub struct EFlintLeakNoErrors;
impl EFlintErrorHandler for EFlintLeakNoErrors {
    type Error = std::convert::Infallible;

    #[inline]
    fn new(_cli_args: &HashMap<String, Option<String>>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        // Doesn't need to parse anything!
        Ok(Self)
    }
}

/// EFlintLeakPrefixErrors is an e-flint error handler
/// that returns errors if the violation identifier start with a certain
/// prefix. Which prefix is matched against can be configured.
pub struct EFlintLeakPrefixErrors {
    prefix: String,
}
impl EFlintErrorHandler for EFlintLeakPrefixErrors {
    type Error = EFlintLeakPrefixErrorsError;

    fn new(args: &HashMap<String, Option<String>>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        debug!("Parsing nested arguments for EFlintLeakPrefixErrors");
        let prefix: String = match args.get("prefix") {
            Some(Some(path)) => path.into(),
            _ => "pub-".into(),
        };

        // Done
        Ok(Self { prefix })
    }

    fn extract_errors(&self, result: Option<&PhraseResult>) -> Vec<String> {
        result
            .map(|r| match r {
                eflint_json::spec::PhraseResult::StateChange(sc) => match &sc.violations {
                    Some(v) => v.iter().filter(|v| v.identifier.starts_with(&self.prefix)).map(|v| v.identifier.clone()).collect(),
                    None => vec![],
                },
                _ => vec![],
            })
            .unwrap_or_else(Vec::new)
    }

    #[inline]
    fn nested_args() -> Vec<(char, &'static str, &'static str)> {
        vec![('p', "prefix", "Any eFLINT facts that have this prefix will be shared with clients. Default: 'pub-'")]
    }
}

/***** LIBRARY *****/
pub struct EFlintReasonerConnector<T: EFlintErrorHandler> {
    pub addr: String,
    err_handler: T,
    base_defs: Vec<Phrase>,
}

impl<T: EFlintErrorHandler> EFlintReasonerConnector<T> {
    pub fn new(cli_args: String) -> Result<Self, Error<T::Error>> {
        info!("Creating new EFlintReasonerConnector with {} plugin", std::any::type_name::<T>());

        debug!("Parsing nested arguments for EFlintReasonerConnector<{}>", std::any::type_name::<T>());
        let parser = MapParser::new(Self::cli_args());
        let args: HashMap<String, Option<String>> = match parser.parse(&cli_args) {
            Ok(args) => args,
            Err(err) => return Err(Error::CliArgumentsParse { raw: cli_args, err }),
        };

        // See what to do with it
        let addr: String = match args.get("reasoner-address") {
            Some(Some(path)) => path.into(),
            _ => "http://localhost:8080".into(),
        };
        let err_handler: T = match T::new(&args) {
            Ok(handler) => handler,
            Err(err) => return Err(Error::ErrorHandler { name: std::any::type_name::<T>(), err }),
        };

        debug!("Creating new EFlintReasonerConnector to '{addr}'");
        let base_defs: RequestPhrases = serde_json::from_str(JSON_BASE_SPEC).unwrap();
        Ok(EFlintReasonerConnector { addr, base_defs: base_defs.phrases, err_handler })
    }

    /// Returns the arguments necessary to build the parser for the EFlintReasonerConnector.
    ///
    /// # Returns
    /// A vector of arguments appropriate to use to build a [`MapParser`].
    #[inline]
    fn cli_args() -> Vec<(char, &'static str, &'static str)> {
        let mut args: Vec<(char, &'static str, &'static str)> = vec![(
            'r',
            "reasoner-address",
            "The address (as `<scheme>://<hostname>:<port>`) of the actual reasoner to connect with. Default: 'http://localhost:8080'",
        )];
        args.extend(T::nested_args());
        args
    }

    /// Returns a formatter that can be printed to understand the arguments to this connector.
    ///
    /// # Arguments
    /// - `short`: A shortname for the argument that contains the nested arguments we parse.
    /// - `long`: A longname for the argument that contains the nested arguments we parse.
    ///
    /// # Returns
    /// A [`NestedCliParserHelpFormatter`] that implements [`Display`].
    pub fn help<'l>(short: char, long: &'l str) -> NestedCliParserHelpFormatter<'static, 'l, MapParser> {
        MapParser::new(Self::cli_args()).into_help("EFlintReasonerConnector plugin", short, long)
    }

    fn conv_state_to_eflint(&self, state: State) -> Vec<Phrase> {
        debug!(
            "Serializing state of {} datasets, {} functions, {} locations and {} users to eFLINT phrases",
            state.datasets.len(),
            state.functions.len(),
            state.locations.len(),
            state.users.len()
        );
        let mut result: Vec<Phrase> = Vec::<Phrase>::new();

        for user in state.users.iter() {
            // ```eflint
            // +user(#user.name).
            // ```
            let user_constr: Expression = constr_app!("user", str_lit!(user.name.clone()));
            result.push(create!(user_constr.clone()));
        }
        let user_len: usize = result.len();
        debug!("Generated {} user phrases", user_len);

        for location in state.locations.iter() {
            // ```eflint
            // +user(#location.name).
            // +domain(user(#location.name))
            // ```
            let user_constr: Expression = constr_app!("user", str_lit!(location.name.clone()));
            result.push(create!(user_constr.clone()));
            result.push(create!(constr_app!("domain", user_constr)));

            // add metadata
        }
        let location_len: usize = result.len();
        debug!("Generated {} location phrases", location_len - user_len);

        for dataset in state.datasets.iter() {
            // ```eflint
            // +asset(#data.name).
            // ```
            result.push(create!(constr_app!("asset", str_lit!(dataset.name.clone()))));
        }
        let dataset_len: usize = result.len();
        debug!("Generated {} dataset phrases", dataset_len - location_len);

        for function in state.functions.iter() {
            // ```eflint
            // +asset(#function.name).
            // +code(asset(#function.name)).
            // ```
            let asset_constr: Expression = constr_app!("asset", str_lit!(function.name.clone()));
            result.push(create!(asset_constr.clone()));
            result.push(create!(constr_app!("code", asset_constr)));
        }
        let function_len: usize = result.len();
        debug!("Generated {} function phrases", function_len - dataset_len);

        return result;
    }

    fn extract_eflint_policy(&self, policy: &Policy) -> Vec<Phrase> {
        info!("Extracting eFLINT policy...");
        let eflint_content: Vec<&PolicyContent> = policy.content.iter().filter(|x| x.reasoner == EFLINT_JSON_ID).collect();
        let eflint_content = eflint_content.first().unwrap();
        debug!("Deserializing input to eFLINT JSON...");
        let content: &str = eflint_content.content.get();
        let result: RequestPhrases = match serde_json::from_str(content) {
            Ok(result) => match result {
                Request::Phrases(phrases) => phrases,
                Request::Handshake(_) | Request::Inspect(_) | Request::Ping(_) => panic!("Cannot accept non-Phrases Request input from request"),
            },
            Err(err) => panic!(
                "Input is not valid eFLINT JSON: {err}\n\nInput:\n{}\n{}\n{}\n",
                (0..80).map(|_| '-').collect::<String>(),
                content,
                (0..80).map(|_| '-').collect::<String>()
            ),
        };
        result.phrases
    }

    fn conv_workflow(&self, workflow: Workflow) -> Vec<Phrase> {
        info!("Compiling Checker Workflow to eFLINT phrases...");
        workflow.to_eflint()
    }

    fn extract_eflint_version(&self, policy: &Policy) -> Result<Version, String> {
        info!("Retrieving eFLINT reasoner version from policy...");
        let eflint_content: Vec<&PolicyContent> = policy.content.iter().filter(|x| x.reasoner == EFLINT_JSON_ID).collect();
        let eflint_content = eflint_content.first().unwrap();
        let parts: Vec<&str> = eflint_content.reasoner_version.split(".").collect();

        if parts.len() != 3 {
            return Err(format!("Invalid version format, should be 'maj.min.patch', got '{}'", eflint_content.reasoner_version));
        }

        let maj = parts[0].parse::<u32>().map_err(|_| format!("Invalid major version part, could not parse {} into u32", parts[0]))?;
        let min = parts[1].parse::<u32>().map_err(|_| format!("Invalid minor version part, could not parse {} into u32", parts[1]))?;
        let patch = parts[2].parse::<u32>().map_err(|_| format!("Invalid patch version part, could not parse {} into u32", parts[2]))?;

        Ok(Version(maj, min, patch))
    }

    fn build_phrases(&self, policy: &Policy, state: State, workflow: Workflow, question: Phrase) -> Vec<Phrase> {
        let mut phrases = Vec::<Phrase>::new();

        // Build request
        // 1. Base Facts
        debug!("Loading interface ({} phrase(s))", self.base_defs.len());
        phrases.extend(self.base_defs.clone());

        // 2. Fill knowledgebase from state
        let state_phrases: Vec<Phrase> = self.conv_state_to_eflint(state);
        debug!("Loading state ({} phrase(s))", state_phrases.len());
        phrases.extend(state_phrases);

        // 3. Add request
        debug!("Loading question (1 phrase(s))");
        phrases.push(question);

        // 4. Add workflow
        let workflow_phrases: Vec<Phrase> = self.conv_workflow(workflow);
        debug!("Loading workflow ({} phrase(s))", workflow_phrases.len());
        phrases.extend(workflow_phrases);

        // 5. Add Policy
        let policy_phrases: Vec<Phrase> = self.extract_eflint_policy(&policy);
        debug!("Loading policy ({} phrase(s))", policy_phrases.len());
        phrases.extend(policy_phrases);

        phrases
    }



    async fn process_phrases<L: ReasonerConnectorAuditLogger + Send + Sync>(
        &self,
        logger: SessionedConnectorAuditLogger<L>,
        policy: &Policy,
        phrases: Vec<Phrase>,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        let version = self.extract_eflint_version(policy).map_err(|err| ReasonerConnError::new(err))?;
        debug!("Full request length: {} phrase(s)", phrases.len());
        let request = Request::Phrases(RequestPhrases { common: RequestCommon { version, extensions: HashMap::new() }, phrases, updates: true });
        debug!("Full request:\n\n{}\n\n", serde_json::to_string_pretty(&request).unwrap_or_else(|_| "<serialization failure>".into()));

        // Make request
        debug!("Sending eFLINT exec-task request to '{}'", self.addr);
        let client = reqwest::Client::new();
        let res = client.post(&self.addr).json(&request).send().await.map_err(|err| ReasonerConnError::new(err.to_string()))?;

        debug!("Awaiting response...");
        let raw_body = res.text().await.map_err(|err| ReasonerConnError::new(err.to_string()))?;

        debug!("Log raw response...");

        logger.log_reasoner_response(&raw_body).await.map_err(|err| {
            debug!("Error trying to log{:?}", err);
            ReasonerConnError::new(err.to_string())
        })?;

        debug!("Parsing response...");
        let response = serde_json::from_str::<eflint_json::spec::ResponsePhrases>(&raw_body).map_err(|err| {
            error!(
                "{}\n\nRaw response:\n{}\n{}\n{}\n",
                err,
                (0..80).map(|_| '-').collect::<String>(),
                raw_body,
                (0..80).map(|_| '-').collect::<String>()
            );
            ReasonerConnError::new(err.to_string())
        })?;

        debug!("Analysing response...");
        let errors: Vec<String> = self.err_handler.extract_errors(response.results.last());

        // TODO proper handle invalid query and unexpected result
        let success: Result<bool, String> = response
            .results
            .last()
            .map(|r| match r {
                eflint_json::spec::PhraseResult::BooleanQuery(r) => Ok(r.result),
                eflint_json::spec::PhraseResult::InstanceQuery(_) => Err("Invalid query".into()),
                eflint_json::spec::PhraseResult::StateChange(r) => Ok(!r.violated),
            })
            .unwrap_or_else(|| Err("Unexpected result".into()));

        match success {
            Ok(success) => {
                debug!(
                    "Response judged as: {} ({} && {})",
                    if success && response.common.success { "success" } else { "violated" },
                    success,
                    response.common.success
                );
                Ok(ReasonerResponse::new(success && response.common.success, errors))
            },
            // TODO better error handling
            Err(err) => Err(ReasonerConnError::new(err)),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EFlintReasonerConnectorContext {
    #[serde(rename = "type")]
    pub t: String,
    pub version: String,
    pub base_defs: String,
    pub base_defs_hash: String,
}

impl std::hash::Hash for EFlintReasonerConnectorContext {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.t.hash(state);
        self.version.hash(state);
        self.base_defs_hash.hash(state);
    }
}

impl ConnectorContext for EFlintReasonerConnectorContext {
    fn r#type(&self) -> String {
        self.t.clone()
    }

    fn version(&self) -> String {
        self.version.clone()
    }
}

impl<T: EFlintErrorHandler> ConnectorWithContext for EFlintReasonerConnector<T> {
    type Context = EFlintReasonerConnectorContext;

    #[inline]
    fn context() -> Self::Context {
        EFlintReasonerConnectorContext {
            t: "eflint-json".into(),
            // NOTE: Must stay at 0.1.0, since else Olaf's reasoner will complain it's the wrong version lol
            // TODO: Decouple reasoner version from the version on the wire (at least for now)
            version: "0.1.0".into(),
            base_defs: JSON_BASE_SPEC.into(),
            base_defs_hash: JSON_BASE_SPEC_HASH.into(),
        }
    }
}

#[async_trait::async_trait]
impl<L: ReasonerConnectorAuditLogger + Send + Sync + 'static, T: EFlintErrorHandler + Send + Sync + 'static> ReasonerConnector<L>
    for EFlintReasonerConnector<T>
{
    async fn execute_task(
        &self,
        logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        state: State,
        workflow: Workflow,
        task: String,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        info!("Considering task '{}' in workflow '{}' for execution", task, workflow.id);

        // Add the question for this task
        // ```eflint
        // +task-to-execute(task(node(workflow(#workflow.id), #task))).
        // ```
        let question: Phrase = create!(constr_app!(
            "task-to-execute",
            constr_app!("task", constr_app!("node", constr_app!("workflow", str_lit!(workflow.id.clone())), str_lit!(task)))
        ));

        // Build & submit the phrases with the given policy, state, workflow _and_ question
        let phrases = self.build_phrases(&policy, state, workflow, question);
        self.process_phrases(logger, &policy, phrases).await
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
        // Determine if we're asking for a node-to-node data transfer (there's a task as context) or a node-to-user (there's no task).
        let question: Phrase = match task {
            Some(task_id) => {
                info!("Considering data access '{}' for task '{}' in workflow '{}'", data, task_id, workflow.id);

                // ```eflint
                // +dataset-to-transfer(node-input(node(workflow(#workflow.id), #task), asset(#data))).
                // ```
                create!(constr_app!(
                    "dataset-to-transfer",
                    constr_app!(
                        "node-input",
                        constr_app!("node", constr_app!("workflow", str_lit!(workflow.id.clone())), str_lit!(task_id)),
                        constr_app!("asset", str_lit!(data)),
                    )
                ))
            },
            None => {
                info!("Considering data access '{}' for result of workflow '{}'", data, workflow.id);

                // ```eflint
                // +result-to-transfer(workflow-result-recipient(workflow-result(workflow(#workflow.id), asset(#data)), user(#workflow.user))).
                // ```
                create!(constr_app!(
                    "result-to-transfer",
                    constr_app!(
                        "workflow-result-recipient",
                        constr_app!("workflow-result", constr_app!("workflow", str_lit!(workflow.id.clone())), constr_app!("asset", str_lit!(data))),
                        constr_app!("user", str_lit!(workflow.user.name.clone()))
                    )
                ))
            },
        };

        let phrases = self.build_phrases(&policy, state, workflow, question);
        self.process_phrases(logger, &policy, phrases).await
    }

    async fn workflow_validation_request(
        &self,
        logger: SessionedConnectorAuditLogger<L>,
        policy: Policy,
        state: State,
        workflow: Workflow,
    ) -> Result<ReasonerResponse, ReasonerConnError> {
        info!("Considering workflow '{}'", workflow.id);

        // Add the question for this task
        // ```eflint
        // +workflow-to-execute(workflow(#workflow.id)).
        // ```
        let question = create!(constr_app!("workflow-to-execute", constr_app!("workflow", str_lit!(workflow.id.clone()))));

        // Build & submit the phrases with the given policy, state, workflow _and_ question
        let phrases = self.build_phrases(&policy, state, workflow, question);
        self.process_phrases(logger, &policy, phrases).await
    }
}
