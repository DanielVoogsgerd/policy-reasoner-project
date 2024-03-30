//  DELIBERATION.rs
//    by Lut99
//
//  Created:
//    09 Jan 2024, 13:45:18
//  Last edited:
//    18 Jan 2024, 15:55:17
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the deliberation side of the [`Srv`].
//

use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::sync::Arc;

use audit_logger::{AuditLogger, SessionedConnectorAuditLogger};
use auth_resolver::{AuthContext, AuthResolver};
use brane_ast::SymTable;
use deliberation::spec::{
    AccessDataRequest, DataAccessResponse, DeliberationAllowResponse, DeliberationDenyResponse, DeliberationResponse, ExecuteTaskRequest,
    TaskExecResponse, Verdict, WorkflowValidationRequest, WorkflowValidationResponse,
};
use error_trace::ErrorTrace as _;
use log::{debug, error, info};
use policy::{Policy, PolicyDataAccess, PolicyDataError};
use reasonerconn::ReasonerConnector;
use serde::Serialize;
use state_resolver::StateResolver;
use warp::hyper::StatusCode;
use warp::reject::{Reject, Rejection};
use warp::reply::{Json, WithStatus};
use warp::Filter;
use workflow::Workflow;

use crate::Srv;


/***** HELPER FUNCTIONS *****/
/// Retrieves the currently active policy, or immediately denies the request if there is no such policy.
///
/// # Arguments
/// - `logger`: A [`SessionedConnectorAuditLogger`] on which to log the verdict if we deny because no active policy was found.
/// - `reference`: The UUID that the policy expert can use to recognize that this verdict belongs to a particular request, if any.
/// - `policystore`: The story with [`PolicyDataAccess`] from which we'll try to retrieve the active policy.
///
/// # Errors
/// This function may error (= reject the request) if no active policy was found or there was another error trying to retrieve it.


//Right now, throws an error if there is no active policy iteration
async fn get_active_policy<L: AuditLogger, P: PolicyDataAccess>(
    logger: &L,
    reference: &str,
    policystore: &P,
) -> Result<Result<Policy, WithStatus<Json>>, Rejection> {
    // Attempt to get the policy first
    match policystore.get_active().await {
        Ok(policy) => Ok(Ok(policy)),
        Err(PolicyDataError::NotFound) => {
            //TODO: fix later
            // Create the verdict
            let verdict = Verdict::Deny(DeliberationDenyResponse {
                shared: DeliberationResponse { verdict_reference: reference.into() },
                reasons_for_denial: Some(vec!["No active policy found".to_string()]),
            });

            // Log it: first, the "actual response" with the reason and then the verdict returned to the user
            logger.log_reasoner_response(reference, "<reasoner not queried because no active policy is present>").await.map_err(|err| {
                debug!("Could not log \"reasoner response\" to audit log : {:?} | request id: {}", err, reference);
                warp::reject::custom(err)
            })?;
            logger.log_verdict(reference, &verdict).await.map_err(|err| {
                debug!("Could not log verdict to audit log : {:?} | request id: {}", err, reference);
                warp::reject::custom(err)
            })?;

            // Then send it to the user as promised
            Ok(Err(warp::reply::with_status(warp::reply::json(&verdict), StatusCode::OK)))
        },
        Err(PolicyDataError::GeneralError(err)) => {
            error!("Failed to get currently active policy: {err}");
            Err(warp::reject::custom(RejectableString(err)))
        },
    }
}





/***** HELPERS *****/
/// Defines a wrapper around a [`String`] to make it [`Reject`]able.
struct RejectableString(String);
impl Debug for RejectableString {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { if f.alternate() { write!(f, "{:#?}", self.0) } else { write!(f, "{:?}", self.0) } }
}
impl Reject for RejectableString {}



/// Defines a wrapper around an [`Error`] that also makes it [`Reject`].
#[derive(Debug)]
struct RejectableError<E>(E);
impl<E: Display> Display for RejectableError<E> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}
impl<E: Error> Error for RejectableError<E> {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> { self.0.source() }
}
impl<E: 'static + Debug + Send + Sync> Reject for RejectableError<E> {}





/***** IMPLEMENTATION *****/
impl<L, C, P, S, PA, DA> Srv<L, C, P, S, PA, DA>
where
    L: 'static + AuditLogger + Send + Sync + Clone,
    C: 'static + ReasonerConnector<L> + Send + Sync,
    P: 'static + PolicyDataAccess + Send + Sync,
    S: 'static + StateResolver + Send + Sync,
    PA: 'static + AuthResolver + Send + Sync,
    DA: 'static + AuthResolver + Send + Sync,
    C::Context: Send + Sync + Debug + Serialize,
{
    // POST /v1/deliberation/execute-task
    async fn handle_execute_task_request(
        auth_ctx: AuthContext,
        this: Arc<Self>,
        body: ExecuteTaskRequest,
    ) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::reject::Rejection> {
        info!("Handling exec-task request");
        let ExecuteTaskRequest { use_case, workflow, task_id } = body;
        let verdict_reference: String = uuid::Uuid::new_v4().into();

        // First, resolve the task ID in the workflow to the ProgramCounter ID needed for `task_id` below (and before we pass it by ownership to be converted)
        debug!("Compiling WIR workflow to Checker Workflow...");
        let task_pc: String = task_id.resolved(&workflow.table).to_string();

        // Read the body's workflow as a Checker Workflow
        let workflow: Workflow = match Workflow::try_from(workflow) {
            Ok(workflow) => workflow,
            Err(err) => {
                return Ok(warp::reply::with_status(warp::reply::json(&err.to_string()), warp::hyper::StatusCode::BAD_REQUEST));
            },
        };
        // Get the task ID based on the request's target ID
        let task_id = format!("{}-{}-task", workflow.id, task_pc);
        debug!("Considering task '{}' in workflow '{}'", task_id, workflow.id);

        debug!("Retrieving state...");
        let state = match this.stateresolver.get_state(use_case).await {
            Ok(state) => state,
            Err(err) => {
                error!("Could not retrieve state: {err} | request id: {verdict_reference}");
                return Err(warp::reject::custom(RejectableError(err)));
            },
        };
        debug!(
            "Got state with {} datasets, {} functions, {} locations and {} users",
            state.datasets.len(),
            state.functions.len(),
            state.locations.len(),
            state.users.len()
        );

        let verdict_reference: String = uuid::Uuid::new_v4().into();
        debug!("Generated verdict_reference: {}", verdict_reference);

        debug!("Retrieving active policy...");

        let policy: Policy = match get_active_policy(&this.logger, &verdict_reference, &this.policystore).await? {
            Ok(policy) => policy,
            Err(err) => return Ok(err),
        };
        // let policy = this.policystore.get_active().await.unwrap();
        debug!("Got policy with {} bodies", policy.content.len());

        this.logger
            .log_exec_task_request(&verdict_reference, &auth_ctx, policy.version.version.unwrap(), &state, &workflow, &task_id)
            .await
            .map_err(|err| {
                debug!("Could not log exec task request to audit log : {:?} | request id: {}", err, verdict_reference);
                warp::reject::custom(err)
            })?;

        debug!("Consulting reasoner connector...");

        match this
            .reasonerconn
            .execute_task(SessionedConnectorAuditLogger::new(verdict_reference.clone(), this.logger.clone()), policy, state, workflow, task_id)
            .await
        {
            Ok(v) => {
                let resp: Verdict;
                if !v.success {
                    resp = Verdict::Deny(DeliberationDenyResponse {
                        shared: TaskExecResponse { verdict_reference: verdict_reference.clone() },
                        reasons_for_denial: Some(v.errors),
                    });
                } else {
                    resp = Verdict::Allow(DeliberationAllowResponse {
                        shared:    TaskExecResponse { verdict_reference: verdict_reference.clone() },
                        // TODO implement signature
                        signature: "signature".into(),
                    })
                }

                this.logger.log_verdict(&verdict_reference, &resp).await.map_err(|err| {
                    debug!("Could not log execute task verdict to audit log : {:?} | request id: {}", err, verdict_reference);
                    warp::reject::custom(err)
                })?;

                Ok(warp::reply::with_status(warp::reply::json(&resp), warp::hyper::StatusCode::OK))
            },
            Err(err) => Ok(warp::reply::with_status(warp::reply::json(&format!("{}", err)), warp::hyper::StatusCode::OK)),
        }
    }

    // POST /v1/deliberation/access-data
    async fn handle_access_data_request(
        auth_ctx: AuthContext,
        this: Arc<Self>,
        body: AccessDataRequest,
    ) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::reject::Rejection> {
        info!("Handling access-data request");
        let AccessDataRequest { use_case, workflow, data_id, task_id } = body;

        let verdict_reference: String = uuid::Uuid::new_v4().into();

        debug!("Compiling WIR workflow to Checker Workflow...");

        // Read the body's workflow as a Checker Workflow
        // NOTE: We need the deep clone of the table here to ensure that the `Arc` in the WIR is not duplicated. Nice design, Tim!
        let table: SymTable = (*workflow.table).clone();
        let workflow: Workflow = match Workflow::try_from(workflow) {
            Ok(workflow) => workflow,
            Err(err) => {
                return Ok(warp::reply::with_status(warp::reply::json(&err.trace().to_string()), warp::hyper::StatusCode::BAD_REQUEST));
            },
        };

        debug!("Retrieving state...");
        let state = match this.stateresolver.get_state(use_case).await {
            Ok(state) => state,
            Err(err) => {
                error!("Could not retrieve state: {err} | request id: {verdict_reference}");
                return Err(warp::reject::custom(RejectableError(err)));
            },
        };
        debug!(
            "Got state with {} datasets, {} functions, {} locations and {} users",
            state.datasets.len(),
            state.functions.len(),
            state.locations.len(),
            state.users.len()
        );

        debug!("Retrieving active policy...");
        let policy = match get_active_policy(&this.logger, &verdict_reference, &this.policystore).await? {
            Ok(policy) => policy,
            Err(err) => return Ok(err),
        };
        debug!("Got policy with {} bodies", policy.content.len());

        let task_id: Option<String> = match task_id {
            Some(task_id) => {
                // First, resolve the task ID in the workflow to the ProgramCounter ID needed for `task_id` below (and before we pass it by ownership to be converted)
                let task_pc: String = task_id.resolved(&table).to_string();

                // Get the task ID based on the request's target ID
                let task_id = format!("{}-{}-task", workflow.id, task_pc);
                debug!("Considering task '{}' in workflow '{}'", task_id, workflow.id);
                Some(task_id)
            },
            None => None,
        };

        debug!("Retrieving active policy...");
        let policy = match this.policystore.get_active().await {
            Ok(p) => p,
            Err(_) => {
                let resp = Verdict::Deny(DeliberationDenyResponse {
                    shared: DataAccessResponse { verdict_reference: verdict_reference.clone() },
                    reasons_for_denial: vec![].into(),
                });

                this.logger.log_data_access_request(&verdict_reference, &auth_ctx, -1, &state, &workflow, &data_id, &task_id).await.map_err(
                    |err| {
                        debug!("Could not log data access request to audit log : {:?} | request id: {}", err, verdict_reference);
                        warp::reject::custom(err)
                    },
                )?;

                this.logger.log_verdict(&verdict_reference, &resp).await.map_err(|err| {
                    debug!("Could not log data access verdict to audit log : {:?} | request id: {}", err, verdict_reference);
                    warp::reject::custom(err)
                })?;

                return Ok(warp::reply::with_status(warp::reply::json(&resp), warp::hyper::StatusCode::OK));
            },
        };
        debug!("Got policy with {} bodies", policy.content.len());

        this.logger
            .log_data_access_request(&verdict_reference, &auth_ctx, policy.version.version.unwrap(), &state, &workflow, &data_id, &task_id)
            .await
            .map_err(|err| {
                debug!("Could not log data access request to audit log : {:?} | request id: {}", err, verdict_reference);
                warp::reject::custom(err)
            })?;

        debug!("Consulting reasoner connector...");

        match this
            .reasonerconn
            .access_data_request(
                SessionedConnectorAuditLogger::new(verdict_reference.clone(), this.logger.clone()),
                policy,
                state,
                workflow,
                data_id,
                task_id,
            )
            .await
        {
            Ok(v) => {
                let resp: Verdict;
                if !v.success {
                    resp = Verdict::Deny(DeliberationDenyResponse {
                        shared: DataAccessResponse { verdict_reference: verdict_reference.clone() },
                        reasons_for_denial: Some(v.errors),
                    });
                } else {
                    resp = Verdict::Allow(DeliberationAllowResponse {
                        shared:    DataAccessResponse { verdict_reference: verdict_reference.clone() },
                        // TODO implement signature
                        signature: "signature".into(),
                    })
                }

                this.logger.log_verdict(&verdict_reference, &resp).await.map_err(|err| {
                    debug!("Could not log data access verdict to audit log : {:?} | request id: {}", err, verdict_reference);
                    warp::reject::custom(err)
                })?;

                Ok(warp::reply::with_status(warp::reply::json(&resp), warp::hyper::StatusCode::OK))
            },
            Err(err) => Ok(warp::reply::with_status(warp::reply::json(&format!("{}", err)), warp::hyper::StatusCode::OK)),
        }
    }

    // POST /v1/deliberation/validate-workflow
    async fn handle_validate_workflow_request(
        auth_ctx: AuthContext,
        this: Arc<Self>,
        body: WorkflowValidationRequest,
    ) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::reject::Rejection> {
        info!("Handling validate request");
        let WorkflowValidationRequest { use_case, workflow } = body;

        let verdict_reference: String = uuid::Uuid::new_v4().into();

        debug!("Compiling WIR workflow to Checker Workflow...");
        // Read the body's workflow as a Checker Workflow
        let workflow: Workflow = match Workflow::try_from(workflow) {
            Ok(workflow) => workflow,
            Err(err) => {
                return Ok(warp::reply::with_status(warp::reply::json(&err.to_string()), warp::hyper::StatusCode::BAD_REQUEST));
            },
        };

        debug!("Retrieving state...");
        let state = match this.stateresolver.get_state(use_case).await {
            Ok(state) => state,
            Err(err) => {
                error!("Could not retrieve state: {err} | request id: {verdict_reference}");
                return Err(warp::reject::custom(RejectableError(err)));
            },
        };
        debug!(
            "Got state with {} datasets, {} functions, {} locations and {} users",
            state.datasets.len(),
            state.functions.len(),
            state.locations.len(),
            state.users.len()
        );

        let verdict_reference: String = uuid::Uuid::new_v4().into();
        debug!("Generated verdict_reference: {}", verdict_reference);

        debug!("Retrieving active policy...");
        let policy = match get_active_policy(&this.logger, &verdict_reference, &this.policystore).await? {
            Ok(policy) => policy,
            Err(err) => return Ok(err),
        };
        debug!("Got policy with {} bodies", policy.content.len());
        debug!("Policy version: {:?}", policy.version.version);
        this.logger.log_validate_workflow_request(&verdict_reference, &auth_ctx, policy.version.version.unwrap(), &state, &workflow).await.map_err(
            |err| {
                debug!("Could not log validate workflow request to audit log : {:?} | request id: {}", err, verdict_reference);
                warp::reject::custom(err)
            },
        )?;

        debug!("Consulting reasoner connector...");

        match this
            .reasonerconn
            .workflow_validation_request(SessionedConnectorAuditLogger::new(verdict_reference.clone(), this.logger.clone()), policy, state, workflow)
            .await
        {
            Ok(v) => {
                let resp: Verdict;
                if !v.success {
                    resp = Verdict::Deny(DeliberationDenyResponse {
                        shared: WorkflowValidationResponse { verdict_reference: verdict_reference.clone() },
                        reasons_for_denial: Some(v.errors),
                    });
                } else {
                    resp = Verdict::Allow(DeliberationAllowResponse {
                        shared:    WorkflowValidationResponse { verdict_reference: verdict_reference.clone() },
                        // TODO implement signature
                        signature: "signature".into(),
                    })
                }

                this.logger.log_verdict(&verdict_reference, &resp).await.map_err(|err| {
                    debug!("Could not log workflow validation verdict to audit log : {:?} | request id: {}", err, verdict_reference);
                    warp::reject::custom(err)
                })?;

                Ok(warp::reply::with_status(warp::reply::json(&resp), warp::hyper::StatusCode::OK))
            },
            Err(err) => Ok(warp::reply::with_status(warp::reply::json(&format!("{}", err)), warp::hyper::StatusCode::OK)),
        }
    }

    pub fn deliberation_handlers(this: Arc<Self>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let exec_task = warp::post()
            .and(warp::path!("execute-task"))
            .and(Self::with_deliberation_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and(warp::body::json())
            .and_then(Self::handle_execute_task_request);

        let access_data = warp::post()
            .and(warp::path!("access-data"))
            .and(Self::with_deliberation_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and(warp::body::json())
            .and_then(Self::handle_access_data_request);

        let execute_workflow = warp::post()
            .and(warp::path!("execute-workflow"))
            .and(Self::with_deliberation_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and(warp::body::json())
            .and_then(Self::handle_validate_workflow_request);

        warp::path("v1").and(warp::path("deliberation")).and(exec_task.or(access_data).or(execute_workflow))
    }

    pub fn with_deliberation_api_auth(this: Arc<Self>) -> impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone {
        Self::with_self(this.clone()).and(warp::header::headers_cloned()).and_then(|this: Arc<Self>, headers| async move {
            match this.dauthresolver.authenticate(headers).await {
                Ok(v) => Ok(v),
                Err(err) => Err(warp::reject::custom(err)),
            }
        })
    }
}
