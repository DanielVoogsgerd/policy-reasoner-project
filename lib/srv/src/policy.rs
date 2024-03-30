use std::fmt::Debug;
use std::sync::Arc;

use audit_logger::AuditLogger;
use auth_resolver::{AuthContext, AuthResolver};
use policy::{Context, PolicyDataAccess, PolicyDataError};
use problem_details::ProblemDetails;
use reasonerconn::ReasonerConnector;
use serde::Serialize;
use state_resolver::StateResolver;
use warp::Filter;

use crate::problem::Problem;
use crate::{models, Srv};

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
    // GET specific version
    // GET /v1/policies/:version
    // out:
    // - 200 Policy
    // - 404

    async fn handle_get_policy_version(_auth_ctx: AuthContext, version: i64, this: Arc<Self>) -> Result<warp::reply::Json, warp::reject::Rejection> {
        match this.policystore.get_version(version).await {
            Ok(v) => Ok(warp::reply::json(&v)),
            Err(err) => match err {
                PolicyDataError::NotFound => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::NOT_FOUND);
                    Err(warp::reject::custom(Problem(p)))
                },
                PolicyDataError::GeneralError(msg) => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(msg);
                    Err(warp::reject::custom(Problem(p)))
                },
            },
        }
    }

    // List policy's versions
    // GET /v1/policies
    // out:
    // - 200 Vec<PolicyVersionDescription>

    async fn handle_get_all_policies(_auth_ctx: AuthContext, this: Arc<Self>) -> Result<warp::reply::Json, warp::reject::Rejection> {
        match this.policystore.get_versions().await {
            Ok(v) => Ok(warp::reply::json(&v)),
            Err(err) => match err {
                PolicyDataError::NotFound => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::NOT_FOUND);
                    Err(warp::reject::custom(Problem(p)))
                },
                PolicyDataError::GeneralError(msg) => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(msg);
                    Err(warp::reject::custom(Problem(p)))
                },
            },
        }
    }

    // Create new version of policy
    // POST /v1/policies
    // in: Policy
    // out:
    //  - 201 Policy. version in body
    //  - 400 problem+json

    async fn handle_add_policy(
        auth_ctx: AuthContext,
        this: Arc<Self>,
        body: models::AddPolicyPostModel,
    ) -> Result<warp::reply::Json, warp::reject::Rejection> {
        let t: Arc<Self> = this.clone();
        let mut model = body.to_domain();
        model.version.reasoner_connector_context = C::hash();
        match this
            .policystore
            .add_version(model, Context { initiator: auth_ctx.initiator.clone() }, |policy| async move {
                t.logger.log_add_policy_request::<C>(&auth_ctx, &policy).await.map_err(|err| match err {
                    audit_logger::Error::CouldNotDeliver(err) => PolicyDataError::GeneralError(err),
                })
            })
            .await
        {
            Ok(policy) => Ok(warp::reply::json(&policy)),
            Err(err) => match err {
                PolicyDataError::NotFound => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::NOT_FOUND);
                    Err(warp::reject::custom(Problem(p)))
                },
                PolicyDataError::GeneralError(msg) => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(msg);
                    Err(warp::reject::custom(Problem(p)))
                },
            },
        }
    }

    // Show active policy
    // GET /v1/policies/active
    // out: 200 {version: string}

    async fn handle_get_active_policy(_auth_ctx: AuthContext, this: Arc<Self>) -> Result<warp::reply::Json, warp::reject::Rejection> {
        match this.policystore.get_active().await {
            Ok(v) => Ok(warp::reply::json(&v)),
            Err(err) => match err {
                PolicyDataError::NotFound => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::NOT_FOUND).with_detail("No version currently active");
                    Err(warp::reject::custom(Problem(p)))
                },
                PolicyDataError::GeneralError(msg) => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(msg);
                    Err(warp::reject::custom(Problem(p)))
                },
            },
        }
    }

    // Set active policy
    // PUT /v1/policies/active
    // in: {version: string}
    // out:
    //  200 {version: string}
    //  400 problem+json

    async fn handle_set_active_policy(
        auth_ctx: AuthContext,
        this: Arc<Self>,
        body: models::SetVersionPostModel,
    ) -> Result<warp::reply::Json, warp::reject::Rejection> {
        // Reject activation of policy with invalid base defs
        let conn_hash = C::hash();
        match this.policystore.get_version(body.version).await {
            Ok(policy) => {
                if policy.version.reasoner_connector_context != conn_hash {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(format!(
                        "Cannot activate policy which has a different base policy than current the reasoners connector's base. Policy base defs \
                         hash is '{}' and connector's base defs hash is '{}'",
                        policy.version.reasoner_connector_context, conn_hash
                    ));
                    return Err(warp::reject::custom(Problem(p)));
                }
            },
            Err(_) => {},
        }

        let t = this.clone();
        match this
            .policystore
            .set_active(body.version, Context { initiator: auth_ctx.initiator.clone() }, |policy| async move {
                t.logger.log_set_active_version_policy(&auth_ctx, &policy).await.map_err(|err| match err {
                    audit_logger::Error::CouldNotDeliver(err) => PolicyDataError::GeneralError(err),
                })
            })
            .await
        {
            Ok(policy) => Ok(warp::reply::json(&policy)),
            Err(err) => match err {
                PolicyDataError::NotFound => {
                    let p = ProblemDetails::new()
                        .with_status(warp::http::StatusCode::BAD_REQUEST)
                        .with_detail(format!("Invalid version: {}", body.version));
                    Err(warp::reject::custom(Problem(p)))
                },
                PolicyDataError::GeneralError(msg) => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(msg);
                    Err(warp::reject::custom(Problem(p)))
                },
            },
        }
    }

    // Set active policy
    // DELETE /v1/policies/active
    // out:
    //  200
    //  400 problem+json

    async fn handle_deactivate_policy(auth_ctx: AuthContext, this: Arc<Self>) -> Result<warp::reply::Json, warp::reject::Rejection> {
        let t = this.clone();
        match this
            .policystore
            .deactivate_policy(Context { initiator: auth_ctx.initiator.clone() }, || async move {
                t.logger.log_deactivate_policy(&auth_ctx).await.map_err(|err| match err {
                    audit_logger::Error::CouldNotDeliver(err) => PolicyDataError::GeneralError(err),
                })
            })
            .await
        {
            Ok(policy) => Ok(warp::reply::json(&policy)),
            Err(err) => match err {
                PolicyDataError::NotFound => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail("No active version to deactivate");
                    Err(warp::reject::custom(Problem(p)))
                },
                PolicyDataError::GeneralError(msg) => {
                    let p = ProblemDetails::new().with_status(warp::http::StatusCode::BAD_REQUEST).with_detail(msg);
                    Err(warp::reject::custom(Problem(p)))
                },
            },
        }
    }

    pub fn policy_handlers(this: Arc<Self>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let add_version = warp::post()
            .and(warp::path::end())
            .and(Self::with_policy_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and(warp::body::json())
            .and_then(Self::handle_add_policy);

        let get_version = warp::get()
            .and(Self::with_policy_api_auth(this.clone()))
            .and(warp::path!(i64))
            .and(Self::with_self(this.clone()))
            .and_then(Self::handle_get_policy_version);

        let get_all = warp::get()
            .and(warp::path::end())
            .and(Self::with_policy_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and_then(Self::handle_get_all_policies);

        let get_active = warp::get()
            .and(warp::path!("active"))
            .and(Self::with_policy_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and_then(Self::handle_get_active_policy);

        let set_active = warp::put()
            .and(warp::path!("active"))
            .and(Self::with_policy_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and(warp::body::json())
            .and_then(Self::handle_set_active_policy);

        let deactivate = warp::delete()
            .and(warp::path!("active"))
            .and(Self::with_policy_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and_then(Self::handle_deactivate_policy);

        warp::path("v1")
            .and(warp::path("management"))
            .and(warp::path("policies"))
            .and(get_version.or(get_all).or(get_active).or(set_active).or(add_version).or(deactivate))
    }

    fn with_policy_api_auth(this: Arc<Self>) -> impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone {
        Self::with_self(this.clone()).and(warp::header::headers_cloned()).and_then(|this: Arc<Self>, headers| async move {
            println!("Headers: {:?}", headers);
            println!("Authenticating");

            match this.pauthresolver.authenticate(headers).await {
                Ok(v) => Ok(v),
                Err(err) => Err(warp::reject::custom(err)),
            }
        })
    }
}
