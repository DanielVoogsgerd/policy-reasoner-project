use std::fmt::Debug;
use std::sync::Arc;

use audit_logger::AuditLogger;
use auth_resolver::{AuthContext, AuthResolver};
use policy::PolicyDataAccess;
use reasonerconn::ReasonerConnector;
use serde::Serialize;
use state_resolver::StateResolver;
use warp::Filter;

use crate::Srv;

#[derive(Serialize)]
struct ConnectorContextViewModel<T> {
    context: T,
    hash:    String,
}

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
    // Get reasoner connector context
    // GET /v1/reasoner-connector-context
    // out:
    // 200

    async fn handle_reasoner_conn_ctx(_: AuthContext, _this: Arc<Self>) -> Result<warp::reply::Json, warp::reject::Rejection> {
        Ok(warp::reply::json(&ConnectorContextViewModel { context: Box::new(C::context()), hash: C::hash() }))
    }

    pub fn reasoner_connector_handlers(this: Arc<Self>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let get_context = warp::get()
            .and(warp::path!("management" / "reasoner-connector-context"))
            .and(Self::with_reasoner_connector_api_auth(this.clone()))
            .and(Self::with_self(this.clone()))
            .and_then(Self::handle_reasoner_conn_ctx);

        warp::path("v1").and(get_context)
    }

    fn with_reasoner_connector_api_auth(this: Arc<Self>) -> impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone {
        Self::with_self(this.clone()).and(warp::header::headers_cloned()).and_then(|this: Arc<Self>, headers| async move {
            match this.pauthresolver.authenticate(headers).await {
                Ok(v) => Ok(v),
                Err(err) => Err(warp::reject::custom(err)),
            }
        })
    }
}
