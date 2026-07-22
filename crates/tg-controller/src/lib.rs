use std::collections::BTreeSet;

use tg_contracts::{Permission, RouteDecision, SessionRequest, SessionState};
use tg_policy::{evaluate_permissions, PermissionDecision, PolicyContext};
use tg_router::{select_route, AvailableResources, RouteManifest};
use tg_session::{SessionError, SessionMachine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSession {
    pub machine: SessionMachine,
    pub route: RouteDecision,
    pub permissions: PermissionDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOutcome {
    Ready(PreparedSession),
    RouteBlocked(RouteDecision),
    PermissionBlocked {
        route: RouteDecision,
        permissions: PermissionDecision,
    },
}

pub fn prepare_session(
    request: &SessionRequest,
    routes: &[RouteManifest],
    resources: &AvailableResources,
    policy: &PolicyContext,
    engine_requested_permissions: &BTreeSet<Permission>,
    human_approved_permissions: &BTreeSet<Permission>,
) -> Result<PlanOutcome, ControllerError> {
    let mut machine = SessionMachine::default();
    machine.transition(SessionState::Detected)?;
    machine.transition(SessionState::IntakeLocked)?;
    machine.transition(SessionState::RouteProposed)?;

    let route = select_route(request, routes, resources);
    if !route.approved {
        machine.transition(SessionState::Failed)?;
        return Ok(PlanOutcome::RouteBlocked(route));
    }

    machine.transition(SessionState::AwaitingAuthorization)?;
    let permissions = evaluate_permissions(
        policy,
        engine_requested_permissions,
        &route.granted_permissions,
        human_approved_permissions,
    );

    if !permissions.approved {
        machine.transition(SessionState::Failed)?;
        return Ok(PlanOutcome::PermissionBlocked { route, permissions });
    }

    machine.transition(SessionState::Preparing)?;
    Ok(PlanOutcome::Ready(PreparedSession {
        machine,
        route,
        permissions,
    }))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ControllerError {
    #[error(transparent)]
    Session(#[from] SessionError),
}
