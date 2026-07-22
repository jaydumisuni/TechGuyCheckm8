use tg_contracts::SessionState;
use tg_session::{can_transition, SessionError, SessionMachine};

#[test]
fn verified_happy_path_is_explicit() {
    let mut machine = SessionMachine::default();
    for state in [
        SessionState::Detected,
        SessionState::IntakeLocked,
        SessionState::RouteProposed,
        SessionState::AwaitingAuthorization,
        SessionState::Preparing,
        SessionState::WaitingForDeviceMode,
        SessionState::ExecutingStage,
        SessionState::StageVerification,
        SessionState::Rebooting,
        SessionState::FinalVerification,
        SessionState::CompletedVerified,
    ] {
        machine
            .transition(state)
            .expect("transition should be legal");
    }

    assert_eq!(machine.state(), &SessionState::CompletedVerified);
    assert_eq!(machine.transition_count(), 11);
}

#[test]
fn success_cannot_be_reached_directly_from_execution() {
    let mut machine = SessionMachine::default();
    machine.transition(SessionState::Detected).unwrap();
    machine.transition(SessionState::IntakeLocked).unwrap();
    machine.transition(SessionState::RouteProposed).unwrap();
    machine
        .transition(SessionState::AwaitingAuthorization)
        .unwrap();
    machine.transition(SessionState::Preparing).unwrap();
    machine.transition(SessionState::ExecutingStage).unwrap();

    assert_eq!(
        machine.transition(SessionState::CompletedVerified),
        Err(SessionError::IllegalTransition {
            from: SessionState::ExecutingStage,
            to: SessionState::CompletedVerified,
        })
    );
}

#[test]
fn terminal_states_are_terminal() {
    for terminal in [
        SessionState::CompletedVerified,
        SessionState::CompletedUnverified,
        SessionState::Failed,
        SessionState::Cancelled,
    ] {
        assert!(!can_transition(&terminal, &SessionState::Preparing));
        assert!(!can_transition(&terminal, &SessionState::Idle));
    }
}

#[test]
fn recovery_must_return_through_an_allowed_checkpoint() {
    assert!(can_transition(
        &SessionState::RecoveryRequired,
        &SessionState::Preparing
    ));
    assert!(can_transition(
        &SessionState::RecoveryRequired,
        &SessionState::FinalVerification
    ));
    assert!(!can_transition(
        &SessionState::RecoveryRequired,
        &SessionState::CompletedVerified
    ));
}
