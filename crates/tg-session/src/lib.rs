use tg_contracts::SessionState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMachine {
    state: SessionState,
    transition_count: u64,
}

impl Default for SessionMachine {
    fn default() -> Self {
        Self {
            state: SessionState::Idle,
            transition_count: 0,
        }
    }
}

impl SessionMachine {
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    pub fn transition(&mut self, next: SessionState) -> Result<Transition, SessionError> {
        if self.state == next {
            return Err(SessionError::NoOpTransition(next));
        }
        if !can_transition(&self.state, &next) {
            return Err(SessionError::IllegalTransition {
                from: self.state.clone(),
                to: next,
            });
        }

        let previous = self.state.clone();
        self.state = next.clone();
        self.transition_count += 1;

        Ok(Transition {
            sequence: self.transition_count,
            from: previous,
            to: next,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub sequence: u64,
    pub from: SessionState,
    pub to: SessionState,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session is already in state {0:?}")]
    NoOpTransition(SessionState),
    #[error("illegal session transition from {from:?} to {to:?}")]
    IllegalTransition {
        from: SessionState,
        to: SessionState,
    },
}

pub fn can_transition(from: &SessionState, to: &SessionState) -> bool {
    use SessionState::*;

    match from {
        Idle => matches!(to, Detected | Cancelled),
        Detected => matches!(to, IntakeLocked | Failed | Cancelled),
        IntakeLocked => matches!(to, RouteProposed | Failed | Cancelled),
        RouteProposed => matches!(to, AwaitingAuthorization | Failed | Cancelled),
        AwaitingAuthorization => matches!(to, Preparing | Failed | Cancelled),
        Preparing => matches!(
            to,
            WaitingForDeviceMode | ExecutingStage | RecoveryRequired | Failed | Cancelled
        ),
        WaitingForDeviceMode => {
            matches!(to, ExecutingStage | RecoveryRequired | Failed | Cancelled)
        }
        ExecutingStage => matches!(
            to,
            StageVerification | RecoveryRequired | Failed | Cancelled
        ),
        StageVerification => matches!(
            to,
            Preparing
                | WaitingForDeviceMode
                | ExecutingStage
                | Rebooting
                | FinalVerification
                | RecoveryRequired
                | Failed
                | Cancelled
        ),
        RecoveryRequired => matches!(
            to,
            Preparing | WaitingForDeviceMode | FinalVerification | Failed | Cancelled
        ),
        Rebooting => matches!(
            to,
            WaitingForDeviceMode | FinalVerification | RecoveryRequired | Failed | Cancelled
        ),
        FinalVerification => matches!(
            to,
            CompletedVerified | CompletedUnverified | RecoveryRequired | Failed | Cancelled
        ),
        CompletedVerified | CompletedUnverified | Failed | Cancelled => false,
    }
}
