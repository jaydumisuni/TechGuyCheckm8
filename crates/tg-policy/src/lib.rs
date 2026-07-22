use std::collections::BTreeSet;

use tg_contracts::Permission;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyContext {
    pub profile: PolicyProfile,
    pub offline_required: bool,
    pub destructive_authorized: bool,
    pub recovery_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyProfile {
    Stable,
    Beta,
    Development,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecision {
    pub approved: bool,
    pub granted: BTreeSet<Permission>,
    pub missing_human_authorization: BTreeSet<Permission>,
    pub denied_by_policy: BTreeSet<Permission>,
    pub reasons: Vec<String>,
}

pub fn evaluate_permissions(
    context: &PolicyContext,
    engine_requested: &BTreeSet<Permission>,
    route_required: &BTreeSet<Permission>,
    human_approved: &BTreeSet<Permission>,
) -> PermissionDecision {
    let needed: BTreeSet<_> = engine_requested
        .intersection(route_required)
        .cloned()
        .collect();

    let missing_human_authorization: BTreeSet<_> =
        needed.difference(human_approved).cloned().collect();
    let mut denied_by_policy = BTreeSet::new();
    let mut reasons = Vec::new();

    for permission in &needed {
        if context.offline_required && permission == &Permission::NetworkApprovedSource {
            denied_by_policy.insert(permission.clone());
            reasons.push("offline session cannot grant approved-source network access".to_owned());
        }

        if is_destructive(permission)
            && (!context.destructive_authorized || !context.recovery_ready)
        {
            denied_by_policy.insert(permission.clone());
            reasons.push(format!(
                "destructive permission {permission:?} requires explicit authorization and recovery readiness"
            ));
        }

        if context.profile == PolicyProfile::Stable && is_development_only(permission) {
            denied_by_policy.insert(permission.clone());
            reasons.push(format!(
                "permission {permission:?} is not available in Stable policy"
            ));
        }
    }

    let granted: BTreeSet<_> = needed
        .difference(&missing_human_authorization)
        .filter(|permission| !denied_by_policy.contains(*permission))
        .cloned()
        .collect();

    let approved = missing_human_authorization.is_empty()
        && denied_by_policy.is_empty()
        && granted == needed;

    PermissionDecision {
        approved,
        granted,
        missing_human_authorization,
        denied_by_policy,
        reasons,
    }
}

fn is_destructive(permission: &Permission) -> bool {
    matches!(
        permission,
        Permission::DeviceErase
            | Permission::FilesystemMountReadwrite
            | Permission::FirmwarePatch
            | Permission::FirmwareRestore
            | Permission::SysCfgRestoreSameBoard
            | Permission::ActivationArtifactRestoreSameDevice
    )
}

fn is_development_only(permission: &Permission) -> bool {
    matches!(permission, Permission::PackActivate)
}
