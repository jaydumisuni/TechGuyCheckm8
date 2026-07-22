use std::collections::BTreeSet;

use tg_contracts::{
    DeviceMode, Maturity, OperationKind, Permission, RouteDecision, SessionRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteManifest {
    pub route_id: String,
    pub engine_ids: Vec<String>,
    pub maturity: Maturity,
    pub operations: BTreeSet<OperationKind>,
    pub product_types: BTreeSet<String>,
    pub chips: BTreeSet<String>,
    pub firmware_versions: BTreeSet<String>,
    pub host_platforms: BTreeSet<String>,
    pub allowed_entry_modes: BTreeSet<DeviceMode>,
    pub required_permissions: BTreeSet<Permission>,
    pub hardware_requirements: BTreeSet<String>,
    pub exact_hardware_proof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableResources {
    pub hardware: BTreeSet<String>,
}

pub fn select_route(
    request: &SessionRequest,
    routes: &[RouteManifest],
    resources: &AvailableResources,
) -> RouteDecision {
    let mut matching = Vec::new();
    let mut near_match_reasons = Vec::new();

    for route in routes {
        let mut reasons = Vec::new();
        if !route.operations.contains(&request.operation) {
            reasons.push("operation");
        }
        if !route.product_types.contains(&request.device.product_type) {
            reasons.push("product_type");
        }
        if !route.chips.is_empty()
            && request
                .device
                .chip
                .as_ref()
                .map_or(true, |chip| !route.chips.contains(chip))
        {
            reasons.push("chip");
        }
        if !route.allowed_entry_modes.contains(&request.current_mode) {
            reasons.push("entry_mode");
        }
        if !route.host_platforms.contains(&request.host.os) {
            reasons.push("host");
        }
        if !route.firmware_versions.is_empty()
            && request.firmware.as_ref().map_or(true, |firmware| {
                !route.firmware_versions.contains(&firmware.version)
            })
        {
            reasons.push("firmware");
        }
        if !route.hardware_requirements.is_subset(&resources.hardware) {
            reasons.push("hardware");
        }
        if request.policy_profile == "stable"
            && (route.maturity != Maturity::Stable || !route.exact_hardware_proof)
        {
            reasons.push("stable_maturity_or_proof");
        }

        if reasons.is_empty() {
            matching.push(route);
        } else if reasons.len() <= 2 {
            near_match_reasons.push(format!("{}: {}", route.route_id, reasons.join(",")));
        }
    }

    match matching.as_slice() {
        [route] => RouteDecision {
            approved: true,
            route_id: Some(route.route_id.clone()),
            engine_ids: route.engine_ids.clone(),
            granted_permissions: route.required_permissions.clone(),
            unmet_requirements: Vec::new(),
            blockers: Vec::new(),
            rationale_codes: vec!["exact_route_match".to_owned()],
        },
        [] => {
            let detail = if near_match_reasons.is_empty() {
                "No approved route matches the complete session constraints".to_owned()
            } else {
                format!(
                    "No approved route matches; near matches: {}",
                    near_match_reasons.join("; ")
                )
            };
            RouteDecision::blocked("no_exact_route", detail)
        }
        routes => RouteDecision::blocked(
            "ambiguous_route",
            format!(
                "Multiple routes match exactly: {}",
                routes
                    .iter()
                    .map(|route| route.route_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    }
}
