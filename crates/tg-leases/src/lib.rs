use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Session,
    Device,
    Usb,
    Serial,
    Arduino,
    Ssh,
    Vault,
    Pack,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceKey {
    pub kind: ResourceKind,
    pub stable_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseOwner {
    pub session_id: Uuid,
    pub worker_id: String,
    pub run_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease_id: Uuid,
    pub owner: LeaseOwner,
    pub resources: BTreeSet<ResourceKey>,
    pub expires_at_tick: u64,
}

#[derive(Debug, Clone, Default)]
pub struct LeaseManager {
    resources: BTreeMap<ResourceKey, LeaseGrant>,
}

impl LeaseManager {
    pub fn acquire(
        &mut self,
        resources: BTreeSet<ResourceKey>,
        owner: LeaseOwner,
        current_tick: u64,
        ttl_ticks: u64,
    ) -> Result<LeaseGrant, LeaseError> {
        if resources.is_empty() {
            return Err(LeaseError::EmptyResourceSet);
        }
        if ttl_ticks == 0 {
            return Err(LeaseError::InvalidTtl);
        }

        let conflicts: Vec<_> = resources
            .iter()
            .filter(|resource| self.resources.contains_key(*resource))
            .cloned()
            .collect();
        if !conflicts.is_empty() {
            return Err(LeaseError::ResourceConflict(conflicts));
        }

        let grant = LeaseGrant {
            lease_id: Uuid::new_v4(),
            owner,
            resources: resources.clone(),
            expires_at_tick: current_tick.saturating_add(ttl_ticks),
        };
        for resource in resources {
            self.resources.insert(resource, grant.clone());
        }
        Ok(grant)
    }

    pub fn renew(
        &mut self,
        lease_id: Uuid,
        owner: &LeaseOwner,
        current_tick: u64,
        ttl_ticks: u64,
    ) -> Result<LeaseGrant, LeaseError> {
        if ttl_ticks == 0 {
            return Err(LeaseError::InvalidTtl);
        }
        let existing = self
            .resources
            .values()
            .find(|grant| grant.lease_id == lease_id)
            .cloned()
            .ok_or(LeaseError::LeaseNotFound)?;
        if &existing.owner != owner {
            return Err(LeaseError::OwnerMismatch);
        }

        let mut renewed = existing;
        renewed.expires_at_tick = current_tick.saturating_add(ttl_ticks);
        for resource in &renewed.resources {
            self.resources.insert(resource.clone(), renewed.clone());
        }
        Ok(renewed)
    }

    pub fn release(
        &mut self,
        lease_id: Uuid,
        owner: &LeaseOwner,
    ) -> Result<LeaseGrant, LeaseError> {
        let grant = self
            .resources
            .values()
            .find(|grant| grant.lease_id == lease_id)
            .cloned()
            .ok_or(LeaseError::LeaseNotFound)?;
        if &grant.owner != owner {
            return Err(LeaseError::OwnerMismatch);
        }

        self.resources
            .retain(|_, active| active.lease_id != lease_id);
        Ok(grant)
    }

    pub fn expire(&mut self, current_tick: u64) -> Vec<LeaseGrant> {
        let mut expired_by_id = BTreeMap::new();
        for grant in self.resources.values() {
            if grant.expires_at_tick <= current_tick {
                expired_by_id.insert(grant.lease_id, grant.clone());
            }
        }
        let expired_ids: BTreeSet<_> = expired_by_id.keys().copied().collect();
        self.resources
            .retain(|_, grant| !expired_ids.contains(&grant.lease_id));
        expired_by_id.into_values().collect()
    }

    pub fn active_for(&self, resource: &ResourceKey) -> Option<&LeaseGrant> {
        self.resources.get(resource)
    }

    pub fn active_resource_count(&self) -> usize {
        self.resources.len()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("a lease must contain at least one resource")]
    EmptyResourceSet,
    #[error("lease TTL must be greater than zero")]
    InvalidTtl,
    #[error("one or more resources are already leased: {0:?}")]
    ResourceConflict(Vec<ResourceKey>),
    #[error("lease was not found")]
    LeaseNotFound,
    #[error("lease owner does not match the caller")]
    OwnerMismatch,
}
