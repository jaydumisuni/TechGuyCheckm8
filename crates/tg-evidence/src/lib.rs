use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{EvidenceClass, EvidenceRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRequirement {
    pub requirement_id: String,
    pub stage_id: String,
    pub class: EvidenceClass,
    pub minimum_valid_records: usize,
    pub disallowed_sources: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalProofDecision {
    pub passed: bool,
    pub satisfied: BTreeMap<String, Vec<String>>,
    pub missing: Vec<String>,
    pub blockers: Vec<String>,
}

pub fn evaluate_final_proof(
    requirements: &[ProofRequirement],
    evidence: &[EvidenceRecord],
) -> FinalProofDecision {
    let mut satisfied = BTreeMap::new();
    let mut missing = Vec::new();
    let mut blockers = Vec::new();

    for record in evidence {
        if !record.contradicts.is_empty() {
            blockers.push(format!(
                "evidence {} declares unresolved contradictions",
                record.evidence_id
            ));
        }
        if record.valid && record.source.trim().is_empty() {
            blockers.push(format!(
                "evidence {} is marked valid without a source",
                record.evidence_id
            ));
        }
    }

    for requirement in requirements {
        let matching: Vec<_> = evidence
            .iter()
            .filter(|record| {
                record.valid
                    && record.stage_id == requirement.stage_id
                    && record.class == requirement.class
                    && !requirement.disallowed_sources.contains(&record.source)
            })
            .collect();

        if matching.len() < requirement.minimum_valid_records {
            missing.push(format!(
                "{} requires {} valid record(s), found {}",
                requirement.requirement_id,
                requirement.minimum_valid_records,
                matching.len()
            ));
            continue;
        }

        let unique_sources: BTreeSet<_> = matching
            .iter()
            .map(|record| record.source.clone())
            .collect();
        if unique_sources.len() < requirement.minimum_valid_records {
            missing.push(format!(
                "{} requires {} independent source(s), found {}",
                requirement.requirement_id,
                requirement.minimum_valid_records,
                unique_sources.len()
            ));
            continue;
        }

        satisfied.insert(
            requirement.requirement_id.clone(),
            matching
                .iter()
                .map(|record| record.evidence_id.to_string())
                .collect(),
        );
    }

    FinalProofDecision {
        passed: missing.is_empty() && blockers.is_empty(),
        satisfied,
        missing,
        blockers,
    }
}
