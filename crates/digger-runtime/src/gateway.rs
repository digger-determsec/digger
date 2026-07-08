use std::collections::BTreeMap;
use std::sync::Arc;

use digger_evidence::{canonicalize, sha256_hex, EvidenceStore, VerifyResult};

use crate::approvals::{ApprovalService, ApprovalToken};
use crate::audit::{create_audit_event, AuditStore};
use crate::connectors::{Connector, ConnectorError, ConnectorInput, ConnectorOutput};
use crate::credentials::CredentialBroker;
use crate::policy::{Pdp, Policy};
use crate::types::{ActionRequest, Decision, PolicyDecision};

pub struct ActionGateway {
    pub(crate) pdp: Pdp,
    pub(crate) evidence_store: Arc<dyn EvidenceStore>,
    pub(crate) audit_store: Arc<dyn AuditStore>,
    pub(crate) approval_service: Arc<ApprovalService>,
    credential_broker: Arc<CredentialBroker>,
    connectors: BTreeMap<String, Arc<dyn Connector>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub decision: Decision,
    pub connector_output: Option<ConnectorOutput>,
    pub approval_id: Option<String>,
    pub response_hash: Option<String>,
}

use serde::{Deserialize, Serialize};

impl ActionGateway {
    pub fn new(
        policy: Policy,
        evidence_store: Arc<dyn EvidenceStore>,
        audit_store: Arc<dyn AuditStore>,
        approval_service: Arc<ApprovalService>,
        credential_broker: Arc<CredentialBroker>,
        connectors: BTreeMap<String, Arc<dyn Connector>>,
    ) -> Self {
        Self {
            pdp: Pdp::new(policy),
            evidence_store,
            audit_store,
            approval_service,
            credential_broker,
            connectors,
        }
    }

    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        let request_hash = compute_request_hash(request);

        // Step 1: Validate request schema
        if request.action_id.is_empty() || request.tenant_id.is_empty() {
            let decision = self.empty_decision("Missing required fields (action_id or tenant_id)");
            self.write_audit(request, &decision, &request_hash, None, None);
            return decision;
        }

        // Step 2: Load + verify evidence bundle
        let verify_result = match self.evidence_store.load_bundle(&request.evidence_bundle_id) {
            Ok(bundle) => digger_evidence::verify_bundle(&bundle),
            Err(e) => VerifyResult {
                valid: false,
                expected_hash: String::new(),
                actual_hash: String::new(),
                details: vec![format!("Bundle load failed: {}", e)],
            },
        };

        if !verify_result.valid {
            let decision = self.make_decision(
                Decision::Deny,
                vec![
                    "Evidence bundle verification failed â€” possible tampering".into(),
                    verify_result.details.join("; "),
                ],
                &verify_result.actual_hash,
            );
            self.write_audit(request, &decision, &request_hash, None, None);
            return decision;
        }

        let bundle_hash = verify_result.actual_hash.clone();

        // Step 3: Tenant check
        let bundle = match self.evidence_store.load_bundle(&request.evidence_bundle_id) {
            Ok(b) => b,
            Err(e) => {
                let decision = self.make_decision(
                    Decision::Deny,
                    vec![format!("Bundle reload failed: {}", e)],
                    &bundle_hash,
                );
                self.write_audit(request, &decision, &request_hash, None, None);
                return decision;
            }
        };

        if bundle.tenant_id != request.tenant_id {
            let decision = self.make_decision(
                Decision::Deny,
                vec!["Cross-tenant access".into()],
                &bundle_hash,
            );
            self.write_audit(request, &decision, &request_hash, None, None);
            return decision;
        }

        // Step 4: finding_ids validation
        if request.finding_ids.is_empty() {
            let decision = self.make_decision(
                Decision::Deny,
                vec!["finding_ids must be non-empty".into()],
                &bundle_hash,
            );
            self.write_audit(request, &decision, &request_hash, None, None);
            return decision;
        }

        let bundle_finding_ids: Vec<&str> = bundle
            .findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect();
        for fid in &request.finding_ids {
            if !bundle_finding_ids.contains(&fid.as_str()) {
                let decision = self.make_decision(
                    Decision::Deny,
                    vec![format!("finding_id '{}' not in bundle", fid)],
                    &bundle_hash,
                );
                self.write_audit(request, &decision, &request_hash, None, None);
                return decision;
            }
        }

        // Step 5: Evaluate policy
        let decision = self.pdp.evaluate(request, &bundle_hash);

        // Step 6: Audit the decision
        self.write_audit(request, &decision, &request_hash, None, None);

        decision
    }

    pub fn execute_allow(
        &self,
        request: &ActionRequest,
    ) -> Result<ExecutionOutput, ConnectorError> {
        // Pre-check: must not be a ScopedPause (requires approval, not auto-execute)
        if request.action_type == crate::types::ActionType::ScopedPause {
            return Err("ScopedPause requires approval \u{2014} cannot auto-execute"
                .to_string()
                .into());
        }

        let connector_name = action_type_to_connector(&request.action_type);
        let connector = self
            .connectors
            .get(&connector_name)
            .ok_or_else(|| format!("No connector for {}", connector_name))?;

        let idempotency_key = compute_idempotency_key(request);
        let credential = self.credential_broker.issue_scoped(
            &request.tenant_id,
            &request.action_type.to_string(),
            &connector_name,
        );

        let input = ConnectorInput {
            action_id: request.action_id.clone(),
            tenant_id: request.tenant_id.clone(),
            action_type: request.action_type.to_string(),
            payload: request.payload.clone(),
            credential_handle: credential.handle_id.clone(),
        };

        let output = connector.execute(&input, &idempotency_key)?;

        let response_hash =
            sha256_hex(canonicalize(&serde_json::to_value(&output).unwrap_or_default()).as_bytes());

        let request_hash = compute_request_hash(request);
        let decision = self.pdp.evaluate(
            &ActionRequest {
                action_id: request.action_id.clone(),
                tenant_id: request.tenant_id.clone(),
                actor: request.actor.clone(),
                action_type: request.action_type.clone(),
                target: request.target.clone(),
                payload: request.payload.clone(),
                evidence_bundle_id: request.evidence_bundle_id.clone(),
                finding_ids: request.finding_ids.clone(),
                justification: request.justification.clone(),
                requested_at: request.requested_at.clone(),
            },
            "",
        );
        self.write_audit(
            request,
            &decision,
            &request_hash,
            Some(&response_hash),
            None,
        );

        Ok(ExecutionOutput {
            decision: Decision::Allow,
            connector_output: Some(output),
            approval_id: None,
            response_hash: Some(response_hash),
        })
    }

    pub fn create_approval_request(
        &self,
        request: &ActionRequest,
    ) -> Result<crate::approvals::ApprovalRequest, ConnectorError> {
        let scope = vec![action_type_to_connector(&request.action_type)];
        let approval = self.approval_service.create_approval(
            &request.action_id,
            &request.actor.user_id,
            scope,
        );
        Ok(approval)
    }

    pub fn execute_approved(
        &self,
        approval_token: &ApprovalToken,
        request: &ActionRequest,
    ) -> Result<ExecutionOutput, ConnectorError> {
        // Validate token
        self.approval_service
            .consume(&approval_token.approval_id, &approval_token.nonce)
            .map_err(|e| format!("Approval rejected: {}", e))?;

        // TOCTOU re-check: verify bundle still valid + policy still permits
        let verify_result = match self.evidence_store.load_bundle(&request.evidence_bundle_id) {
            Ok(bundle) => digger_evidence::verify_bundle(&bundle),
            Err(e) => VerifyResult {
                valid: false,
                expected_hash: String::new(),
                actual_hash: String::new(),
                details: vec![format!("Bundle load failed: {}", e)],
            },
        };

        if !verify_result.valid {
            let decision = self.make_decision(
                Decision::Deny,
                vec!["TOCTOU: bundle no longer valid".into()],
                &verify_result.actual_hash,
            );
            self.write_audit(
                request,
                &decision,
                &compute_request_hash(request),
                None,
                None,
            );
            return Err("Bundle verification failed at execution time"
                .to_string()
                .into());
        }

        // Re-run policy
        let decision = self.pdp.evaluate(request, &verify_result.actual_hash);
        // For actions that went through the approval flow (RequireApproval),
        // the approval itself is the authorization. The TOCTOU re-check
        // verifies the bundle is still valid (done above), but the policy
        // decision may still be RequireApproval â€” that's expected and
        // doesn't mean the action should be re-denied.
        if decision.decision == Decision::Deny {
            self.write_audit(
                request,
                &decision,
                &compute_request_hash(request),
                None,
                None,
            );
            return Err(format!("TOCTOU: policy changed to {:?}", decision.decision).into());
        }

        // Execute via connector
        let connector_name = action_type_to_connector(&request.action_type);
        let connector = self
            .connectors
            .get(&connector_name)
            .ok_or_else(|| format!("No connector for {}", connector_name))?;

        let idempotency_key = compute_idempotency_key(request);
        let credential = self.credential_broker.issue_scoped(
            &request.tenant_id,
            &request.action_type.to_string(),
            &connector_name,
        );

        let input = ConnectorInput {
            action_id: request.action_id.clone(),
            tenant_id: request.tenant_id.clone(),
            action_type: request.action_type.to_string(),
            payload: request.payload.clone(),
            credential_handle: credential.handle_id.clone(),
        };

        let output = connector.execute(&input, &idempotency_key)?;

        let response_hash =
            sha256_hex(canonicalize(&serde_json::to_value(&output).unwrap_or_default()).as_bytes());
        let request_hash = compute_request_hash(request);

        // The approval IS the authorization â€” record Allow in the audit log.
        let approved_decision = PolicyDecision {
            decision: Decision::Allow,
            decision_reasons: vec!["Approved via ScopedPause approval flow".into()],
            effective_scopes: decision.effective_scopes,
            policy_version_hash: decision.policy_version_hash,
            bundle_hash: decision.bundle_hash,
            evaluated_at: decision.evaluated_at,
        };
        self.write_audit(
            request,
            &approved_decision,
            &request_hash,
            Some(&response_hash),
            Some(&approval_token.approval_id),
        );

        Ok(ExecutionOutput {
            decision: Decision::Allow,
            connector_output: Some(output),
            approval_id: Some(approval_token.approval_id.clone()),
            response_hash: Some(response_hash),
        })
    }

    fn empty_decision(&self, reason: &str) -> PolicyDecision {
        self.make_decision(Decision::Deny, vec![reason.into()], "")
    }

    fn make_decision(
        &self,
        decision: Decision,
        reasons: Vec<String>,
        bundle_hash: &str,
    ) -> PolicyDecision {
        let now = now_secs();
        PolicyDecision {
            decision,
            decision_reasons: reasons,
            effective_scopes: Vec::new(),
            policy_version_hash: self
                .pdp
                .evaluate(
                    &ActionRequest {
                        action_id: String::new(),
                        tenant_id: String::new(),
                        actor: crate::types::Actor {
                            user_id: String::new(),
                            agent_id: None,
                            session_id: None,
                        },
                        action_type: crate::types::ActionType::GithubCreatePr,
                        target: crate::types::ActionTarget::Repo {
                            repo: String::new(),
                            branch: String::new(),
                        },
                        payload: serde_json::json!(null),
                        evidence_bundle_id: String::new(),
                        finding_ids: Vec::new(),
                        justification: String::new(),
                        requested_at: String::new(),
                    },
                    "",
                )
                .policy_version_hash,
            bundle_hash: bundle_hash.to_string(),
            evaluated_at: format!("{}", now),
        }
    }

    fn write_audit(
        &self,
        request: &ActionRequest,
        decision: &PolicyDecision,
        request_hash: &str,
        response_hash: Option<&str>,
        approval_id: Option<&str>,
    ) {
        let prev_hash = self.audit_store.last_event_hash(&request.tenant_id);
        let mut event = create_audit_event(
            &request.action_id,
            &request.tenant_id,
            decision,
            request_hash,
            prev_hash.as_deref(),
        );
        event.response_hash = response_hash.map(|s| s.to_string());
        event.approval_id = approval_id.map(|s| s.to_string());
        let _ = self.audit_store.append(&event);
    }
}

pub fn compute_request_hash(request: &ActionRequest) -> String {
    let canonical = canonicalize(&serde_json::to_value(request).unwrap_or_default());
    sha256_hex(canonical.as_bytes())
}

pub fn compute_idempotency_key(request: &ActionRequest) -> String {
    let key = format!(
        "{}|{}|{}",
        request.tenant_id, request.action_id, request.evidence_bundle_id
    );
    sha256_hex(key.as_bytes())
}

fn action_type_to_connector(action_type: &crate::types::ActionType) -> String {
    match action_type {
        crate::types::ActionType::GithubCreatePr => "github.create_pr".into(),
        crate::types::ActionType::SlackPostMessage => "slack.post_message".into(),
        crate::types::ActionType::CiTriggerWorkflow => "ci.trigger_workflow".into(),
        crate::types::ActionType::ScopedPause => "scoped.pause.dry_run".into(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
