#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod edges;
pub mod effects;
pub mod enums;
pub mod function;
pub mod state;
pub mod system;
pub mod types;

pub use edges::*;
pub use effects::*;
pub use enums::*;
pub use function::*;
pub use state::*;
pub use system::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_ir_smoke_test() {
        let ir = SystemIR {
            program_id: "test".into(),
            language: Language::Solidity,
            functions: vec![],
            state: vec![],
            edges: vec![],
        };

        assert_eq!(ir.program_id, "test");
        assert_eq!(ir.language, Language::Solidity);
    }

    #[test]
    fn severity_serialization_round_trip() {
        let severities = vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for sev in &severities {
            let json = serde_json::to_string(sev).expect("serialize");
            let back: Severity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*sev, back);
        }
    }

    #[test]
    fn type_construction() {
        let ty = Type {
            name: "uint256".into(),
        };
        assert_eq!(ty.name, "uint256");
    }

    #[test]
    fn effects_construction() {
        let eff = Effects {
            state_mutation: true,
            external_call: false,
            authority_required: true,
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        };
        assert!(eff.state_mutation);
        assert!(!eff.external_call);
        assert!(eff.authority_required);
        assert!(!eff.value_transfer);

        let default_eff = Effects::default();
        assert!(!default_eff.state_mutation);
        assert!(!default_eff.external_call);
        assert!(!default_eff.authority_required);
        assert!(!default_eff.value_transfer);
    }

    #[test]
    fn function_construction() {
        let func = Function {
            id: "fn_0".into(),
            name: "transfer".into(),
            contract: String::new(),
            visibility: Visibility::Public,
            inputs: vec![Type {
                name: "address".into(),
            }],
            outputs: vec![],
            modifiers: vec!["onlyOwner".into()],
            effects: Effects {
                state_mutation: true,
                external_call: true,
                authority_required: true,
                value_transfer: true,
                has_arithmetic: false,
                has_temporal_guard: false,
                value_flow: None,
                has_unchecked_arithmetic: false,
                writes_caller_scoped_state: false,
                has_precision_loss_ordering: false,
            },
        };
        assert_eq!(func.name, "transfer");
        assert_eq!(func.visibility, Visibility::Public);
        assert_eq!(func.inputs.len(), 1);
        assert_eq!(func.modifiers.len(), 1);
    }

    #[test]
    fn state_variable_construction() {
        let sv = StateVariable {
            id: "sv_0".into(),
            name: "balances".into(),
            ty: "mapping(address => uint256)".into(),
            mutable: true,
        };
        assert_eq!(sv.name, "balances");
        assert!(sv.mutable);
    }

    #[test]
    fn edge_construction() {
        let call = Edge::Call(CallEdge {
            from: "fn_a".into(),
            to: "fn_b".into(),
        });
        let state = Edge::State(StateEdge {
            function: "fn_a".into(),
            state: "balances".into(),
            access: "write".into(),
        });
        let auth = Edge::Authority(AuthorityEdge {
            function: "fn_a".into(),
            authority_source: "msg_sender".into(),
            check_type: "enforced".into(),
        });
        let ext = Edge::External(ExternalCallEdge {
            function: "fn_a".into(),
            target: "Token".into(),
            risk_flags: vec!["external_call".into()],
        });

        match call {
            Edge::Call(e) => assert_eq!(e.from, "fn_a"),
            _ => panic!("expected Call variant"),
        }
        match state {
            Edge::State(e) => assert_eq!(e.access, "write"),
            _ => panic!("expected State variant"),
        }
        match auth {
            Edge::Authority(e) => assert_eq!(e.check_type, "enforced"),
            _ => panic!("expected Authority variant"),
        }
        match ext {
            Edge::External(e) => assert_eq!(e.risk_flags.len(), 1),
            _ => panic!("expected External variant"),
        }
    }

    #[test]
    fn display_severity() {
        assert_eq!(Severity::Info.to_string(), "INFO");
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn display_language() {
        assert_eq!(Language::Solidity.to_string(), "Solidity");
        assert_eq!(Language::Rust.to_string(), "Rust");
        assert_eq!(Language::Anchor.to_string(), "Anchor");
        assert_eq!(Language::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn display_call_kind() {
        assert_eq!(CallKind::External.to_string(), "External");
        assert_eq!(CallKind::CrossProgram.to_string(), "CrossProgram");
        assert_eq!(CallKind::Internal.to_string(), "Internal");
        assert_eq!(CallKind::Unknown.to_string(), "Unknown");
    }
}
