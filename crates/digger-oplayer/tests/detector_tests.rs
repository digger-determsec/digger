use digger_oplayer::detector::detect_unverified_attestation;
use digger_oplayer::parser::parse_op_program;

fn read_fixture(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    assert!(path.exists(), "fixture must exist: {:?}", path);
    std::fs::read_to_string(&path).unwrap()
}

#[test]
fn positive_fires_unverified_attestation() {
    let src = read_fixture("positive/handler.ts");
    let prog = parse_op_program(&src);
    let violations = detect_unverified_attestation(&prog);

    assert!(
        !violations.is_empty(),
        "positive fixture must produce at least 1 violation"
    );
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_kind, "UnverifiedAttestation");
    assert!(!violations[0].suppressed);
    assert!(violations[0].id.starts_with("op:"));
}

#[test]
fn benign_sibling_produces_zero_findings() {
    let src = read_fixture("benign/handler.ts");
    let prog = parse_op_program(&src);
    let violations = detect_unverified_attestation(&prog);

    assert!(
        violations.is_empty(),
        "benign fixture must produce 0 violations, got: {:?}",
        violations
    );
}

#[test]
fn flip_proof_deleting_verify_makes_benign_fire() {
    // Prove the benign assertion is load-bearing: if we remove the
    // verify() call from the benign source, the detector fires.
    let src = read_fixture("benign/handler.ts");
    let broken = src.replace("const attested = verify(price);", "// verify removed");
    let prog = parse_op_program(&broken);
    let violations = detect_unverified_attestation(&prog);

    assert!(
        !violations.is_empty(),
        "benign with verify removed must produce violations (flip proof)"
    );
    assert_eq!(violations[0].violation_kind, "UnverifiedAttestation");
}
