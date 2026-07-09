//! Diagnostic: measure value_transfer across the 12-file Bancor subset.
//! Run with and without the fix to get before/after comparison.

use digger_graph::build_system_ir_with_language;
use digger_ir::Language;
use digger_parser::parse_program;

fn load_bancor_concatenated() -> String {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../digger-hypothesis/tests/fixtures/real-corpus/bancor/contracts"
    );
    let files = [
        "utility/Owned.sol",
        "NetworkSettings.sol",
        "ConversionPathFinder.sol",
        "bancorx/BancorX.sol",
        "converter/ConverterFactory.sol",
        "converter/ConverterRegistry.sol",
        "utility/interfaces/IOwned.sol",
        "INetworkSettings.sol",
        "IConversionPathFinder.sol",
        "converter/interfaces/IConverterFactory.sol",
        "converter/interfaces/IConverter.sol",
        "converter/interfaces/IConverterRegistry.sol",
    ];
    let mut source = String::new();
    for f in &files {
        let path = format!("{}/{}", base, f);
        if let Ok(content) = std::fs::read_to_string(&path) {
            if !source.is_empty() {
                source.push_str("\n\n");
            }
            source.push_str(&content);
        }
    }
    source
}

#[test]
fn measure_value_transfer_bancor_12file() {
    let source = load_bancor_concatenated();
    assert!(!source.is_empty(), "Failed to load Bancor sources");

    let raw_program = parse_program(&source, "solidity");
    let ir = build_system_ir_with_language(raw_program.clone(), Language::Solidity);

    // All value_transfer=true functions
    let vt_fns: Vec<&digger_ir::Function> = ir
        .functions
        .iter()
        .filter(|f| f.effects.value_transfer)
        .collect();

    eprintln!("=== value_transfer=true functions: {} ===", vt_fns.len());
    for f in &vt_fns {
        eprintln!("  - {}", f.name);
    }
    eprintln!("TOTAL value_transfer=true: {}", vt_fns.len());
}
