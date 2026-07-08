use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "digger",
    version,
    about = "Digger — evidence-gated AI-assisted blockchain security infrastructure",
    long_about = "Digger is deterministic at the evidence layer and agentic/LLM-assisted by design.\nAI can suspect. Digger proves. Model output is untrusted until grounded through evidence gates."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Disable all network access (hard offline mode)
    #[arg(long, global = true)]
    pub no_network: bool,

    /// Auto-approve network egress prompts (for CI/non-interactive use)
    #[arg(long, global = true)]
    pub assume_yes: bool,

    /// Allow network egress to a specific host (can be repeated)
    #[arg(long = "allow-egress", global = true, action = clap::ArgAction::Append)]
    pub allow_egress: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a smart contract for security hypotheses (not confirmed vulnerabilities)
    Scan {
        /// Path to the source file
        path: String,

        /// Language: solidity, anchor, rust, auto
        #[arg(long, default_value = "auto")]
        lang: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Export SecurityIntelligenceOutput to file
        #[arg(long)]
        surface_json: Option<String>,

        /// Enable corpus evidence attachment (opt-in, default OFF).
        /// Pass a directory path containing corpus JSON files.
        #[arg(long)]
        with_corpus: Option<String>,
    },

    /// Generate a detailed triage report (JSON + Markdown) — not a full security audit
    Report {
        /// Path to the source file
        path: String,

        /// Language: solidity, anchor, rust, auto
        #[arg(long, default_value = "auto")]
        lang: String,

        /// Output directory for report files
        #[arg(long, default_value = ".")]
        output_dir: String,
    },

    /// Derive exploit hypotheses from source
    Hypothesis {
        /// Path to the source file
        path: String,

        /// Language: solidity, anchor, rust, auto
        #[arg(long, default_value = "auto")]
        lang: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Export HypothesisResult to file
        #[arg(long)]
        output: Option<String>,
    },

    /// Run benchmark against corpus
    Benchmark {
        /// Path to corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,

        /// Output report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Validate Digger installation and test corpus
    Validate {},

    /// Run knowledge coverage dashboard analytics
    Dashboard {
        /// Path to knowledge corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Export dashboard report to file
        #[arg(long)]
        output: Option<String>,
    },

    /// Show version information
    Version,

    /// Scan a local EVM repository for fuzzing maturity signals (static inspection only)
    FuzzMaturity {
        /// Local repository or project path to scan
        #[arg(long)]
        path: String,

        /// Target chain (only "evm" supported currently)
        #[arg(long, default_value = "evm")]
        chain: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Parse a fuzz invariant failure artifact into a structured fuzz evidence report
    FuzzEvidence {
        /// Tool that produced the artifact: foundry, echidna, medusa (EVM) or crucible (Solana)
        #[arg(long, default_value = "foundry")]
        tool: String,

        /// Target chain: evm (for foundry/echidna/medusa) or solana (for crucible)
        #[arg(long, default_value = "evm")]
        chain: String,

        /// Path to the artifact/log file
        #[arg(long)]
        artifact: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Read-only repository intelligence scan for agent-consumable output
    RepoIntelligence {
        /// Local repository path to scan
        #[arg(long)]
        path: String,

        /// Target chain: evm or solana
        #[arg(long, default_value = "evm")]
        chain: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Scan a verified smart contract for security hypotheses (not confirmed vulnerabilities)
    ScanLive {
        /// Contract address on a block explorer (0x...)
        #[arg(long, conflicts_with_all = &["source_file", "use_stdin", "repo"])]
        address: Option<String>,

        /// Chain name (ethereum, arbitrum, optimism, polygon, base, sepolia)
        #[arg(long, requires = "address")]
        chain: Option<String>,

        /// Raw Solidity source file to analyze locally
        #[arg(long, conflicts_with_all = &["address", "use_stdin", "repo"])]
        source_file: Option<String>,

        /// Read Solidity source from stdin
        #[arg(long, conflicts_with_all = &["address", "source_file", "repo"])]
        use_stdin: bool,

        /// Local Foundry repo path to scan (detects foundry.toml, resolves imports)
        #[arg(long, conflicts_with_all = &["address", "source_file", "use_stdin"])]
        repo: Option<String>,

        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        format: String,

        /// Emit a typed ScanContext JSON file for MCP consumption
        #[arg(long)]
        emit_scan_context: Option<String>,

        /// Implementation address for proxy contracts (used with --address)
        #[arg(long)]
        impl_address: Option<String>,
    },

    /// CI scan mode: run on a checked-out repo, emit SARIF + PR comment
    Ci {
        /// Local repo path (auto-detected if in a git repo)
        #[arg(long)]
        repo: Option<String>,

        /// Diff range for scoping (e.g. main..HEAD or base..head)
        #[arg(long)]
        diff: Option<String>,

        /// Output format: sarif (default), pr-comment, text, json
        #[arg(long, default_value = "sarif")]
        format: String,

        /// Fail CI if any finding at or above this severity (high, medium, low)
        #[arg(long)]
        fail_on: Option<String>,
    },

    /// Synthesize complete exploit chains from evidence (Gen 3)
    Synthesize {
        /// Source file to analyze
        path: String,

        /// Language (auto, solidity, anchor, rust)
        #[arg(long, default_value = "auto")]
        lang: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Export report to file
        #[arg(long)]
        output: Option<String>,
    },

    /// Local-first audit triage for EVM and Solana security researchers
    AuditTriage {
        /// Local repository or project path to scan
        #[arg(long, conflicts_with = "address")]
        path: Option<String>,

        /// Contract address on a block explorer (e.g. 0x...) for live triage
        #[arg(long, conflicts_with = "path")]
        address: Option<String>,

        /// Implementation address for proxy contracts (used with --address)
        #[arg(long, requires = "address")]
        impl_address: Option<String>,

        /// Target chain: ethereum, arbitrum, optimism, polygon, base, solana
        #[arg(long, default_value = "evm")]
        chain: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,

        /// Include fuzz maturity scan
        #[arg(long)]
        include_fuzz_maturity: bool,

        /// Path to fuzz artifact for evidence parsing
        #[arg(long)]
        fuzz_artifact: Option<String>,

        /// Filter candidate hypotheses and proof tasks to production files only
        #[arg(long)]
        exclude_tests: bool,
    },

    /// Decode calldata / instruction and explain what the transaction does
    ExplainIntent {
        /// Raw calldata hex (EVM): 0x...
        #[arg(long, conflicts_with_all = ["tx", "eip712", "sol_tx"])]
        calldata: Option<String>,

        /// Path to a JSON file representing a transaction (EVM)
        #[arg(long, conflicts_with_all = ["calldata", "eip712", "sol_tx"])]
        tx: Option<String>,

        /// Path to an EIP-712 typed data JSON file (EVM)
        #[arg(long, conflicts_with_all = ["calldata", "tx", "sol_tx"])]
        eip712: Option<String>,

        /// Solana transaction as base64 or JSON (Solana)
        #[arg(long, conflicts_with_all = ["calldata", "tx", "eip712"])]
        sol_tx: Option<String>,

        /// Target chain: evm or solana
        #[arg(long, default_value = "evm")]
        chain: String,

        /// Target contract/program address (for mismatch detection)
        #[arg(long)]
        to: Option<String>,

        /// Address the UI claims the transaction targets (for mismatch detection)
        #[arg(long)]
        expected: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Create a validated hypothesis from a triage packet
    HypothesisCreate {
        /// Path to triage packet JSON
        #[arg(long)]
        from_triage: String,

        /// Optional claim file
        #[arg(long)]
        claim: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },

    /// Generate a validated proof task from a hypothesis
    ProofTaskGenerate {
        /// Path to hypothesis JSON
        #[arg(long)]
        from_hypothesis: String,

        /// Path to triage packet JSON
        #[arg(long)]
        triage: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },

    /// Verify a claim against triage evidence
    VerifyClaim {
        /// Path to triage packet JSON
        #[arg(long)]
        triage: String,

        /// Path to claim markdown file
        #[arg(long)]
        claim: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },

    /// Generate a report draft from verification results
    ReportDraft {
        /// Path to triage packet JSON
        #[arg(long)]
        triage: String,

        /// Path to verification JSON
        #[arg(long)]
        verification: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },

    /// Create an evidence package bundling the full chain
    EvidencePackage {
        /// Path to triage packet JSON
        #[arg(long)]
        triage: String,

        /// Path to verification JSON
        #[arg(long)]
        verification: String,

        /// Path to report draft JSON
        #[arg(long)]
        report_draft: Option<String>,

        /// Path to hypothesis JSON (optional, for event accumulation)
        #[arg(long)]
        hypothesis: Option<String>,

        /// Path to proof task JSON (optional, for event accumulation)
        #[arg(long)]
        proof_task: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },

    /// Manage knowledge ingestion
    Ingest {
        /// Subcommand: run, validate, status
        #[command(subcommand)]
        command: IngestCommand,
    },
    /// Generate a beginner-friendly Markdown report from an AuditTriagePacket JSON
    RenderReport {
        /// Path to the AuditTriagePacket JSON file produced by `digger audit-triage --json`
        #[arg(long)]
        from: String,

        /// Maximum number of findings to include in the main report (default: all)
        #[arg(long)]
        top: Option<usize>,

        /// Minimum confidence tier to include: confirmed, high, medium, experimental
        #[arg(long)]
        min_confidence: Option<String>,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IngestCommand {
    /// Run ingestion pipeline
    Run {
        /// Source filter (optional)
        #[arg(long)]
        source: Option<String>,

        /// Corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,
    },
    /// Validate existing corpus
    Validate {
        /// Corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,
    },
    /// Show ingestion status
    Status {
        /// Corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,
    },
    /// Show ingestion health dashboard
    Dashboard {
        /// Corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,
    },
    /// Run regression checks
    Regression {
        /// Corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,
        /// Source filter (optional)
        #[arg(long)]
        source: Option<String>,
    },
    /// Corpus intelligence — gap analysis and recommendations
    Intel {
        /// Corpus directory
        #[arg(long, default_value = "corpus")]
        corpus: String,
    },
}

pub fn run() {
    let cli = Cli::parse();
    let mut egress =
        digger_egress::EgressPolicy::new(cli.no_network, cli.assume_yes, cli.allow_egress.clone());
    digger_egress::init_global(egress.clone());

    match cli.command {
        Commands::Scan {
            path,
            lang,
            json,
            surface_json,
            with_corpus,
        } => {
            if !std::path::Path::new(&path).exists() {
                eprintln!("Error: File not found: {}", path);
                std::process::exit(1);
            }

            let lang = if lang == "auto" {
                detect_language(&path)
            } else {
                lang
            };

            crate::pipeline::run(path, lang, json, surface_json, with_corpus.as_deref());
        }
        Commands::Report {
            path,
            lang,
            output_dir,
        } => {
            if !std::path::Path::new(&path).exists() {
                eprintln!("Error: File not found: {}", path);
                std::process::exit(1);
            }

            let lang = if lang == "auto" {
                detect_language(&path)
            } else {
                lang
            };

            crate::report_cmd::run(path, lang, output_dir);
        }
        Commands::Hypothesis {
            path,
            lang,
            json,
            output,
        } => {
            if !std::path::Path::new(&path).exists() {
                eprintln!("Error: File not found: {}", path);
                std::process::exit(1);
            }

            let lang = if lang == "auto" {
                detect_language(&path)
            } else {
                lang
            };

            crate::hypothesis_cmd::run(&path, &lang, json, output.as_deref());
        }
        Commands::Benchmark { corpus, json } => {
            if !std::path::Path::new(&corpus).exists() {
                eprintln!("Error: Corpus directory not found: {}", corpus);
                std::process::exit(1);
            }
            crate::benchmark::run(&corpus, json);
        }
        Commands::Validate {} => {
            crate::validate::run();
        }
        Commands::Dashboard {
            corpus,
            json,
            output,
        } => {
            crate::dashboard_cmd::run(&corpus, json, output);
        }
        Commands::ScanLive {
            address,
            chain,
            source_file,
            use_stdin,
            repo,
            format,
            emit_scan_context,
            impl_address,
        } => {
            crate::scan_live::run_scan(
                address,
                chain,
                source_file,
                use_stdin,
                repo,
                format == "json",
                impl_address,
                emit_scan_context,
            );
        }
        Commands::Ci {
            repo,
            diff,
            format,
            fail_on,
        } => {
            crate::ci_mode::run_ci(repo, diff, format, fail_on);
        }
        Commands::Version => {
            println!("Digger v{}", env!("CARGO_PKG_VERSION"));
            println!("Deterministic blockchain security research platform");
            println!();
            println!("Architecture:");
            println!("  Schema version: {}", digger_core::freeze::SCHEMA_VERSION);
            println!("  Phase 3 status: {}", digger_core::freeze::PHASE3_STATUS);
            println!();
            println!("Pipelines:");
            println!("  Gen 1: Parser → SystemIR → Graph analysis");
            println!("  Gen 2: Hypothesis engine (8-factor ranking, assumption validation)");
            println!("  Gen 3: Exploit synthesis → validation → execution preparation");
            println!("  Gen 4: Deterministic execution → differential analysis → confirmation");
            println!("  Eval:  Contest evaluation, replay, false positive/miss analysis");
            println!("  Ingest: 6 sources, incremental manifests, health dashboard");
            println!();
            println!("Languages: Solidity, Rust/Anchor");
            println!("Sources: Code4rena, Sherlock, DeFiLlama, DeFiHackLabs, SlowMist, GitHub Advisories");
            println!();
            println!("Commands:");
            println!("  scan       Analyze a smart contract file");
            println!("  report     Generate detailed triage report");
            println!("  hypothesis Generate hypotheses only");
            println!("  synthesize Synthesize full exploit chains (Gen 3)");
            println!("  benchmark  Run benchmark suite");
            println!("  dashboard  Knowledge dashboard");
            println!("  validate   System validation");
            println!("  ingest     Knowledge ingestion pipeline");
            println!("  version    Show this information");
            println!();
            println!("Evidence-gated, AI-assisted blockchain security. Models can suspect; Digger proves. is_finding stays false.");
        }
        Commands::FuzzMaturity { path, chain, json } => {
            crate::fuzz_maturity_cmd::run(&path, &chain, json);
        }
        Commands::FuzzEvidence {
            tool,
            chain,
            artifact,
            json,
        } => {
            crate::fuzz_evidence_cmd::run(&tool, &chain, &artifact, json);
        }
        Commands::RepoIntelligence { path, chain, json } => {
            crate::repo_intelligence_cmd::run(&path, &chain, json);
        }
        Commands::Synthesize {
            path,
            lang,
            json,
            output,
        } => {
            if !std::path::Path::new(&path).exists() {
                eprintln!("Error: File not found: {}", path);
                std::process::exit(1);
            }

            let lang = if lang == "auto" {
                detect_language(&path)
            } else {
                lang
            };

            crate::synthesize_cmd::run(path, lang, json, output);
        }
        Commands::AuditTriage {
            path,
            address,
            impl_address,
            chain,
            json,
            output,
            include_fuzz_maturity,
            fuzz_artifact,
            exclude_tests,
        } => {
            crate::audit_triage_cmd::run(
                path.as_deref(),
                address.as_deref(),
                impl_address.as_deref(),
                &chain,
                json,
                output.as_deref(),
                include_fuzz_maturity,
                fuzz_artifact.as_deref(),
                exclude_tests,
                &mut egress,
            );
        }
        Commands::ExplainIntent {
            calldata,
            tx: _tx,
            eip712: _eip712,
            sol_tx,
            chain,
            to,
            expected,
            json,
        } => {
            if chain == "evm" {
                if let Some(ref cd) = calldata {
                    let analysis = digger_intent_verifier::decode_evm_calldata(
                        cd,
                        to.as_deref(),
                        expected.as_deref(),
                    );
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&analysis).unwrap_or_default()
                        );
                    } else {
                        println!("Digger Intent Verifier — v{}", env!("CARGO_PKG_VERSION"));
                        println!("Chain: {}", analysis.chain);
                        println!("Risk: {:?}", analysis.risk_level);
                        println!();
                        for call in &analysis.calls {
                            println!("[{}] {}", call.selector, call.function_name);
                            println!("  Effect: {}", call.effect);
                            if !call.risk_flags.is_empty() {
                                println!("  Risk flags: {:?}", call.risk_flags);
                            }
                            if call.target_mismatch {
                                println!("  *** TARGET MISMATCH ***");
                            }
                            for arg in &call.decoded_args {
                                println!("  {}: {} ({})", arg.name, arg.value, arg.kind);
                            }
                            println!();
                        }
                        println!("{}", analysis.summary);
                        println!();
                        println!("is_finding: false");
                    }
                } else if let Some(ref path) = _tx {
                    let content = match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Error reading tx file: {e}");
                            std::process::exit(1);
                        }
                    };
                    let tx_json: serde_json::Value = match serde_json::from_str(&content) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error parsing tx JSON: {e}");
                            std::process::exit(1);
                        }
                    };
                    let analysis = digger_intent_verifier::decode_tx_json(
                        &tx_json,
                        to.as_deref(),
                        expected.as_deref(),
                    );
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&analysis).unwrap_or_default()
                        );
                    } else {
                        println!("Digger Intent Verifier — v{}", env!("CARGO_PKG_VERSION"));
                        println!("Chain: {}", analysis.chain);
                        println!("Risk: {:?}", analysis.risk_level);
                        println!();
                        for call in &analysis.calls {
                            println!("[{}] {}", call.selector, call.function_name);
                            println!("  Effect: {}", call.effect);
                            if !call.risk_flags.is_empty() {
                                println!("  Risk flags: {:?}", call.risk_flags);
                            }
                            if call.target_mismatch {
                                println!("  *** TARGET MISMATCH ***");
                            }
                            for arg in &call.decoded_args {
                                println!("  {}: {} ({})", arg.name, arg.value, arg.kind);
                            }
                            println!();
                        }
                        println!("{}", analysis.summary);
                        println!();
                        println!("is_finding: false");
                    }
                } else if let Some(ref path) = _eip712 {
                    let content = match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Error reading EIP-712 file: {e}");
                            std::process::exit(1);
                        }
                    };
                    let typed_data: serde_json::Value = match serde_json::from_str(&content) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error parsing EIP-712 JSON: {e}");
                            std::process::exit(1);
                        }
                    };
                    let analysis = digger_intent_verifier::decode_eip712(
                        &typed_data,
                        to.as_deref(),
                        expected.as_deref(),
                    );
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&analysis).unwrap_or_default()
                        );
                    } else {
                        println!("Digger Intent Verifier — v{}", env!("CARGO_PKG_VERSION"));
                        println!("Chain: {}", analysis.chain);
                        println!("Risk: {:?}", analysis.risk_level);
                        println!();
                        for call in &analysis.calls {
                            println!("[{}] {}", call.selector, call.function_name);
                            println!("  Effect: {}", call.effect);
                            if !call.risk_flags.is_empty() {
                                println!("  Risk flags: {:?}", call.risk_flags);
                            }
                            if call.target_mismatch {
                                println!("  *** TARGET MISMATCH ***");
                            }
                            for arg in &call.decoded_args {
                                println!("  {}: {} ({})", arg.name, arg.value, arg.kind);
                            }
                            println!();
                        }
                        println!("{}", analysis.summary);
                        println!();
                        println!("is_finding: false");
                    }
                } else {
                    eprintln!("Provide --calldata, --tx, or --eip712 for EVM");
                    std::process::exit(1);
                }
            } else if chain == "solana" {
                if let Some(ref sol_data) = sol_tx {
                    let analysis = if let Ok(v) =
                        serde_json::from_str::<serde_json::Value>(sol_data)
                    {
                        // Full transaction JSON: {"account_keys": [...], "instructions": [...]}
                        if v.get("account_keys").is_some() && v.get("instructions").is_some() {
                            digger_intent_verifier::decode_solana_transaction_json(
                                &v,
                                to.as_deref().or(expected.as_deref()),
                            )
                        } else if let Some(data_b64) = v.get("data").and_then(|d| d.as_str()) {
                            // Single instruction JSON: {"data": "base64..."}
                            let decoded = base64::Engine::decode(
                                &base64::engine::general_purpose::STANDARD,
                                data_b64,
                            )
                            .unwrap_or_default();
                            let program_id = v
                                .get("program_id")
                                .and_then(|p| p.as_str())
                                .unwrap_or("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
                            let call = digger_intent_verifier::decode_solana_instruction(
                                program_id,
                                &decoded,
                                to.as_deref().or(expected.as_deref()),
                            );
                            let mut a = digger_intent_verifier::IntentAnalysis::new(
                                "solana",
                                to.clone(),
                                expected.clone(),
                            );
                            a.add_call(call);
                            a.finalize_summary();
                            a
                        } else {
                            eprintln!("JSON must have {{\"account_keys\",\"instructions\"}} or {{\"data\":\"base64...\"}}");
                            std::process::exit(1);
                        }
                    } else if let Ok(bytes) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        sol_data.trim(),
                    ) {
                        let call = digger_intent_verifier::decode_solana_instruction(
                            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                            &bytes,
                            to.as_deref().or(expected.as_deref()),
                        );
                        let mut a = digger_intent_verifier::IntentAnalysis::new(
                            "solana",
                            to.clone(),
                            expected.clone(),
                        );
                        a.add_call(call);
                        a.finalize_summary();
                        a
                    } else {
                        eprintln!("--sol-tx must be base64 or JSON");
                        std::process::exit(1);
                    };
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&analysis).unwrap_or_default()
                        );
                    } else {
                        println!("Digger Intent Verifier — v{}", env!("CARGO_PKG_VERSION"));
                        println!("Chain: {}", analysis.chain);
                        println!("Risk: {:?}", analysis.risk_level);
                        println!();
                        for call in &analysis.calls {
                            println!("[{}] {}", call.selector, call.function_name);
                            println!("  Effect: {}", call.effect);
                            if !call.risk_flags.is_empty() {
                                println!("  Risk flags: {:?}", call.risk_flags);
                            }
                            if call.target_mismatch {
                                println!("  *** TARGET MISMATCH ***");
                            }
                            for arg in &call.decoded_args {
                                println!("  {}: {} ({})", arg.name, arg.value, arg.kind);
                            }
                            println!();
                        }
                        println!("{}", analysis.summary);
                        println!();
                        println!("is_finding: false");
                    }
                } else {
                    eprintln!("Provide --sol-tx for Solana");
                    std::process::exit(1);
                }
            } else {
                eprintln!("Unknown chain: {}", chain);
                std::process::exit(1);
            }
        }
        Commands::HypothesisCreate {
            from_triage,
            claim,
            json,
            output,
        } => {
            crate::hypothesis_cmd::create_from_triage(
                &from_triage,
                claim.as_deref(),
                json,
                output.as_deref(),
            );
        }
        Commands::ProofTaskGenerate {
            from_hypothesis,
            triage,
            json,
            output,
        } => {
            crate::proof_task_cmd::generate_from_hypothesis(
                &from_hypothesis,
                &triage,
                json,
                output.as_deref(),
            );
        }
        Commands::VerifyClaim {
            triage,
            claim,
            json,
            output,
        } => {
            crate::verify_claim_cmd::verify_claim(&triage, &claim, json, output.as_deref());
        }
        Commands::ReportDraft {
            triage,
            verification,
            json,
            output,
        } => {
            crate::report_draft_cmd::generate_report_draft(
                &triage,
                &verification,
                json,
                output.as_deref(),
            );
        }
        Commands::EvidencePackage {
            triage,
            verification,
            report_draft,
            hypothesis,
            proof_task,
            json,
            output,
        } => {
            crate::evidence_package_cmd::create_evidence_package(
                &triage,
                &verification,
                report_draft.as_deref(),
                hypothesis.as_deref(),
                proof_task.as_deref(),
                json,
                output.as_deref(),
            );
        }
        Commands::Ingest { command } => match command {
            IngestCommand::Run { source, corpus } => {
                let args = if let Some(s) = source {
                    vec!["--source".into(), s, "--corpus".into(), corpus]
                } else {
                    vec!["--corpus".into(), corpus]
                };
                digger_ingestion::cli::run("run", &args);
            }
            IngestCommand::Validate { corpus } => {
                let args = vec!["--corpus".into(), corpus];
                digger_ingestion::cli::run("validate", &args);
            }
            IngestCommand::Status { corpus } => {
                let args = vec!["--corpus".into(), corpus];
                digger_ingestion::cli::run("status", &args);
            }
            IngestCommand::Dashboard { corpus } => {
                let args = vec!["--corpus".to_string(), corpus];
                digger_ingestion::cli::run("dashboard", &args);
            }
            IngestCommand::Regression { corpus, source } => {
                let mut args = vec!["--corpus".to_string(), corpus];
                if let Some(source) = source {
                    args.push("--source".to_string());
                    args.push(source);
                }
                digger_ingestion::cli::run("regression", &args);
            }
            IngestCommand::Intel { corpus } => {
                let args = vec!["--corpus".to_string(), corpus];
                digger_ingestion::cli::run("intel", &args);
            }
        },
        Commands::RenderReport {
            from,
            top,
            min_confidence,
            output,
        } => {
            let input = match std::fs::read_to_string(&from) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error reading {}: {e}", from);
                    std::process::exit(1);
                }
            };
            let packet: serde_json::Value = match serde_json::from_str(&input) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing JSON: {e}");
                    std::process::exit(1);
                }
            };
            let mut findings: Vec<digger_report::ReportFinding> = Vec::new();
            if let Some(hyps) = packet["candidate_hypotheses"].as_array() {
                for h in hyps {
                    let rule_id = h
                        .get("rule_id")
                        .or_else(|| h.get("detector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let severity = h
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let confidence = h
                        .get("confidence")
                        .or_else(|| h.get("confidence_label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("experimental")
                        .to_string();
                    let component = h
                        .get("component")
                        .or_else(|| h.get("function_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let file = h
                        .get("file")
                        .or_else(|| h.get("path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let line_start = h
                        .get("line_start")
                        .or_else(|| h.get("line"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let line_end = h
                        .get("line_end")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(line_start as u64) as u32;
                    let description = h
                        .get("description")
                        .or_else(|| h.get("summary"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let finding_id = h
                        .get("finding_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&rule_id)
                        .to_string();
                    let evidence_lines: Vec<String> = h
                        .get("evidence_lines")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    findings.push(digger_report::ReportFinding {
                        finding_id,
                        rule_id,
                        severity,
                        confidence,
                        component,
                        file,
                        line_start,
                        line_end,
                        description,
                        evidence_lines,
                    });
                }
            }
            let report = digger_report::generate_report(&findings, top, min_confidence.as_deref());
            if let Some(out_path) = output {
                if let Err(e) = std::fs::write(&out_path, &report.markdown) {
                    eprintln!("Error writing output: {e}");
                    std::process::exit(1);
                }
                eprintln!(
                    "Written to {out_path} ({} findings, {} omitted)",
                    report.findings_count, report.omitted_count
                );
            } else {
                print!("{}", report.markdown);
            }
        }
    }
}

fn detect_language(path: &str) -> String {
    let p = std::path::Path::new(path);
    match p.extension().and_then(|e| e.to_str()) {
        Some("sol") => "solidity".into(),
        Some("rs") => {
            if let Ok(code) = std::fs::read_to_string(path) {
                if code.contains("#[program]")
                    || code.contains("#[account]")
                    || code.contains("anchor_lang")
                {
                    "anchor".into()
                } else {
                    "rust".into()
                }
            } else {
                "rust".into()
            }
        }
        _ => {
            eprintln!(
                "Error: Cannot detect language for '{}'. Use --lang flag.",
                path
            );
            std::process::exit(1);
        }
    }
}
