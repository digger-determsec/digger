use crate::intent_model::{ArgValue, DecodedCall, IntentAnalysis};

/// SPL Token program IDs.
pub const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const SPL_TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const BPF_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

#[allow(dead_code)]
/// SPL Token instruction discriminators (data byte 0).
mod spl_disc {
    pub const INITIALIZE_MINT: u8 = 0;
    pub const INITIALIZE_ACCOUNT: u8 = 1;
    pub const INITIALIZE_MULTISIG: u8 = 2;
    pub const TRANSFER: u8 = 3;
    pub const APPROVE: u8 = 4;
    pub const REVOKE: u8 = 5;
    pub const SET_AUTHORITY: u8 = 6;
    pub const MINT_TO: u8 = 7;
    pub const BURN: u8 = 8;
    pub const CLOSE_ACCOUNT: u8 = 9;
    pub const FREEZE_ACCOUNT: u8 = 10;
    pub const THAW_ACCOUNT: u8 = 11;
    pub const TRANSFER_CHECKED: u8 = 12;
    pub const APPROVE_CHECKED: u8 = 13;
}

/// SPL Token AuthorityType (SetAuthority data byte 1).
fn authority_type_name(t: u8) -> &'static str {
    match t {
        0 => "MintTokens",
        1 => "FreezeAccount",
        2 => "AccountOwner",
        3 => "CloseAccount",
        _ => "Unknown",
    }
}

/// Decode a single SPL Token instruction.
///
/// `program_id` — base58 program ID.
/// `data` — instruction data bytes (discriminator + args).
/// `account_keys` — optional account keys array for resolving account indices.
/// `user_pubkey` — the user's pubkey for mismatch detection.
///
/// SPL Token instruction data layouts (from Solana docs):
/// - Transfer (3): data=[3, amount:u64]; accounts=[source, dest, authority]
/// - Approve (4): data=[4, amount:u64]; accounts=[source, delegate, owner]
/// - SetAuthority (6): data=[6, auth_type:u8, COption<pubkey>]; accounts=[target, current_auth]
///   COption: 0=None (renounce), 1=Some(pubkey)
/// - CloseAccount (9): data=[9]; accounts=[account, destination, authority]
pub fn decode_spl_instruction(
    _program_id: &str,
    data: &[u8],
    account_keys: Option<&[String]>,
    user_pubkey: Option<&str>,
) -> DecodedCall {
    let _disc_hex = format!("{:02x?}", data.first().copied().unwrap_or(0));
    let disc_short = if data.len() >= 8 {
        hex::encode(&data[..8])
    } else {
        hex::encode(data)
    };

    let Some(&disc) = data.first() else {
        return DecodedCall {
            selector: disc_short,
            function_name: "unknown".into(),
            decoded_args: vec![],
            effect: "Empty instruction data.".into(),
            risk_flags: vec![],
            target_mismatch: false,
        };
    };

    match disc {
        spl_disc::TRANSFER => decode_transfer(data, account_keys, user_pubkey, &disc_short),
        spl_disc::APPROVE => decode_approve(data, account_keys, user_pubkey, &disc_short),
        spl_disc::SET_AUTHORITY => {
            decode_set_authority(data, account_keys, user_pubkey, &disc_short)
        }
        spl_disc::CLOSE_ACCOUNT => {
            decode_close_account(data, account_keys, user_pubkey, &disc_short)
        }
        _ => DecodedCall {
            selector: disc_short,
            function_name: format!("spl_token_{disc}"),
            decoded_args: vec![],
            effect: format!("SPL Token instruction (disc={disc}). No specific handler."),
            risk_flags: vec![],
            target_mismatch: false,
        },
    }
}

fn decode_transfer(
    data: &[u8],
    account_keys: Option<&[String]>,
    user_pubkey: Option<&str>,
    disc_hex: &str,
) -> DecodedCall {
    // Transfer: data = [3, amount:u64 LE] = 9 bytes
    // accounts = [source, destination, authority]
    let mut risk_flags = Vec::new();
    let mut target_mismatch = false;

    let amount = if data.len() >= 9 {
        u64::from_le_bytes(data[1..9].try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    // Resolve destination from account_keys if available
    let destination = account_keys
        .and_then(|keys| {
            // Transfer accounts: [source, destination, authority]
            // destination is account index 1
            keys.get(1).cloned()
        })
        .unwrap_or_else(|| "unknown".into());

    let effect = if destination == "unknown" {
        format!("Transfers {amount} tokens (destination unknown — no account_keys provided).")
    } else {
        let mut e = format!("Transfers {amount} tokens to {destination}.");
        if let Some(user) = user_pubkey {
            if destination != *user {
                target_mismatch = true;
                risk_flags.push("transfer_to_non_user".into());
                e.push_str(&format!(
                    " WARNING: destination differs from expected {user}."
                ));
            }
        }
        e
    };

    let decoded_args = vec![
        ArgValue {
            name: "amount".into(),
            value: amount.to_string(),
            kind: "u64".into(),
        },
        ArgValue {
            name: "destination".into(),
            value: destination.clone(),
            kind: "pubkey".into(),
        },
    ];

    DecodedCall {
        selector: disc_hex.to_string(),
        function_name: "Transfer".into(),
        decoded_args,
        effect,
        risk_flags,
        target_mismatch,
    }
}

fn decode_approve(
    data: &[u8],
    account_keys: Option<&[String]>,
    user_pubkey: Option<&str>,
    disc_hex: &str,
) -> DecodedCall {
    // Approve: data = [4, amount:u64 LE] = 9 bytes
    // accounts = [source, delegate, owner]
    let amount = if data.len() >= 9 {
        u64::from_le_bytes(data[1..9].try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    let delegate = account_keys
        .and_then(|keys| keys.get(1).cloned())
        .unwrap_or_else(|| "unknown".into());

    let mut risk_flags = Vec::new();
    let mut target_mismatch = false;

    let effect = if delegate == "unknown" {
        format!("Grants {delegate} delegation of {amount} tokens (delegate unknown).")
    } else {
        let mut e = format!("Grants {delegate} delegation of {amount} tokens.");
        if let Some(user) = user_pubkey {
            if delegate != *user {
                target_mismatch = true;
                risk_flags.push("delegate_non_user".into());
                e.push_str(&format!(" WARNING: delegate differs from expected {user}."));
            }
        }
        e
    };

    DecodedCall {
        selector: disc_hex.to_string(),
        function_name: "Approve".into(),
        decoded_args: vec![
            ArgValue {
                name: "amount".into(),
                value: amount.to_string(),
                kind: "u64".into(),
            },
            ArgValue {
                name: "delegate".into(),
                value: delegate,
                kind: "pubkey".into(),
            },
        ],
        effect,
        risk_flags,
        target_mismatch,
    }
}

fn decode_set_authority(
    data: &[u8],
    _account_keys: Option<&[String]>,
    user_pubkey: Option<&str>,
    disc_hex: &str,
) -> DecodedCall {
    // SetAuthority: data = [6, auth_type:u8, option_tag:u8, (32 bytes if option_tag==1)]
    // accounts = [target_account, current_authority]
    let mut risk_flags = Vec::new();
    let mut target_mismatch = false;

    if data.len() < 2 {
        return DecodedCall {
            selector: disc_hex.to_string(),
            function_name: "SetAuthority".into(),
            decoded_args: vec![],
            effect: "SetAuthority with truncated data.".into(),
            risk_flags: vec![],
            target_mismatch: false,
        };
    }

    let auth_type_byte = data[1];
    let auth_type = authority_type_name(auth_type_byte);

    // COption<pubkey>: 0 = None (renounce), 1 = Some(pubkey)
    let is_renounce = data.len() < 3 || data[2] == 0;

    let new_auth = if !is_renounce && data.len() >= 34 {
        Some(bs58::encode(&data[3..35]).into_string())
    } else {
        None
    };

    let effect = if is_renounce {
        format!("Renders {auth_type} authority unusable (set to null).")
    } else if let Some(ref auth) = new_auth {
        if let Some(user) = user_pubkey {
            if auth != user {
                target_mismatch = true;
                risk_flags.push("authority_takeover".into());
                format!("Transfers {auth_type} to {auth} (not you). Account takeover.")
            } else {
                format!("Transfers {auth_type} to your account.")
            }
        } else {
            format!("Transfers {auth_type} to {auth}.")
        }
    } else {
        "SetAuthority with ambiguous new authority.".into()
    };

    let mut decoded_args = vec![ArgValue {
        name: "authority_type".into(),
        value: auth_type.to_string(),
        kind: "enum".into(),
    }];
    if let Some(ref auth) = new_auth {
        decoded_args.push(ArgValue {
            name: "new_authority".into(),
            value: auth.clone(),
            kind: "Option<pubkey>".into(),
        });
    } else {
        decoded_args.push(ArgValue {
            name: "new_authority".into(),
            value: "null".into(),
            kind: "Option<pubkey>".into(),
        });
    }

    DecodedCall {
        selector: disc_hex.to_string(),
        function_name: "SetAuthority".into(),
        decoded_args,
        effect,
        risk_flags,
        target_mismatch,
    }
}

fn decode_close_account(
    _data: &[u8],
    account_keys: Option<&[String]>,
    user_pubkey: Option<&str>,
    disc_hex: &str,
) -> DecodedCall {
    // CloseAccount: data = [9] = 1 byte
    // accounts = [account, destination, authority]
    let destination = account_keys
        .and_then(|keys| keys.get(1).cloned())
        .unwrap_or_else(|| "unknown".into());

    let mut risk_flags = Vec::new();
    let mut target_mismatch = false;

    let effect = if destination == "unknown" {
        "Closes token account (destination unknown).".into()
    } else {
        let mut e = format!("Closes token account, sends rent to {destination}.");
        if let Some(user) = user_pubkey {
            if destination != *user {
                target_mismatch = true;
                risk_flags.push("close_to_non_user".into());
                e.push_str(&format!(
                    " WARNING: destination differs from expected {user}."
                ));
            }
        }
        e
    };

    DecodedCall {
        selector: disc_hex.to_string(),
        function_name: "CloseAccount".into(),
        decoded_args: vec![ArgValue {
            name: "destination".into(),
            value: destination,
            kind: "pubkey".into(),
        }],
        effect,
        risk_flags,
        target_mismatch,
    }
}

/// Decode a Solana transaction from a JSON message structure.
///
/// Expected JSON format:
/// ```json
/// {
///   "account_keys": ["key1", "key2", ...],
///   "instructions": [
///     { "program_id_index": 0, "accounts": [1, 2, 0], "data": "base64..." }
///   ]
/// }
/// ```
pub fn decode_solana_transaction_json(
    message: &serde_json::Value,
    user_pubkey: Option<&str>,
) -> IntentAnalysis {
    let account_keys: Vec<String> = message
        .get("account_keys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let instructions = message
        .get("instructions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut result = IntentAnalysis::new("solana", None, None);

    for ix in &instructions {
        let program_idx = ix
            .get("program_id_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let program_id = account_keys.get(program_idx).cloned().unwrap_or_default();

        let account_indices: Vec<usize> = ix
            .get("accounts")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as usize))
                    .collect()
            })
            .unwrap_or_default();

        let resolved_accounts: Vec<String> = account_indices
            .iter()
            .filter_map(|&idx| account_keys.get(idx).cloned())
            .collect();

        let data_b64 = ix.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_b64)
            .unwrap_or_default();

        let call =
            decode_spl_instruction(&program_id, &data, Some(&resolved_accounts), user_pubkey);
        result.add_call(call);
    }

    result.finalize_summary();
    result
}

/// Decode a Solana instruction from raw data (no account context).
pub fn decode_solana_instruction(
    program_id: &str,
    data: &[u8],
    user_pubkey: Option<&str>,
) -> DecodedCall {
    // Determine program type from ID
    if program_id == SPL_TOKEN || program_id == SPL_TOKEN_2022 {
        decode_spl_instruction(program_id, data, None, user_pubkey)
    } else if program_id == SYSTEM_PROGRAM {
        decode_system_instruction(data, user_pubkey)
    } else if program_id == BPF_UPGRADEABLE {
        decode_bpf_upgradeable(data)
    } else {
        DecodedCall {
            selector: hex::encode(data.get(..8).unwrap_or(&[])),
            function_name: "unknown".into(),
            decoded_args: vec![],
            effect: format!("Unknown program {program_id}. Cannot decode without IDL."),
            risk_flags: vec![],
            target_mismatch: false,
        }
    }
}

fn decode_system_instruction(data: &[u8], _user_pubkey: Option<&str>) -> DecodedCall {
    if data.len() < 4 {
        return DecodedCall {
            selector: hex::encode(data),
            function_name: "unknown".into(),
            decoded_args: vec![],
            effect: "Truncated System Program instruction.".into(),
            risk_flags: vec![],
            target_mismatch: false,
        };
    }

    let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (name, desc) = match code {
        1 => ("CreateAccount", "Creates a new system account"),
        3 => ("Transfer", "Transfers SOL between accounts"),
        4 => ("Assign", "Assigns account to a program"),
        _ => ("unknown", "Unknown System Program instruction"),
    };

    let mut risk_flags = Vec::new();
    if name == "Assign" {
        risk_flags.push("program_assignment".into());
    }

    DecodedCall {
        selector: hex::encode(&data[..4.min(data.len())]),
        function_name: name.into(),
        decoded_args: vec![],
        effect: desc.into(),
        risk_flags,
        target_mismatch: false,
    }
}

fn decode_bpf_upgradeable(data: &[u8]) -> DecodedCall {
    let disc_hex = hex::encode(data.get(..8).unwrap_or(data));

    if data.len() < 4 {
        return DecodedCall {
            selector: disc_hex,
            function_name: "bpf_upgradeable".into(),
            decoded_args: vec![],
            effect: "Truncated BPF Upgradeable Loader instruction.".into(),
            risk_flags: vec![],
            target_mismatch: false,
        };
    }

    let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut risk_flags = Vec::new();

    let effect = match code {
        4 => {
            risk_flags.push("upgrade_authority_transfer".into());
            "Transfers BPF Upgradeable Loader authority — program can be upgraded by new authority."
                .into()
        }
        _ => format!("BPF Upgradeable Loader instruction (code={code})."),
    };

    DecodedCall {
        selector: disc_hex,
        function_name: "bpf_upgradeable".into(),
        decoded_args: vec![],
        effect,
        risk_flags,
        target_mismatch: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SPL Token Transfer ────────────────────────────────────

    #[test]
    fn transfer_real_instruction() {
        // Real SPL Token Transfer: disc=3, amount=1000
        // Data: [3, 0xe8, 0x03, 0, 0, 0, 0, 0, 0] (1000 in LE u64)
        // Accounts: [source, destination, authority]
        let data = [3u8, 0xe8, 0x03, 0, 0, 0, 0, 0, 0];
        let accounts = vec![
            "SourceTokenAccount111111111111111111111111".into(),
            "DestTokenAccount111111111111111111111111".into(),
            "AuthorityPubkey1111111111111111111111111".into(),
        ];
        let call = decode_spl_instruction(SPL_TOKEN, &data, Some(&accounts), None);
        assert_eq!(call.function_name, "Transfer");
        // amount=1000
        let amount_arg = call
            .decoded_args
            .iter()
            .find(|a| a.name == "amount")
            .unwrap();
        assert_eq!(amount_arg.value, "1000");
        // destination from account index 1
        let dest_arg = call
            .decoded_args
            .iter()
            .find(|a| a.name == "destination")
            .unwrap();
        assert_eq!(dest_arg.value, "DestTokenAccount111111111111111111111111");
        assert!(!call.target_mismatch);
    }

    #[test]
    fn transfer_no_accounts_flags_unknown() {
        let data = [3u8, 0xe8, 0x03, 0, 0, 0, 0, 0, 0];
        let call = decode_spl_instruction(SPL_TOKEN, &data, None, None);
        assert_eq!(call.function_name, "Transfer");
        assert!(call.effect.contains("destination unknown"));
    }

    // ── SPL Token Approve ─────────────────────────────────────

    #[test]
    fn approve_real_instruction() {
        // Approve: disc=4, amount=500
        let data = [4u8, 0xf4, 0x01, 0, 0, 0, 0, 0, 0];
        let accounts = vec![
            "SourceAcct1111111111111111111111111111111".into(),
            "DelegateAcct1111111111111111111111111111".into(),
            "OwnerAcct111111111111111111111111111111".into(),
        ];
        let call = decode_spl_instruction(SPL_TOKEN, &data, Some(&accounts), None);
        assert_eq!(call.function_name, "Approve");
        let amt = call
            .decoded_args
            .iter()
            .find(|a| a.name == "amount")
            .unwrap();
        assert_eq!(amt.value, "500");
        let del = call
            .decoded_args
            .iter()
            .find(|a| a.name == "delegate")
            .unwrap();
        assert_eq!(del.value, "DelegateAcct1111111111111111111111111111");
        assert!(!call.target_mismatch);
    }

    #[test]
    fn approve_to_non_user() {
        let data = [4u8, 0xf4, 0x01, 0, 0, 0, 0, 0, 0];
        let accounts = vec![
            "SourceAcct1111111111111111111111111111111".into(),
            "DelegateAttacker111111111111111111111111".into(),
            "OwnerAcct111111111111111111111111111111".into(),
        ];
        let call = decode_spl_instruction(
            SPL_TOKEN,
            &data,
            Some(&accounts),
            Some("11111111111111111111111111111111"),
        );
        assert!(call.target_mismatch);
        assert!(call.risk_flags.contains(&"delegate_non_user".to_string()));
    }

    // ── SetAuthority — each AuthorityType ────────────────────

    fn make_set_authority_data(auth_type: u8, new_auth: Option<[u8; 32]>) -> Vec<u8> {
        let mut d = vec![6u8, auth_type];
        match new_auth {
            Some(key) => {
                d.push(1);
                d.extend_from_slice(&key);
            }
            None => {
                d.push(0);
            }
        }
        d
    }

    #[test]
    fn set_authority_mint_tokens_takeover() {
        let data = make_set_authority_data(0, Some([0xAA; 32])); // 0=MintTokens
        let accounts = vec![
            "TargetAcct11111111111111111111111111".into(),
            "CurrentAuth11111111111111111111111".into(),
        ];
        let call = decode_spl_instruction(
            SPL_TOKEN,
            &data,
            Some(&accounts),
            Some("11111111111111111111111111111111"),
        );
        assert_eq!(call.function_name, "SetAuthority");
        let at = call
            .decoded_args
            .iter()
            .find(|a| a.name == "authority_type")
            .unwrap();
        assert_eq!(at.value, "MintTokens");
        assert!(call.target_mismatch);
        assert!(call.risk_flags.contains(&"authority_takeover".to_string()));
        assert!(call.effect.contains("MintTokens"));
        assert!(call.effect.contains("Account takeover"));
    }

    #[test]
    fn set_authority_freeze_account_takeover() {
        let data = make_set_authority_data(1, Some([0xBB; 32])); // 1=FreezeAccount
        let accounts = vec!["T1".into(), "C1".into()];
        let call = decode_spl_instruction(
            SPL_TOKEN,
            &data,
            Some(&accounts),
            Some("11111111111111111111111111111111"),
        );
        let at = call
            .decoded_args
            .iter()
            .find(|a| a.name == "authority_type")
            .unwrap();
        assert_eq!(at.value, "FreezeAccount");
        assert!(call.target_mismatch);
    }

    #[test]
    fn set_authority_account_owner_takeover() {
        let data = make_set_authority_data(2, Some([0xCC; 32])); // 2=AccountOwner
        let accounts = vec!["T1".into(), "C1".into()];
        let call = decode_spl_instruction(
            SPL_TOKEN,
            &data,
            Some(&accounts),
            Some("11111111111111111111111111111111"),
        );
        let at = call
            .decoded_args
            .iter()
            .find(|a| a.name == "authority_type")
            .unwrap();
        assert_eq!(at.value, "AccountOwner");
        assert!(call.target_mismatch);
    }

    #[test]
    fn set_authority_close_account_takeover() {
        let data = make_set_authority_data(3, Some([0xDD; 32])); // 3=CloseAccount
        let accounts = vec!["T1".into(), "C1".into()];
        let call = decode_spl_instruction(
            SPL_TOKEN,
            &data,
            Some(&accounts),
            Some("11111111111111111111111111111111"),
        );
        let at = call
            .decoded_args
            .iter()
            .find(|a| a.name == "authority_type")
            .unwrap();
        assert_eq!(at.value, "CloseAccount");
        assert!(call.target_mismatch);
    }

    #[test]
    fn set_authority_renounce_mint() {
        let data = make_set_authority_data(0, None); // MintTokens -> null
        let call = decode_spl_instruction(SPL_TOKEN, &data, None, None);
        assert_eq!(call.function_name, "SetAuthority");
        assert!(!call.target_mismatch);
        assert!(call.risk_flags.is_empty());
        assert!(call.effect.contains("Renders"));
    }

    #[test]
    fn set_authority_renounce_freeze() {
        let data = make_set_authority_data(1, None); // FreezeAccount -> null
        let call = decode_spl_instruction(SPL_TOKEN, &data, None, None);
        assert!(!call.target_mismatch);
        assert!(call.effect.contains("Renders"));
    }

    #[test]
    fn set_authority_renounce_owner() {
        let data = make_set_authority_data(2, None); // AccountOwner -> null
        let call = decode_spl_instruction(SPL_TOKEN, &data, None, None);
        assert!(!call.target_mismatch);
        assert!(call.effect.contains("Renders"));
    }

    #[test]
    fn set_authority_renounce_close() {
        let data = make_set_authority_data(3, None); // CloseAccount -> null
        let call = decode_spl_instruction(SPL_TOKEN, &data, None, None);
        assert!(!call.target_mismatch);
        assert!(call.effect.contains("Renders"));
    }

    // ── CloseAccount ──────────────────────────────────────────

    #[test]
    fn close_account_to_non_user() {
        let data = [9u8]; // CloseAccount: data=[9]
        let accounts = vec![
            "TokenAcct1111111111111111111111111111111".into(),
            "AttackerDest1111111111111111111111111111".into(),
            "AuthorityKey111111111111111111111111111".into(),
        ];
        let call = decode_spl_instruction(
            SPL_TOKEN,
            &data,
            Some(&accounts),
            Some("11111111111111111111111111111111"),
        );
        assert_eq!(call.function_name, "CloseAccount");
        assert!(call.target_mismatch);
        assert!(call.risk_flags.contains(&"close_to_non_user".to_string()));
    }

    #[test]
    fn close_account_to_self() {
        let data = [9u8];
        let accounts = vec![
            "TokenAcct1111111111111111111111111111111".into(),
            "MyWallet11111111111111111111111111111111".into(),
            "AuthorityKey111111111111111111111111111".into(),
        ];
        let user = "MyWallet11111111111111111111111111111111";
        let call = decode_spl_instruction(SPL_TOKEN, &data, Some(&accounts), Some(user));
        assert!(!call.target_mismatch);
    }

    // ── Transaction JSON decode ───────────────────────────────

    #[test]
    fn transaction_json_transfer() {
        let msg = serde_json::json!({
            "account_keys": [
                "OwnerWallet1111111111111111111111111111111",
                "SourceTokenAcct11111111111111111111111111",
                "DestTokenAcct1111111111111111111111111111"
            ],
            "instructions": [{
                "program_id_index": 0,
                "accounts": [1, 2, 0],
                "data": "AwHoAwAAAAAAAAAA" // base64 of [3, 0xe8, 0x03, 0, 0, 0, 0, 0, 0]
            }]
        });
        let analysis = decode_solana_transaction_json(
            &msg,
            Some("OwnerWallet1111111111111111111111111111111"),
        );
        assert_eq!(analysis.calls.len(), 1);
        assert_eq!(analysis.calls[0].function_name, "Transfer");
        let dest = analysis.calls[0]
            .decoded_args
            .iter()
            .find(|a| a.name == "destination")
            .unwrap();
        assert_eq!(dest.value, "DestTokenAcct1111111111111111111111111111");
    }
}
