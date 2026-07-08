#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![allow(
    clippy::needless_update,
    clippy::single_match,
    clippy::redundant_closure,
    clippy::len_zero,
    clippy::derivable_impls,
    clippy::field_reassign_with_default,
    clippy::useless_format,
    clippy::op_ref,
    clippy::collapsible_match
)]

pub mod anchor;
pub mod anchor_idl;
pub mod anchor_syn;
pub mod model;
pub mod normalize;
pub mod operations;
pub mod rust;
pub mod rust_syn;
pub mod solidity;
pub mod solidity_ast;
pub mod utils;

use model::RawProgram;

pub fn parse_program(code: &str, lang: &str) -> RawProgram {
    match lang {
        "solidity" | "sol" => {
            // Try AST parser first, fallback to regex
            solidity_ast::parse(code)
        }
        "anchor" | "rust" | "rs" => {
            if code.contains("#[program]")
                || code.contains("#[account]")
                || code.contains("anchor_lang")
            {
                // Try syn-based AST parser first, fallback to regex
                anchor_syn::parse(code)
            } else {
                // Try syn-based AST parser first, fallback to regex
                rust_syn::parse(code)
            }
        }
        "idl" => {
            // Parse Anchor IDL JSON
            anchor_idl::parse_idl(code).unwrap_or_default()
        }
        _ => RawProgram::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solidity_ast_parse() {
        let code = r#"
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"#;
        let program = parse_program(code, "solidity");
        assert!(
            program.functions.len() >= 2,
            "Should extract at least 2 functions, got {}",
            program.functions.len()
        );
        assert!(
            program.state.len() >= 1,
            "Should extract state variables, got {}",
            program.state.len()
        );
    }

    #[test]
    fn test_anchor_parse() {
        let code = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        token::transfer(ctx.accounts.transfer_ctx(), amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
        let program = parse_program(code, "anchor");
        assert!(
            program.functions.len() >= 2,
            "Should extract at least 2 functions, got {}",
            program.functions.len()
        );
        // Account structs are in metadata, not state
        assert!(
            !program.metadata.structs.is_empty(),
            "Should extract account structs in metadata, got {}",
            program.metadata.structs.len()
        );
    }

    #[test]
    fn test_rust_parse() {
        let code = r#"
fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    Ok(())
}

pub fn helper_function() -> u64 {
    42
}
"#;
        let program = parse_program(code, "rust");
        assert!(
            program.functions.len() >= 2,
            "Should extract at least 2 functions, got {}",
            program.functions.len()
        );
    }

    #[test]
    fn test_anchor_idl_parse() {
        let idl = r#"
{
    "version": "0.1.0",
    "name": "vault",
    "instructions": [
        {
            "name": "initialize",
            "accounts": [
                {"name": "vault", "isMut": true, "isSigner": false},
                {"name": "authority", "isMut": true, "isSigner": true}
            ],
            "args": []
        },
        {
            "name": "deposit",
            "accounts": [
                {"name": "vault", "isMut": true, "isSigner": false},
                {"name": "authority", "isMut": false, "isSigner": true}
            ],
            "args": [
                {"name": "amount", "type": "u64"}
            ]
        },
        {
            "name": "withdraw",
            "accounts": [
                {"name": "vault", "isMut": true, "isSigner": false},
                {"name": "authority", "isMut": false, "isSigner": true}
            ],
            "args": [
                {"name": "amount", "type": "u64"}
            ]
        }
    ],
    "accounts": [
        {
            "name": "Vault",
            "fields": [
                {"name": "authority", "type": "publicKey"},
                {"name": "balance", "type": "u64"}
            ]
        }
    ]
}
"#;
        let program = parse_program(idl, "idl");
        assert_eq!(
            program.functions.len(),
            3,
            "Should extract 3 instructions, got {}",
            program.functions.len()
        );
        assert_eq!(
            program.state.len(),
            1,
            "Should extract 1 account, got {}",
            program.state.len()
        );

        // Check function names
        let names: Vec<_> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"initialize"));
        assert!(names.contains(&"deposit"));
        assert!(names.contains(&"withdraw"));

        // Check account
        assert_eq!(program.state[0].name, "Vault");
        assert!(program.state[0].ty.contains("anchor_account"));
    }
}
