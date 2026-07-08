//! Reconstruction engine entry point. It depends ONLY on the chain-agnostic
//! [`BytecodeLifter`](crate::lifter::BytecodeLifter) and
//! [`InterfaceRecoverer`](crate::interface::InterfaceRecoverer) traits — there
//! is no blockchain-specific import here, proving the engine is target-agnostic.

use crate::deployment::{DeploymentRecoverer, RecoveredDeployment, StorageEvidence};
use crate::interface::{InterfaceRecoverer, RecoveredInterface};
use crate::lifter::{BytecodeLifter, LiftError, LiftedProgram};

pub struct ReconstructionEngine<'a> {
    lifter: &'a dyn BytecodeLifter,
}

impl<'a> ReconstructionEngine<'a> {
    pub fn new(lifter: &'a dyn BytecodeLifter) -> Self {
        ReconstructionEngine { lifter }
    }
    pub fn lift(&self, runtime_bytecode: &[u8]) -> Result<LiftedProgram, LiftError> {
        self.lifter.lift(runtime_bytecode)
    }
    /// Recover a chain-agnostic interface using any [`InterfaceRecoverer`].
    /// The engine never depends on a specific chain's ABI concepts.
    pub fn recover_interface(
        &self,
        recoverer: &dyn InterfaceRecoverer,
        program: &LiftedProgram,
    ) -> RecoveredInterface {
        recoverer.recover_interface(program)
    }
    /// Recover a chain-agnostic deployment using any [`DeploymentRecoverer`].
    /// `storage` is evidence only; passing an empty [`StorageEvidence`] keeps
    /// offline reconstruction fully functional. The engine never depends on a
    /// specific chain's deployment mechanics.
    pub fn recover_deployment(
        &self,
        recoverer: &dyn DeploymentRecoverer,
        runtime_bytecode: &[u8],
        storage: &StorageEvidence,
    ) -> RecoveredDeployment {
        recoverer.recover_deployment(runtime_bytecode, storage)
    }
}

pub fn lift_with(
    lifter: &dyn BytecodeLifter,
    runtime_bytecode: &[u8],
) -> Result<LiftedProgram, LiftError> {
    lifter.lift(runtime_bytecode)
}

/// Free-function form of chain-agnostic interface recovery.
pub fn recover_interface_with(
    recoverer: &dyn InterfaceRecoverer,
    program: &LiftedProgram,
) -> RecoveredInterface {
    recoverer.recover_interface(program)
}

/// Free-function form of chain-agnostic deployment recovery.
pub fn recover_deployment_with(
    recoverer: &dyn DeploymentRecoverer,
    runtime_bytecode: &[u8],
    storage: &StorageEvidence,
) -> RecoveredDeployment {
    recoverer.recover_deployment(runtime_bytecode, storage)
}
