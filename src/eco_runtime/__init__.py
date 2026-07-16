"""Embedded runtime contracts and policy enforcement for ecosystem."""

from .contracts import (
    API_VERSION,
    contract_errors,
    tool_argument_errors,
    validate_record,
    validate_tool_arguments,
)
from .team_identity import (
    AUTHORITY_API_VERSION,
    authority_contract_errors,
    authority_record_digest,
    authority_schema_bundle_digest,
    identity_key_id,
    membership_binding_id,
    validate_authority_record,
)
from .policy_bundle import (
    PolicyTrustAnchor,
    TeamPolicyVerifier,
    VerifiedPolicyBundle,
)
from .team_access import (
    TeamAccessDecision,
    evaluate_team_access,
    validate_team_access_policy,
)
from .team_actor import (
    AuthenticatedActorAssertion,
    ActorAuthenticator,
    actor_assertion_message,
    recovery_actor_operation_digest,
    runtime_actor_operation_digest,
    validate_actor_assertion,
)
from .team_approval import (
    ResolvedApprovalKey,
    TeamApprovalVerifier,
    VerifiedActionPermit,
    validate_team_approval_record,
)
from .team_authority import SQLiteTeamAuthority
from .team_migration import rotate_authority_generation
from .team_rotation import TeamKeyRotationVerifier, VerifiedTeamKeyRotation
from .team_runtime import (
    DurableRuntimeDecisionAuthority,
    PolicyEngineRuntimeDecisionAuthority,
    TeamAuthorizationDecision,
    TeamAuthorizationGate,
)
from .broker import RepositoryReadBroker, RepositoryReadResult
from .adapters import (
    ADAPTER_VERSION,
    AdapterInvocationResult,
    OpenAIChatInvocation,
    OpenAICompatibleAdapter,
    OpenAICompatibleInvoker,
    PinnedOpenAICompatibleDeployment,
)
from .artifact_store import ArtifactAvailabilityProof, ContentAddressedArtifactStore
from .approval import (
    ApprovalKeyPolicy,
    ApprovalSigner,
    ApprovalTrustStore,
    VerifiedApproval,
    approval_subject_digest,
    build_approval_grant,
)
from .change_store import SQLiteChangeAuthority, SQLiteChangeStore
from .budget import BudgetLedger, BudgetSnapshot
from .errors import (
    BrokerError,
    ContractValidationError,
    RuntimeAdapterError,
    RuntimeBudgetError,
    RuntimePolicyError,
    RuntimeStateError,
    RuntimeStoreError,
)
from .policy import PlanningResult, PolicyEngine
from .orchestrator import (
    EmbeddedOrchestrator,
    RepositoryReadExecution,
    RepositoryReader,
    RuntimeCapabilities,
)
from .state import RunEventChain, RunState
from .store import SQLiteRuntimeStore
from .write_broker import (
    FileState,
    LinuxWorkspaceWriteBroker,
    WorkspaceRollbackResult,
    WorkspaceWriteResult,
)
from .write_orchestrator import (
    ControlledWriteExecution,
    ControlledWriteOrchestrator,
    ControlledWriteProposal,
)

__all__ = [
    "API_VERSION",
    "AUTHORITY_API_VERSION",
    "ADAPTER_VERSION",
    "AdapterInvocationResult",
    "AuthenticatedActorAssertion",
    "ActorAuthenticator",
    "ArtifactAvailabilityProof",
    "ApprovalKeyPolicy",
    "ApprovalSigner",
    "ApprovalTrustStore",
    "BrokerError",
    "BudgetLedger",
    "BudgetSnapshot",
    "ContractValidationError",
    "authority_contract_errors",
    "authority_record_digest",
    "authority_schema_bundle_digest",
    "identity_key_id",
    "membership_binding_id",
    "validate_authority_record",
    "OpenAIChatInvocation",
    "OpenAICompatibleAdapter",
    "OpenAICompatibleInvoker",
    "PinnedOpenAICompatibleDeployment",
    "RuntimeAdapterError",
    "ContentAddressedArtifactStore",
    "ControlledWriteExecution",
    "ControlledWriteOrchestrator",
    "ControlledWriteProposal",
    "FileState",
    "RuntimePolicyError",
    "RuntimeStateError",
    "RuntimeStoreError",
    "PlanningResult",
    "PolicyTrustAnchor",
    "EmbeddedOrchestrator",
    "DurableRuntimeDecisionAuthority",
    "PolicyEngine",
    "PolicyEngineRuntimeDecisionAuthority",
    "LinuxWorkspaceWriteBroker",
    "RunEventChain",
    "RepositoryReadBroker",
    "RepositoryReadExecution",
    "RepositoryReader",
    "RepositoryReadResult",
    "RunState",
    "RuntimeBudgetError",
    "RuntimeCapabilities",
    "TeamPolicyVerifier",
    "TeamAccessDecision",
    "TeamApprovalVerifier",
    "TeamAuthorizationDecision",
    "TeamAuthorizationGate",
    "TeamKeyRotationVerifier",
    "ResolvedApprovalKey",
    "SQLiteTeamAuthority",
    "SQLiteRuntimeStore",
    "SQLiteChangeAuthority",
    "SQLiteChangeStore",
    "VerifiedApproval",
    "VerifiedPolicyBundle",
    "VerifiedActionPermit",
    "VerifiedTeamKeyRotation",
    "WorkspaceRollbackResult",
    "WorkspaceWriteResult",
    "approval_subject_digest",
    "actor_assertion_message",
    "build_approval_grant",
    "contract_errors",
    "evaluate_team_access",
    "recovery_actor_operation_digest",
    "rotate_authority_generation",
    "tool_argument_errors",
    "runtime_actor_operation_digest",
    "validate_record",
    "validate_team_access_policy",
    "validate_actor_assertion",
    "validate_team_approval_record",
    "validate_tool_arguments",
]

VERSION = "0.2.0"
