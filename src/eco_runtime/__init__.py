"""Embedded runtime contracts and policy enforcement for ecosystem."""

from .contracts import (
    API_VERSION,
    contract_errors,
    tool_argument_errors,
    validate_record,
    validate_tool_arguments,
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
    "ADAPTER_VERSION",
    "AdapterInvocationResult",
    "ArtifactAvailabilityProof",
    "ApprovalKeyPolicy",
    "ApprovalSigner",
    "ApprovalTrustStore",
    "BrokerError",
    "BudgetLedger",
    "BudgetSnapshot",
    "ContractValidationError",
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
    "EmbeddedOrchestrator",
    "PolicyEngine",
    "LinuxWorkspaceWriteBroker",
    "RunEventChain",
    "RepositoryReadBroker",
    "RepositoryReadExecution",
    "RepositoryReader",
    "RepositoryReadResult",
    "RunState",
    "RuntimeBudgetError",
    "RuntimeCapabilities",
    "SQLiteRuntimeStore",
    "SQLiteChangeAuthority",
    "SQLiteChangeStore",
    "VerifiedApproval",
    "WorkspaceRollbackResult",
    "WorkspaceWriteResult",
    "approval_subject_digest",
    "build_approval_grant",
    "contract_errors",
    "tool_argument_errors",
    "validate_record",
    "validate_tool_arguments",
]

VERSION = "0.2.0"
