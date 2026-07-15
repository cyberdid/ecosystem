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

__all__ = [
    "API_VERSION",
    "ADAPTER_VERSION",
    "AdapterInvocationResult",
    "ArtifactAvailabilityProof",
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
    "RuntimePolicyError",
    "RuntimeStateError",
    "RuntimeStoreError",
    "PlanningResult",
    "EmbeddedOrchestrator",
    "PolicyEngine",
    "RunEventChain",
    "RepositoryReadBroker",
    "RepositoryReadExecution",
    "RepositoryReader",
    "RepositoryReadResult",
    "RunState",
    "RuntimeBudgetError",
    "RuntimeCapabilities",
    "SQLiteRuntimeStore",
    "contract_errors",
    "tool_argument_errors",
    "validate_record",
    "validate_tool_arguments",
]

VERSION = "0.1.0"
