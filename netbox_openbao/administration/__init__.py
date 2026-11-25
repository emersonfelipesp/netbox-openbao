"""Fail-closed OpenBao administration discovery and parity contracts."""

from .backends import get_administration_backend
from .cluster import (
    HAStatus,
    InitializationResult,
    LeaderStatus,
    MetricsSnapshot,
    RaftConfiguration,
    RaftPeer,
    SealStatus,
    collect_cluster_state,
    normalize_metrics,
)
from .engines import ExplorerOperation, SecretEngineMount
from .observations import record_capability_observation, record_health_observation
from .parity import load_parity_manifest
from .schema import CapabilityDocument, CapabilitySchemaError, DiscoveredOperation

__all__ = (
    'CapabilityDocument',
    'CapabilitySchemaError',
    'DiscoveredOperation',
    'ExplorerOperation',
    'HAStatus',
    'InitializationResult',
    'LeaderStatus',
    'MetricsSnapshot',
    'RaftConfiguration',
    'RaftPeer',
    'SealStatus',
    'SecretEngineMount',
    'get_administration_backend',
    'collect_cluster_state',
    'load_parity_manifest',
    'record_capability_observation',
    'record_health_observation',
    'normalize_metrics',
)
