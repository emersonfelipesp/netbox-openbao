"""Fail-closed OpenBao administration discovery and parity contracts."""

from .backends import get_administration_backend
from .observations import record_capability_observation, record_health_observation
from .parity import load_parity_manifest
from .schema import CapabilityDocument, CapabilitySchemaError, DiscoveredOperation

__all__ = (
    'CapabilityDocument',
    'CapabilitySchemaError',
    'DiscoveredOperation',
    'get_administration_backend',
    'load_parity_manifest',
    'record_capability_observation',
    'record_health_observation',
)
