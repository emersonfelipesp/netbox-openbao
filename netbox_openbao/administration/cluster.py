"""Bounded typed representations for OpenBao cluster and Raft state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .schema import CapabilitySchemaError

MAX_CLUSTER_JSON_BYTES = 1_000_000
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_HA_NODES = 256
MAX_RAFT_PEERS = 256
SNAPSHOT_CHUNK_BYTES = 64 * 1024


def _mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CapabilitySchemaError(f'OpenBao returned invalid {field_name}.')
    return value


def _boolean(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise CapabilitySchemaError(f'OpenBao returned invalid {field_name}.')
    return value


def _integer(value: Any, field_name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CapabilitySchemaError(f'OpenBao returned invalid {field_name}.')
    return value


def _string(value: Any, field_name: str, *, maximum: int = 500, blank: bool = True) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CapabilitySchemaError(f'OpenBao returned invalid {field_name}.')
    if not blank and not value:
        raise CapabilitySchemaError(f'OpenBao returned invalid {field_name}.')
    return value


def _optional_string(value: Any, field_name: str, *, maximum: int = 500) -> str:
    if value is None:
        return ''
    return _string(value, field_name, maximum=maximum)


@dataclass(frozen=True, slots=True)
class SealStatus:
    initialized: bool
    sealed: bool
    threshold: int
    shares: int
    progress: int
    version: str
    seal_type: str
    migration: bool
    recovery_seal: bool
    storage_type: str
    cluster_name: str
    cluster_id: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LeaderStatus:
    ha_enabled: bool
    is_self: bool
    leader_address: str
    leader_cluster_address: str
    active_time: str
    raft_committed_index: int
    raft_applied_index: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HANode:
    hostname: str
    api_address: str
    cluster_address: str
    active_node: bool
    last_echo: str
    version: str


@dataclass(frozen=True, slots=True)
class HAStatus:
    nodes: tuple[HANode, ...]

    def as_dict(self) -> dict[str, Any]:
        return {'nodes': [asdict(node) for node in self.nodes]}


@dataclass(frozen=True, slots=True)
class RaftPeer:
    node_id: str
    address: str
    leader: bool
    voter: bool
    protocol_version: str


@dataclass(frozen=True, slots=True)
class RaftConfiguration:
    index: int
    peers: tuple[RaftPeer, ...]

    def as_dict(self) -> dict[str, Any]:
        return {'index': self.index, 'peers': [asdict(peer) for peer in self.peers]}

    def peer(self, node_id: str) -> RaftPeer | None:
        return next((peer for peer in self.peers if peer.node_id == node_id), None)


@dataclass(frozen=True, slots=True, repr=False)
class InitializationResult:
    """Request-scoped custody material. Never persist, log, cache, or enqueue."""

    keys: tuple[str, ...] = field(repr=False)
    keys_base64: tuple[str, ...] = field(repr=False)
    recovery_keys: tuple[str, ...] = field(repr=False)
    recovery_keys_base64: tuple[str, ...] = field(repr=False)
    root_token: str = field(repr=False)

    def __repr__(self) -> str:
        return '<InitializationResult redacted>'

    def as_dict(self) -> dict[str, Any]:
        return {
            'keys': list(self.keys),
            'keys_base64': list(self.keys_base64),
            'recovery_keys': list(self.recovery_keys),
            'recovery_keys_base64': list(self.recovery_keys_base64),
            'root_token': self.root_token,
        }


class BoundedSnapshotReader:
    """Read-only request body wrapper that enforces the snapshot size limit."""

    def __init__(self, stream, size: int):
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_SNAPSHOT_BYTES:
            raise ValueError('Snapshot size is outside the allowed range.')
        self._stream = stream
        self._size = size
        self._read = 0

    def __len__(self):
        return self._size

    def read(self, amount: int = -1) -> bytes:
        remaining = self._size - self._read
        if remaining <= 0:
            return b''
        if amount is None or amount < 0 or amount > remaining:
            amount = remaining
        if amount == 0:
            return b''
        chunk = self._stream.read(amount)
        if not isinstance(chunk, bytes):
            raise ValueError('Snapshot stream returned invalid data.')
        if not chunk:
            raise ValueError('Snapshot stream ended before its declared size.')
        if len(chunk) > amount:
            raise ValueError('Snapshot stream exceeded its requested chunk size.')
        self._read += len(chunk)
        if self._read > self._size:
            raise ValueError('Snapshot stream exceeded its declared size.')
        return chunk


class SnapshotDownload:
    """One-use bounded response stream. Snapshot bytes are never retained."""

    def __init__(self, response, declared_size: int | None):
        self._response = response
        self.declared_size = declared_size
        self._opened = False

    def __repr__(self) -> str:
        return '<SnapshotDownload redacted>'

    def chunks(self):
        if self._opened:
            raise RuntimeError('Snapshot download streams are one-use.')
        self._opened = True
        total = 0
        try:
            for chunk in self._response.raw.stream(SNAPSHOT_CHUNK_BYTES, decode_content=False):
                if not isinstance(chunk, bytes):
                    raise ValueError('Snapshot stream returned invalid data.')
                total += len(chunk)
                if total > MAX_SNAPSHOT_BYTES:
                    raise ValueError('Snapshot stream exceeded the allowed size.')
                if chunk:
                    yield chunk
            if self.declared_size is not None and total != self.declared_size:
                raise ValueError('Snapshot stream length did not match its declared size.')
        finally:
            self._response.close()

    def close(self):
        self._response.close()


def normalize_seal_status(payload: Any) -> SealStatus:
    value = _mapping(payload, 'seal status')
    return SealStatus(
        initialized=_boolean(value.get('initialized'), 'initialized state'),
        sealed=_boolean(value.get('sealed'), 'sealed state'),
        threshold=_integer(value.get('t', 0), 'seal threshold'),
        shares=_integer(value.get('n', 0), 'seal share count'),
        progress=_integer(value.get('progress', 0), 'unseal progress'),
        version=_optional_string(value.get('version'), 'version', maximum=64),
        seal_type=_optional_string(value.get('type'), 'seal type', maximum=64),
        migration=_boolean(value.get('migration', False), 'migration state'),
        recovery_seal=_boolean(value.get('recovery_seal', False), 'recovery seal state'),
        storage_type=_optional_string(value.get('storage_type'), 'storage type', maximum=64),
        cluster_name=_optional_string(value.get('cluster_name'), 'cluster name', maximum=200),
        cluster_id=_optional_string(value.get('cluster_id'), 'cluster ID', maximum=200),
    )


def normalize_leader_status(payload: Any) -> LeaderStatus:
    value = _mapping(payload, 'leader status')
    return LeaderStatus(
        ha_enabled=_boolean(value.get('ha_enabled'), 'HA enabled state'),
        is_self=_boolean(value.get('is_self', False), 'leader self state'),
        leader_address=_optional_string(value.get('leader_address'), 'leader address'),
        leader_cluster_address=_optional_string(value.get('leader_cluster_address'), 'leader cluster address'),
        active_time=_optional_string(value.get('active_time'), 'leader active time', maximum=100),
        raft_committed_index=_integer(value.get('raft_committed_index', 0), 'Raft committed index'),
        raft_applied_index=_integer(value.get('raft_applied_index', 0), 'Raft applied index'),
    )


def _normalize_ha_node(value: Any) -> HANode:
    node = _mapping(value, 'HA node')
    return HANode(
        hostname=_string(node.get('hostname', ''), 'HA hostname', maximum=255, blank=False),
        api_address=_optional_string(node.get('api_address'), 'HA API address'),
        cluster_address=_optional_string(node.get('cluster_address'), 'HA cluster address'),
        active_node=_boolean(node.get('active_node'), 'HA active state'),
        last_echo=_optional_string(node.get('last_echo'), 'HA last echo', maximum=100),
        version=_optional_string(node.get('version'), 'HA node version', maximum=64),
    )


def normalize_ha_status(payload: Any) -> HAStatus:
    value = _mapping(payload, 'HA status')
    raw_nodes = value.get('nodes', value.get('Nodes'))
    if not isinstance(raw_nodes, list) or len(raw_nodes) > MAX_HA_NODES:
        raise CapabilitySchemaError('OpenBao returned invalid HA nodes.')
    return HAStatus(nodes=tuple(_normalize_ha_node(node) for node in raw_nodes))


def _normalize_raft_peer(value: Any) -> RaftPeer:
    peer = _mapping(value, 'Raft peer')
    raw_protocol = peer.get('protocol_version')
    if isinstance(raw_protocol, int) and not isinstance(raw_protocol, bool):
        protocol_version = str(raw_protocol)
    elif isinstance(raw_protocol, str) and len(raw_protocol) == 1 and ord(raw_protocol) < 32:
        protocol_version = str(ord(raw_protocol))
    else:
        protocol_version = _optional_string(raw_protocol, 'Raft protocol version', maximum=32)
    return RaftPeer(
        node_id=_string(peer.get('node_id', ''), 'Raft node ID', maximum=200, blank=False),
        address=_string(peer.get('address', ''), 'Raft address', maximum=500, blank=False),
        leader=_boolean(peer.get('leader'), 'Raft leader state'),
        voter=_boolean(peer.get('voter'), 'Raft voter state'),
        protocol_version=protocol_version,
    )


def normalize_raft_configuration(payload: Any) -> RaftConfiguration:
    value = _mapping(payload, 'Raft configuration')
    data = _mapping(value.get('data', value), 'Raft configuration data')
    config = _mapping(data.get('config', data), 'Raft configuration object')
    raw_servers = config.get('servers')
    if not isinstance(raw_servers, list) or len(raw_servers) > MAX_RAFT_PEERS:
        raise CapabilitySchemaError('OpenBao returned invalid Raft peers.')
    peers = tuple(_normalize_raft_peer(peer) for peer in raw_servers)
    if len({peer.node_id for peer in peers}) != len(peers):
        raise CapabilitySchemaError('OpenBao returned duplicate Raft node IDs.')
    return RaftConfiguration(index=_integer(config.get('index'), 'Raft configuration index'), peers=peers)


def _material_list(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > 64:
        raise CapabilitySchemaError(f'OpenBao returned invalid {field_name}.')
    return tuple(_string(item, field_name, maximum=20_000, blank=False) for item in value)


def normalize_initialization_result(payload: Any) -> InitializationResult:
    value = _mapping(payload, 'initialization result')
    return InitializationResult(
        keys=_material_list(value.get('keys'), 'unseal keys'),
        keys_base64=_material_list(value.get('keys_base64'), 'base64 unseal keys'),
        recovery_keys=_material_list(value.get('recovery_keys'), 'recovery keys'),
        recovery_keys_base64=_material_list(value.get('recovery_keys_base64'), 'base64 recovery keys'),
        root_token=_string(value.get('root_token', ''), 'initial root token', maximum=20_000, blank=False),
    )
