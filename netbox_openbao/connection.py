"""Where to connect for a credential bound to an Application Service.

The connection target is read straight from NetBox's built-in Application
Service (`ipam.Service`): the host is the service's IP address and the port is
its TCP port mapping. The plugin keeps no second description of the endpoint.

Resolution is deliberately strict. A service with no IP, several IPs, no TCP
port or several TCP ports is not guessed at; it is reported as unusable with a
closed error code so the operator can fix the service in NetBox.
"""

from dataclasses import dataclass

__all__ = (
    'ERROR_MULTIPLE_IPS',
    'ERROR_MULTIPLE_TCP_PORTS',
    'ERROR_NO_IP',
    'ERROR_NO_TCP_PORT',
    'ServiceConnection',
    'service_connection',
)

ERROR_NO_IP = 'no_ip'
ERROR_MULTIPLE_IPS = 'multiple_ips'
ERROR_NO_TCP_PORT = 'no_tcp_port'
ERROR_MULTIPLE_TCP_PORTS = 'multiple_tcp_ports'

_MESSAGES = {
    ERROR_NO_IP: 'Fill in the IP address on the Application Service.',
    ERROR_MULTIPLE_IPS: 'The Application Service must list exactly one IP address.',
    ERROR_NO_TCP_PORT: 'The Application Service must expose a TCP port.',
    ERROR_MULTIPLE_TCP_PORTS: 'The Application Service must expose exactly one TCP port.',
}


@dataclass(frozen=True)
class ServiceConnection:
    """Resolved connection target, or the reason there is none."""

    host: str = ''
    port: int | None = None
    error: str = ''

    @property
    def usable(self):
        return not self.error

    @property
    def message(self):
        return _MESSAGES.get(self.error, '')


def _tcp_ports(port_mappings):
    ports = []
    for mapping in port_mappings or ():
        protocol, _, port = str(mapping).partition('/')
        if protocol.strip().lower() == 'tcp' and port.strip().isdigit():
            ports.append(int(port))
    return sorted(set(ports))


def service_connection(service):
    """Resolve `service` to a host and port, or to a closed error code."""
    # Count IP rows, not host strings: overlapping addresses in different VRFs
    # share a host string but are still two addresses.
    addresses = [str(address.address.ip) for address in service.ipaddresses.all()]
    if not addresses:
        return ServiceConnection(error=ERROR_NO_IP)
    if len(addresses) > 1:
        return ServiceConnection(error=ERROR_MULTIPLE_IPS)
    ports = _tcp_ports(service.port_mappings)
    if not ports:
        return ServiceConnection(error=ERROR_NO_TCP_PORT)
    if len(ports) > 1:
        return ServiceConnection(error=ERROR_MULTIPLE_TCP_PORTS)
    return ServiceConnection(host=addresses[0], port=ports[0])
