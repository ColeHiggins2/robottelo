import re
import socket
from collections import defaultdict
from textwrap import dedent

from cfme.fixtures.pytest_store import store
from cfme.utils.log import logger

# from cfme.utils.wait import wait_for
# from wrapanapi.entities.vm import Vm

_ports = defaultdict(dict)
_dns_cache = {}
ip_address = re.compile(
    r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}" r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def random_port(tcp=True):
    """Get a random port number for making a socket
    Args:
        tcp: Return a TCP port number if True, UDP if False
    This may not be reliable at all due to an inherent race condition. This works
    by creating a socket on an ephemeral port, inspecting it to see what port was used,
    closing it, and returning that port number. In the time between closing the socket
    and opening a new one, it's possible for the OS to reopen that port for another purpose.
    In practical testing, this race condition did not result in a failure to (re)open the
    returned port number, making this solution squarely "good enough for now".
    """
    # Port 0 will allocate an ephemeral port
    socktype = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, socktype) as s:
        s.bind(('', 0))
        addr, port = s.getsockname()
    return port


def my_ip_address(http=False):
    """Get the ip address of the host running tests using the service listed in cfme_data['ip_echo']
    The ip echo endpoint is expected to write the ip address to the socket and close the
    connection. See a working example of this in :py:func:`ip_echo_socket`.
    """
    # the pytest store does this work, it's included here for convenience
    return store.my_ip_address


def net_check(port, addr=None, force=False, timeout=10):
    """Checks the availability of a port"""
    port = int(port)
    if port not in _ports[addr] or force:
        # First try DNS resolution
        try:
            addr_info = socket.getaddrinfo(addr, port)[0]
            sockaddr = addr_info[4]
            addr = sockaddr[0]
            # Then try to connect to the port
            try:
                socket.create_connection(
                    (addr, port), timeout=timeout
                ).close()  # immediately close
            except OSError:
                _ports[addr][port] = False
            else:
                _ports[addr][port] = True
        except Exception:
            _ports[addr][port] = False
    return _ports[addr][port]


def net_check_remote(port, addr=None, machine_addr=None, ssh_creds=None, force=False):
    """Checks the availability of a port from outside using another machine (over SSH)"""
    from robottelo.ssh import SSHClient

    port = int(port)
    if not addr:
        addr = my_ip_address()
    if port not in _ports[addr] or force:
        if not machine_addr:
            machine_addr = store.current_appliance.hostname
        if not ssh_creds:
            ssh_client = store.current_appliance.ssh_client
        else:
            ssh_client = SSHClient(
                hostname=machine_addr,
                username=ssh_creds['username'],
                password=ssh_creds['password'],
            )
        with ssh_client:
            # on exception => fails with return code 1
            cmd = dedent(
                f'''\
            python3 -c "
            import sys, socket
            addr = socket.gethostbyname('{addr:s}')
            socket.create_connection((addr, {port:d}), timeout=10)
            sys.exit(0)
            "'''
            )
            result = ssh_client.run_command(cmd)
            _ports[addr][port] = result.success
            if not result.success:
                logger.debug(f'The net_check_remote failed:\n{result.output}')
    return _ports[addr][port]
