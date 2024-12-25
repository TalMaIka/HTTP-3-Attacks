### Client Arguments and Capabilities:
The **HTTP/3 Client** (`http3_client.py`) supports the following command-line arguments and functionalities:

#### Arguments:
1. **`url`**: Specifies the URL(s) to query (must use HTTPS).
2. **`--ca-certs`**: Load CA certificates from a file.
3. **`--certificate`**: Load a TLS certificate from a file.
4. **`--cipher-suites`**: Restrict to specific cipher suites.
5. **`--congestion-control-algorithm`**: Specify the congestion control algorithm (default: `reno`).
6. **`-d`, `--data`**: Send data in a POST request.
7. **`-i`, `--include`**: Include HTTP response headers in the output.
8. **`--insecure`**: Skip server certificate validation.
9. **`--legacy-http`**: Use HTTP/0.9.
10. **`--max-data`**: Set connection-wide flow control limit.
11. **`--max-stream-data`**: Set per-stream flow control limit.
12. **`--negotiate-v2`**: Attempt to negotiate QUIC v2.
13. **`--output-dir`**: Specify directory for downloaded files.
14. **`--private-key`**: Load the TLS private key from a file.
15. **`-q`, `--quic-log`**: Log QUIC events to QLOG files.
16. **`-l`, `--secrets-log`**: Log secrets for debugging with Wireshark.
17. **`-s`, `--session-ticket`**: Specify a file for reading/writing session tickets.
18. **`-v`, `--verbose`**: Increase logging verbosity.
19. **`--local-port`**: Specify the local port for connections.
20. **`--max-datagram-size`**: Set the maximum datagram size (default provided).
21. **`--zero-rtt`**: Attempt to send requests using 0-RTT.

#### Capabilities:
- Perform **GET** and **POST** requests.
- Open and manage WebSocket connections.
- Process HTTP/3 server push.
- Configure QUIC and TLS options dynamically.
- Log detailed connection and data transmission metrics.

---

### Server Arguments and Capabilities:
The **HTTP/3 Server** (`http3_server.py`) offers the following arguments and features:

#### Arguments:
1. **`app`**: Specify the ASGI application as `<module>:<attribute>` (default: `demo:app`).
2. **`-c`, `--certificate`**: Load a TLS certificate from a file (required).
3. **`--congestion-control-algorithm`**: Specify the congestion control algorithm (default: `reno`).
4. **`--host`**: Set the listening address (default: `::`).
5. **`--port`**: Specify the listening port (default: `4433`).
6. **`-k`, `--private-key`**: Load the TLS private key from a file.
7. **`-l`, `--secrets-log`**: Log secrets for debugging with Wireshark.
8. **`--max-datagram-size`**: Set the maximum datagram size.
9. **`-q`, `--quic-log`**: Log QUIC events to QLOG files.
10. **`--retry`**: Enable retries for new connections.
11. **`-v`, `--verbose`**: Increase logging verbosity.

#### Capabilities:
- Serve HTTP/3 and WebSocket traffic.
- Handle **ASGI applications** for extensibility.
- Support **WebTransport** for advanced session management.
- Push HTTP responses proactively.
- Log and debug QUIC and TLS operations.
- Dynamically negotiate protocols such as HTTP/0.9, HTTP/3, and WebTransport.
- Utilize retry mechanisms for initial connection robustness.

---

Both the client and server are highly configurable, supporting dynamic adjustments for QUIC/TLS parameters, logging, and advanced connection handling mechanisms. Let me know if you want deeper insights or modifications.