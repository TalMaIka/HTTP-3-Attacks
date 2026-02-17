# HTTP/3 Security Research – 0-RTT IP Spoofing Attack

This repository gathers the results of a research project focusing on HTTP/3 and QUIC security. It includes an in-depth analysis of the risks introduced by the 0-RTT early data mechanism and a working proof-of-concept demonstrating an IP spoofing attack that can bypass traditional server-side filtering.

## Overview

HTTP/3, built on the QUIC transport protocol, introduces several improvements in performance, latency, and connection handling. However, features like 0-RTT allow clients to send application data before the handshake completes—creating new security challenges.

This project shows how an attacker can exploit this mechanism by reusing a session ticket and spoofing the UDP source IP address. This enables unauthorized access to endpoints protected by IP-based filtering, even before the server has completed client verification.

## Contributions

- Implementation of a 0-RTT IP spoofing attack using a modified QUIC client based on the `aioquic` library.
- Separation of roles into two modes: a legitimate client (to collect session tickets) and an attacker (to send spoofed early data).
- A technical report analyzing the vulnerability, attack workflow, real-world implications, and potential defenses.
- Summarized readings of key academic papers and RFCs on HTTP/3 and QUIC security.

## Available Materials

- The complete source code of the attack client (client and attacker roles)
- A PDF version of the final academic paper
- Summaries of related academic work and RFC standards

## Academic Paper

The PDF version of the paper can be found here:
[HTTP3_0rtt_spoofing_paper.pdf](http3_0rtt_ip_spoofing_study.pdf)

It includes:

- A technical introduction to HTTP/3 and QUIC
- Review of known vulnerabilities and related work
- Full documentation of the 0-RTT spoofing attack
- Screenshots, packet traces, and source code explanation
- Recommendations and future research directions

## Disclaimer

This repository is intended strictly for academic and research purposes. Do not use the attack code against any system without explicit permission. The purpose of this work is to raise awareness and support the development of better defenses for HTTP/3 deployments.

## Author

Yann Chicheportiche and Tal Malka 
Ariel University , Israel. 
