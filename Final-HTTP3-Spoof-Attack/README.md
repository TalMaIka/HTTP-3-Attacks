# QUIC IP-Spoofing Proof of Concept

This repository demonstrates a **QUIC (HTTP/3) IP spoofing proof of concept** using Python.  
It includes:
- A basic QUIC HTTP/3 server implementation.
- A client mode to send legitimate QUIC requests.
- An attacker mode to send QUIC requests with a spoofed source IP.

⚠ **Disclaimer**  
This project is for educational and research purposes **only**.  
Do not use it on networks or systems without explicit permission.

---

## 📂 Project Structure

```

.
├── http3\_server.py           # QUIC HTTP/3 server
├── http3\_ip\_spoofing.py      # Client & attacker POC script
├── commands.txt              # Quick reference commands
└── tests/
├── ssl\_cert.pem          # Self-signed TLS certificate
└── ssl\_key.pem           # Private key for TLS

````

---

## 📋 Requirements

- Python **3.8+**
- [aioquic](https://github.com/aiortc/aioquic) library
- Root privileges for attacker mode (raw socket operations)
- OpenSSL (for generating certificates)

### Install dependencies
```bash
pip install aioquic
````

---

## 🔐 Generating TLS Certificates

If you don't already have the certificate and key:

```bash
mkdir -p tests
openssl req -new -x509 -days 365 -nodes \
    -out tests/ssl_cert.pem \
    -keyout tests/ssl_key.pem \
    -subj "/CN=localhost"
```

---

## 🚀 Usage

### 1️⃣ Start the QUIC HTTP/3 Server

```bash
python3 http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem
```

This starts the server on `localhost:4433`.

---

### 2️⃣ Run as a Legitimate Client

```bash
sudo python3 http3_ip_spoofing.py https://localhost:4433 --role client
```

Sends a normal QUIC request to the server.

---

### 3️⃣ Run as an Attacker (IP Spoofing)

```bash
sudo python3 http3_ip_spoofing.py https://localhost:4433 --role attacker --spoofed-ip 1.2.3.4 -X POST -d 'msg=hi' -H 'User-Agent: test'
```

* `--spoofed-ip` sets the fake source IP.
* `-X POST` specifies request method.
* `-d` sends request data.
* `-H` adds HTTP headers.

---

## 🧪 Testing

Run the above steps on a controlled lab environment to observe:

* Server logs for spoofed IP requests.
* Packet captures showing forged QUIC packets.

---

## ⚠ Legal & Ethical Notice

This code manipulates raw network packets.
**Only run this on networks you own or have permission to test.**
Unauthorized use may violate laws in your country.
