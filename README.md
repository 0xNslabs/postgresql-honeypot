# Simple PostgreSQL Honeypot Server

## Introduction
The Simple PostgreSQL Honeypot Server is a lightweight, low-interaction honeypot intended to capture and analyze PostgreSQL reconnaissance and authentication attempts. Written in Python using Twisted, it emulates enough of the PostgreSQL wire protocol to record startup parameters (e.g., user/database), password attempts, and optional raw byte streams for anomaly and potential zero-day protocol research.

## Features
- **Low-Interaction Honeypot**: Emulates PostgreSQL startup + authentication to capture credential attempts.
- **Protocol-Aware Parsing**: Handles framed PostgreSQL messages (startup + auth) and common SSL probe requests.
- **Raw Bytes Telemetry (Optional)**: Logs raw received and sent bytes in hex for deeper protocol analysis.
- **Configurable Settings**: Bind host/port via command-line flags.
- **Extensive Logging**: Records new connections, startup parameters, and password attempts in a single log file.

## Requirements
- Python 3.x
- Twisted (`pip install twisted`)

## Installation
```bash
git clone https://github.com/0xNslabs/postgresql-honeypot.git
cd postgresql-honeypot
pip install twisted
```

## Usage
By default, raw byte logging is enabled.

```bash
python3 postgresql.py --host 0.0.0.0 --port 5432
```

Disable raw byte logging (recommended if you expect high traffic and want smaller logs):

```bash
python3 postgresql.py --host 0.0.0.0 --port 5432 --no-raw-bytes-log
```

(You can also explicitly enable it with `--raw-bytes-log`.)

## Logging
Logs are written to `postgresql_honeypot.log` in the project directory and include:
- New connection events (client IP/port)
- Startup parameters (username, database)
- Password attempts
- Raw byte telemetry (hex), when enabled:
  - `PostgreSQL RAW RECV: ...`
  - `PostgreSQL RAW SEND: ...`

## Simple PostgreSQL Honeypot In Action
![Simple PostgreSQL Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/postgresql-honeypot/main/PoC.png)
*Example capture of PostgreSQL login attempts.*

## Other Simple Honeypot Services
- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot)
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot)
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot)
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot)
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot)
- [MongoDB Honeypot](https://github.com/0xNslabs/mongodb-honeypot)
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot)
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot)
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot)
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot)
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot)

## Security and Compliance
- **Caution**: Run honeypots in a controlled environment (segmented network, monitoring, no sensitive assets).
- **Compliance**: Ensure your deployment and data retention comply with applicable laws and internal policies.

## License
This project is distributed under the MIT License. See `LICENSE` for details.
