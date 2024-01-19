# Simple PostgreSQL Honeypot Server

## Introduction
The Simple PostgreSQL Honeypot Server is a script developed for cybersecurity professionals and hobbyists to analyze PostgreSQL-based network interactions. Written in Python and leveraging the Twisted framework, this script emulates a PostgreSQL server to log unauthorized access attempts and credentials. This tool is invaluable for understanding PostgreSQL vulnerabilities and potential intrusion strategies.

## Features
- **Low-Interaction Honeypot**: Effectively simulates a PostgreSQL server to log authentication attempts in a safe environment.
- **Configurable Settings**: Customize host and port settings via command-line arguments for flexibility.
- **Extensive Logging**: Captures every interaction, including usernames, passwords, and database names.
- **Real-Time Activity Monitoring**: Instantly logs and reports PostgreSQL activities for timely anomaly detection.
- **Educational and Research Tool**: Ideal for learning about PostgreSQL security weaknesses and network reconnaissance.

## Requirements
- Python 3.x
- Twisted Python library

## Installation
To set up the PostgreSQL honeypot server, follow these steps:

```bash
git clone https://github.com/0xNslabs/postgresql-honeypot.git
cd postgresql-honeypot
pip install twisted
```

## Usage
Run the server with optional arguments for host and port. Defaults to binding on all interfaces (0.0.0.0) at port 5432.

```bash
python3 psql.py --host 0.0.0.0 --port 5432
```

## Logging
Interaction logs are stored in postgresql_honeypot.log, offering detailed records of all PostgreSQL queries, login attempts, and credentials used.

## Simple PostgreSQL Honeypot In Action
![Simple PostgreSQL Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/postgresql-honeypot/main/PoC.png)
*This image illustrates the Simple PostgreSQL Honeypot Server capturing real-time PostgreSQL queries and login attempts.*

## Other Simple Honeypot Services

Check out the other honeypot services for monitoring various network protocols:

- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: Operate this honeypot within secure, controlled settings for research and learning purposes.
- **Compliance**: Deploy this honeypot in accordance with local and international legal and ethical standards.

## License
This project is available under the MIT License. See the LICENSE file for more information.
