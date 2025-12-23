import os
import argparse
from struct import unpack
from twisted.internet import reactor, protocol, endpoints
from twisted.python import log

script_dir = os.path.dirname(os.path.abspath(__file__))

class SimplePostgreSQLProtocol(protocol.Protocol):
    def __init__(self):
        self.username = None
        self.database = None
        self.state = "startup"
        self._buf = b""
        self._raw_log = True

    def connectionMade(self):
        self.state = "startup"
        self._buf = b""
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(
            f"PostgreSQL NEW Connection - Client IP: {client_ip}, Port: {client_port}"
        )
        f = getattr(self.factory, "raw_bytes_log", None)
        self._raw_log = True if f is None else bool(f)

    def dataReceived(self, data):
        if self._raw_log and data:
            log.msg(f"PostgreSQL RAW RECV: {data.hex()}")

        self._buf += data
        while True:
            if self.state == "startup":
                if len(self._buf) < 8:
                    return

                length = int.from_bytes(self._buf[0:4], "big", signed=False)
                code = int.from_bytes(self._buf[4:8], "big", signed=False)

                if length == 8 and code in (80877103, 80877104):
                    self._buf = self._buf[8:]
                    self._send_raw(b"N")
                    continue

                if length < 8:
                    self._buf = b""
                    self.transport.loseConnection()
                    return

                if len(self._buf) < length:
                    return

                msg = self._buf[:length]
                self._buf = self._buf[length:]
                self.handleStartupMessage(msg)
                continue

            if self.state == "authentication":
                if len(self._buf) < 5:
                    return

                mtype = self._buf[0:1]
                mlen = int.from_bytes(self._buf[1:5], "big", signed=False)
                total = 1 + mlen
                if mlen < 4:
                    self._buf = b""
                    self.transport.loseConnection()
                    return
                if len(self._buf) < total:
                    return

                payload = self._buf[5:total]
                self._buf = self._buf[total:]
                self.handleAuthenticationMessage(mtype, payload)
                continue

            return

    def handleStartupMessage(self, data):
        if len(data) < 8:
            return

        length = int.from_bytes(data[:4], "big", signed=False)
        if length > len(data):
            return

        proto = int.from_bytes(data[4:8], "big", signed=False)
        if proto == 80877102:
            self.transport.loseConnection()
            return

        payload = data[8:length]
        startup_message = {}
        try:
            parts = payload.split(b"\x00")
            if parts and parts[-1] == b"":
                parts = parts[:-1]
            for i in range(0, len(parts) - 1, 2):
                k = parts[i].decode("utf-8", "replace")
                v = parts[i + 1].decode("utf-8", "replace")
                if k:
                    startup_message[k] = v
        except Exception:
            startup_message = {}

        self.username = startup_message.get("user")
        self.database = startup_message.get("database")

        if self.username:
            log.msg(
                f"PostgreSQL Connection Startup - Username: {self.username}, Database: {self.database or 'Not provided'}"
            )
            self.state = "authentication"
            self.sendAuthenticationRequest()
        else:
            self.sendAuthenticationFailure()
            self.transport.loseConnection()

    def handleAuthenticationMessage(self, mtype, payload):
        if mtype == b"p":
            pw = payload
            if pw.endswith(b"\x00"):
                pw = pw[:-1]
            password = pw.decode("utf-8", "replace")
            log.msg(f"PostgreSQL Authentication - Password: {password}")
            self.sendAuthenticationFailure()
            self.transport.loseConnection()
            return

        self.sendAuthenticationFailure()
        self.transport.loseConnection()

    def _send_raw(self, bts):
        if self._raw_log and bts:
            log.msg(f"PostgreSQL RAW SEND: {bts.hex()}")
        confirm = bts
        self.transport.write(confirm)

    def sendAuthenticationRequest(self):
        self._send_raw(b"R\x00\x00\x00\x08\x00\x00\x00\x03")

    def sendAuthenticationFailure(self):
        username_display = self.username if self.username else "unknown"
        message_type = b"E"
        fields = [
            (b"S", b"FATAL"),
            (b"C", b"28P01"),
            (
                b"M",
                f'password authentication failed for user "{username_display}"'.encode(
                    "utf-8", "replace"
                ),
            ),
            (b"\x00", b""),
        ]
        message_content = b"".join([code + value + b"\x00" for code, value in fields])
        message_length = 4 + len(message_content)
        message = message_type + message_length.to_bytes(4, "big") + message_content
        self._send_raw(message)


class SimplePostgreSQLFactory(protocol.ServerFactory):
    protocol = SimplePostgreSQLProtocol

    def __init__(self, raw_bytes_log=True):
        self.raw_bytes_log = bool(raw_bytes_log)


def main():
    parser = argparse.ArgumentParser(
        description="Run a simple PostgreSQL honeypot server."
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind the PostgreSQL server to.",
    )
    parser.add_argument(
        "--port", type=int, default=5432, help="Port to bind the PostgreSQL server to."
    )
    parser.add_argument(
        "--raw-bytes-log",
        action="store_true",
        help="Enable raw bytes logging (recv/send).",
    )
    parser.add_argument(
        "--no-raw-bytes-log",
        action="store_true",
        help="Disable raw bytes logging (recv/send).",
    )
    args = parser.parse_args()

    raw_bytes_log = True
    if args.no_raw_bytes_log:
        raw_bytes_log = False
    if args.raw_bytes_log:
        raw_bytes_log = True

    LOG_FILE_PATH = os.path.join(script_dir, "postgresql_honeypot.log")
    print(f"PostgreSQL HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL access attempts will be logged in: {LOG_FILE_PATH}")
    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    postgresql_factory = SimplePostgreSQLFactory(raw_bytes_log=raw_bytes_log)

    reactor.listenTCP(args.port, postgresql_factory, interface=args.host)
    reactor.run()


if __name__ == "__main__":
    main()
