import os
import argparse
from struct import unpack
from twisted.internet import reactor, protocol, endpoints
from twisted.python import log

script_dir = os.path.dirname(os.path.abspath(__file__))

class SimplePostgreSQLProtocol(protocol.Protocol):
    def __init__(self):
        self.username = None

    def connectionMade(self):
        self.state = 'startup'
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"PostgreSQL NEW Connection - Client IP: {client_ip}, Port: {client_port}")
        self.transport.write(b'N')

    def dataReceived(self, data):
        if self.state == 'startup':
            self.handleStartupMessage(data)
        elif self.state == 'authentication':
            self.handleAuthenticationMessage(data)

    def handleStartupMessage(self, data):
        if len(data) < 8:
            return

        length, = unpack('!I', data[:4])
        if length > len(data):
            return 

        message_items = data[4:length].decode('utf-8', 'replace').split('\x00')
        startup_message = {}
        it = iter(message_items)
        for item in it:
            if item: 
                key = item
                value = next(it, '')
                startup_message[key] = value

        self.username = startup_message.get('user')
        self.database = startup_message.get('database')

        if self.username:
            log.msg(f"PostgreSQL Connection Startup - Username: {self.username}, Database: {self.database or 'Not provided'}")
            self.state = 'authentication'
            self.sendAuthenticationRequest()

    def handleAuthenticationMessage(self, data):
        if len(data) > 5 and data[0:1] == b'p':
            password = data[5:].decode('utf-8', 'replace').split('\x00')[0]
            log.msg(f"PostgreSQL Authentication - Password: {password}")
            self.sendAuthenticationFailure()

    def sendAuthenticationRequest(self):
        self.transport.write(b'R\x00\x00\x00\x08\x00\x00\x00\x03')

    def sendAuthenticationFailure(self):
        username_display = self.username if self.username else 'unknown'
        message_type = b'E'
        fields = [
            (b'S', b'FATAL'),
            (b'C', b'28P01'),
            (b'M', f"password authentication failed for user \"{username_display}\"".encode('utf-8')),
            (b'\x00', b'')
        ]
        message_content = b''.join([code + value + b'\x00' for code, value in fields])
        message_length = 4 + len(message_content)
        message = message_type + message_length.to_bytes(4, 'big') + message_content
        self.transport.write(message)
        self.transport.loseConnection()

class SimplePostgreSQLFactory(protocol.ServerFactory):
    protocol = SimplePostgreSQLProtocol

def main():
    parser = argparse.ArgumentParser(description='Run a simple PostgreSQL honeypot server.')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the PostgreSQL server to.')
    parser.add_argument('--port', type=int, default=5432, help='Port to bind the PostgreSQL server to.')
    args = parser.parse_args()

    LOG_FILE_PATH = os.path.join(script_dir, "postgresql_honeypot.log")
    print(f"PostgreSQL HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL access attempts will be logged in: {LOG_FILE_PATH}")
    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, 'a'))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    postgresql_factory = SimplePostgreSQLFactory()
    
    reactor.listenTCP(args.port, postgresql_factory, interface=args.host)
    reactor.run()

if __name__ == "__main__":
    main()
