import sys
import ssl
import threading
import struct

import logging
import errno

from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler

from base64 import b64encode
from hashlib import sha1

from thread import Server_Thread


LOGGER = logging.getLogger(__name__); logging.basicConfig()

FIN = 0x80
OPCODE = 0x0f
MASKED = 0x80
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT         = 0x1
OPCODE_BINARY       = 0x2
OPCODE_CLOSE_CONN   = 0x8
OPCODE_PING         = 0x9
OPCODE_PONG         = 0xA

CLOSE_STATUS = 1000
CLOSE_REASON = bytes("", encoding="utf-8")


class Samurai():

    def run_forever(self, threaded=False):
        return self._run_forever(threaded)

    def new_client(self, client, server):
        pass

    def del_client(self, client, server):
        pass


class Server(TCPServer, ThreadingMixIn, Samurai):

    allow_reuse_addr = True
    deamon_threads = True

    def __init__(self, host="127.0.0.1", port=0, logger_level=logging.WARNING, key=None, cert=None):
        TCPServer.__init__(self, (host, port), Handler)
        self.host = host
        self.port = self.socket.getsockname()[1]
        self.key = key
        self.cert = cert
        self.conn_clients = []
        self.id = 0
        self.thread = None
        self._deny_clients = False
        LOGGER.setLevel(logger_level)

    def _run_forever(self, threaded):
        cls_name = self.__class__.__name__
        try:
            LOGGER.info(f"Listening on port {self.port} for clients...")
            if not threaded:
                print("** debug ** running")
                self.thread = threading.current_thread()
                LOGGER.info(f"Running {cls_name} on the main thread.")
                super().serve_forever()
            else:
                self.deamon = True
                self.thread = Server_Thread(target=super().serve_forever, daemon=True, logger=LOGGER)
                LOGGER.info(f"Running {cls_name} on the {self.thread.getName()} thread.")
                self.thread.start()
        except KeyboardInterrupt:
            self.server_close(); LOGGER.info("Server closed.")
        except Exception as exc:
            LOGGER.error(str(exc), exc_info=True); sys.exit(1)

    def _msg_received_(self, handler, msg):
        self.message_received(self.find_client(handler), self, msg)

    def _ping_received_(self, handler, msg):
        handler.send_pong(msg)

    def _pong_received_(self, handler, msg): pass

    def _new_client_(self, handler):
        if self._deny_clients:
            status = self._deny_clients["status"]
            reason = self._deny_clients["reason"]
            handler.send_close(status, reason)
            self._terminate_client_handler(handler)
            return
        self.id += 1
        client = {
            "id": self.id,
            "handler": handler,
            "addr": handler.client_address
        }
        self.conn_clients.append(client)
        self.new_client(client, self)

    def _del_client_(self, handler):
        client = self.find_client(handler)
        self.del_client(client, self)
        if client in self.conn_clients:
            self.conn_clients.remove(client)

    def _unicast(self, client, msg):
        client["handler"].send_msg(msg)

    def _multicast(self, msg):
        for client in self.conn_clients:
            self._unicast(client, msg)

    def find_client(self, handler):
        for client in self.conn_clients:
            if client["handler"] == handler: return client

    def _terminate_client_handler(self, handler):
        handler.keep_alive = False
        handler.finish()
        handler.connection.close()

    def _terminate_client_handlers(self):
        for client in self.conn_clients:
            self._terminate_client_handler(client["handler"])

    def _shutdown_gracefully(self, status=CLOSE_STATUS, reason=CLOSE_STATUS):
        self.keep_alive = False
        self._disconnect_clients_gracefully(status, reason)
        self.server_close()
        self.shutdown()

    def _shutdown_abruptly(self):
        self.keep_alive = False
        self._disconnect_clients_abruptly()
        self.server_close()
        self.shutdown()

    def _disconnect_clients_gracefully(self, status=CLOSE_STATUS, reason=CLOSE_REASON):
        for client in self.conn_clients:
            client["handler"].send_close(status, reason)
        self._terminate_client_handlers()

    def _disconnect_clients_abruptly(self):
        self._terminate_client_handlers()

    def _deny_new_connections(self, status, reason):
        self._deny_clients = {
            "status": status,
            "reason": reason
        }

    def _allow_new_connections(self):
        self._deny_clients = False


class Handler(StreamRequestHandler):
    def __init__(self, socket, addr, server):
        self.server = server
        assert not hasattr(self, "_lock"), "_lock already exists"
        self._lock = threading.Lock()
        if server.key and server.cert:
            try:
                socket = ssl.wrap_socket(
                    socket, 
                    server_side=True, 
                    certfile=server.cert, 
                    keyfile=server.key
                )
            except: LOGGER.warning(f"SSL is not available. Are the paths {server.key} and {server.cert} correct?")
        StreamRequestHandler.__init__(self, socket, addr, server)

    def setup(self):
        StreamRequestHandler.setup(self)
        self.keep_alive = True
        self.handshake_done = False
        self.valid_client = False

    def handle(self):
        while self.keep_alive:
            if not self.handshake_done: self.handshake()
            elif self.valid_client: self.read_next_msg()

    def _read_bytes(self, num):
        return self.rfile.read(num)

    def read_next_msg(self):
        try:
            a, b = self._read_bytes(2)
        except ConnectionResetError as err:
            if err.errno == errno.ECONNRESET:
                LOGGER.info("Client closed the connection.")
                self.keep_alive = 0; return
            a, b = 0, 0
        except ValueError as err:
            a, b = 0, 0

        fin = a & FIN
        opcode = a & OPCODE
        masked = b & MASKED
        payload_len = b & PAYLOAD_LEN

        if not masked:
            LOGGER.warning("Client needs to be masked.")
            self.keep_alive = 0; return

        if opcode == OPCODE_CLOSE_CONN:
            LOGGER.info("Client asked to close connection.")
            self.keep_alive = 0; return
        elif opcode == OPCODE_CONTINUATION:
            LOGGER.warning("Continuation frames are not supported."); return
        elif opcode == OPCODE_BINARY:
            LOGGER.warning("Binary frames are not supported."); return
        elif opcode == OPCODE_TEXT:
            opcode_hdlr = self.server._message_received_
        elif opcode == OPCODE_PING:
            opcode_hdlr = self.server._ping_received_
        elif opcode == OPCODE_PONG:
            opcode_hdlr = self.server._pong_received_
        else:
            LOGGER.warning(f"Unknown opcode {opcode}")
            self.keep_alive = 0; return

        if payload_len == 126:
            payload_len = struct.unpack(">H", self.rfile.read(2))[0]
        elif payload_len == 127:
            payload_len = struct.unpack(">Q", self.rfile.read(8))[0]

        masks = self._read_bytes(4)
        msg_bytes = bytearray()

        for msg_byte in self._read_bytes(payload_len):
            msg_byte ^= masks[len(msg_bytes) % 4]
            msg_bytes.append(msg_byte)
        opcode_hdlr(self, msg_bytes.decode("utf-8"))

    def send_msg(self, message):
        self.send_text(message)

    def send_pong(self, message):
        self.send_text(message, OPCODE_PONG)

    def send_close(self, status=CLOSE_STATUS, reason=CLOSE_REASON):
        if status < CLOSE_STATUS or status > 1015:
            raise Exception(f"CLOSE_STATUS must be between 1000 and 1015, currently it is {status}.")
        
        header = bytearray()
        payload = struct.pack("!H", status) + reason
        payload_len = len(payload)
        assert payload_len < 126, "Long closing reasons are not supported."

        header.append(FIN | OPCODE_CLOSE_CONN)
        header.append(payload_len)
        with self._lock: self.request.send(header + payload)

    def send_text(self, message, opcode=OPCODE_TEXT):
        if isinstance(message, bytes):
            message = decode_UTF8(message)
            if not message:
                LOGGER.warning("Cannot send message as it is not valid UTF-8."); return False
        elif not isinstance(message, str):
            LOGGER.warning("Cannot send message, because it has to be a string or bytes."); return False

        header = bytearray()
        payload = encode_UTF8(message)
        payload_len = len(payload)

        if payload_len < 126:
            header.append(FIN | opcode)
            header.append(payload_len)
        elif payload_len > 125 and payload_len < 65536:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT16)
            header.extend(struct.pack(">H", payload_len))
        elif payload_len < 18446744073709551616:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT64)
            header.append(struct.pack(">Q", payload_len))
        else:
            raise Exception("Message is too big. Break it into smaller chunks."); return
        with self._lock: self.request.send(header + payload)

    def read_http_headers(self):
        headers = {}
        http_get = self.rfile.readline().decode().strip()
        assert http_get.upper().startswith("GET")
        while True:
            header = self.rfile.readline().decode().strip()
            if not header: break
            head, val = header.split(":", 1)
            headers[head.lower().strip()] = val.strip()
        return headers

    def handshake(self):
        headers = self.read_http_headers()
        try:
            assert headers["upgrade"].lower() == "websocket"
        except AssertionError:
            self.keep_alive = False; return

        try:
            key = headers["sec-websocket-key"]
        except KeyError as err:
            LOGGER.warning(f"Client tried to connect, but was missing a key: {err}")
            self.keep_alive = False; return

        response = self.make_handshake_response(key)
        with self._lock:
            self.handshake_done = self.request.send(response.encode())
        self.valid_client = True
        self.server._new_client(self)


    def finish(self):
        self.server._del_client_(self)

    @classmethod
    def make_handshake_response(cls, key):
        return \
            "HTTP/1.1 101 Switching Protocols\r\n"\
            "Upgrade: websocket\r\n"              \
            "Connection: Upgrade\r\n"             \
            "Sec-WebSocket-Accept: %s\r\n"        \
            "\r\n" % cls.calc_response_key(key)

    @classmethod
    def calc_response_key(cls, key):
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        hash = sha1(key.encode() + GUID.encode())
        response = b64encode(hash.digest()).strip()
        return response.decode("ASCII")


def encode_UTF8(data):
    try:
        return data.encode("UTF-8")
    except UnicodeEncodeError as err:
        LOGGER.error(f"Could not encode data to UTF-8: {err}"); return False
    except Exception as exc: raise(exc); return False

def decode_UTF8(data):
    try:
        return data.decode("UTF-8")
    except UnicodeDecodeError: return False
    except Exception as exc: raise(exc)