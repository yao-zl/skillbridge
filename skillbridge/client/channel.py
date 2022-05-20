from socket import socket, SOCK_STREAM, AF_INET
from select import select
from typing import Iterable, Union, Any, Type, TextIO
from sys import platform


class Channel:
    def __init__(self, max_transmission_length: int, token: str):
        self._max_transmission_length = max_transmission_length
        self._token = token

    def send(self, data: str) -> str:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        raise NotImplementedError

    def try_repair(self) -> Any:
        raise NotImplementedError

    @property
    def token(self) -> str:
        return self._token

    @token.setter
    def token(self, token: str) -> None:
        self._token = token

    @property
    def max_transmission_length(self) -> int:
        return self._max_transmission_length

    @max_transmission_length.setter
    def max_transmission_length(self, value: int) -> None:
        self._max_transmission_length = value

    def __del__(self) -> None:
        try:
            self.close()
        except BrokenPipeError:
            pass

    @staticmethod
    def decode_response(response: str) -> str:
        status, response = response.split(' ', maxsplit=1)

        if status == 'failure':
            if response == '<timeout>':
                raise RuntimeError(
                    "Timeout: you should restart the skill server and "
                    "increase the timeout `pyStartServer ?timeout X`."
                )
            elif response == '<token>':
                raise RuntimeError(
                    "Token: The server has enabled token authentication, "
                    "please provide the correct token when opening/reconnect the channel."
                )
            raise RuntimeError(response)
        return response


class DirectChannel(Channel):
    def __init__(self, stdout: TextIO):
        super().__init__(10_000, None)
        self.stdout = stdout

    def send(self, data: str) -> str:
        print(data.replace('\n', '\\n'), file=self.stdout, flush=True)
        return self.decode_response(input())

    def close(self) -> None:
        pass

    def flush(self) -> None:
        pass

    def try_repair(self) -> Any:
        pass


class TcpChannel(Channel):
    address_family = AF_INET
    socket_kind = SOCK_STREAM

    def __init__(self, address: Any, token: Any):
        super().__init__(1_000_000, token)

        self.connected = False
        self.address = self.create_address(address)
        if type(self.address) is str:
            from socket import AF_UNIX
            self.address_family = AF_UNIX
        self.socket = self.start()
        self._verify_token()

    @staticmethod
    def create_address(id_: Any) -> Any:
        id_ = 'default' if id_ is None else id_
        if type(id_) is int:
            return 'localhost', id_
        elif platform == 'win32':
            raise ValueError("UNIX Socket is not possible on Windows")
        else:
            return f'/tmp/skill-server-{id_}.sock'

    def start(self) -> socket:
        sock = self.create_socket()
        self.configure(sock)
        return self.connect(sock)

    def create_socket(self) -> socket:
        return socket(self.address_family, self.socket_kind)

    def configure(self, sock: socket) -> None:
        if type(self.address) is tuple:
            try:
                from socket import SIO_LOOPBACK_FAST_PATH  # type: ignore
                sock.ioctl(SIO_LOOPBACK_FAST_PATH, True)  # type: ignore
            except ImportError:
                pass

    def connect(self, sock: socket) -> socket:
        sock.settimeout(1)
        sock.connect(self.address)
        sock.settimeout(None)
        self.connected = True
        return sock

    def reconnect(self) -> None:
        self.socket.close()
        self.socket = self.start()
        self._verify_token()

    def _verify_token(self):
        if not self.token:
            return True
        try:
            result = self.send(self.token)
        except Exception as e:
            self.socket.close()
            self.connected = False
            raise e

    def _receive_all(self, remaining: int) -> Iterable[bytes]:
        while remaining:
            data = self.socket.recv(remaining)
            remaining -= len(data)
            yield data

    def _send_only(self, data: str) -> None:
        byte = data.encode()

        if len(byte) > self._max_transmission_length:
            got = len(byte)
            should = self._max_transmission_length
            raise ValueError(f'Data exceeds max transmission length {got} > {should}')

        length = '{:10}'.format(len(byte)).encode()

        try:
            self.socket.sendall(length)
        except (BrokenPipeError, OSError) as e:
            if self.token:
                raise RuntimeError(
                 "The connection is lost, please update the token and reconnect."
                ) from e
            print("attempting to reconnect")
            self.reconnect()
            self.socket.sendall(length)

        try:
            self.socket.sendall(byte)
        except (BrokenPipeError, OSError) as e:
            if self.token:
                raise RuntimeError(
                 "The connection is lost, please update the token and reconnect."
                ) from e
            print("attempting to reconnect")
            self.reconnect()
            self.socket.sendall(length)
            self.socket.sendall(byte)

    def _receive_only(self) -> str:
        try:
            received_length_raw = self.socket.recv(10)
        except KeyboardInterrupt:
            raise RuntimeError(
                "Receive aborted, you should restart the skill server or"
                " call `ws.try_repair()` if you are sure that the response"
                " will arrive."
            ) from None

        if not received_length_raw:
            raise RuntimeError("The server unexpectedly died")
        received_length = int(received_length_raw)
        response = b''.join(self._receive_all(received_length)).decode()

        return self.decode_response(response)

    def send(self, data: str) -> str:
        self._send_only(data)
        return self._receive_only()

    def try_repair(self) -> Union[Exception, str]:
        try:
            length = int(self.socket.recv(10))
            message = b''.join(self._receive_all(length))
        except Exception as e:
            return e
        return message.decode()

    def close(self) -> None:
        if self.connected:
            self.socket.sendall(b'         5close')
            self.socket.close()
            self.connected = False

    def flush(self) -> None:
        while True:
            read, _, _ = select([self.socket], [], [], 0.1)
            if read:
                length = int(self.socket.recv(10))
                self.socket.recv(length)
            else:
                break

