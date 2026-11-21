"""
 backend.py - pluggable TPM command backends.

 A CommandBackend accepts encoded TPM2 command frames and returns encoded
 response frames. Two implementations are provided:

   * LocalCommandBackend: dispatches directly into an in-process SwtpmRA.
   * SocketCommandBackend: forwards frames over a UNIX domain socket to a
     SocketCommandServer hosting another SwtpmRA instance.

 Both backends share the same wire format, so PCR policies, quotes and
 state handling are backend-agnostic.
"""

import os
import socket
import struct
import threading

from .codec import CodecError, encode_response, TPM_RC_FAILURE


class BackendError(Exception):
    """Raised when a command cannot reach its backend."""


class CommandBackend:
    """Abstract command transport."""

    def send_command(self, frame):
        raise NotImplementedError

    def close(self):
        pass


class LocalCommandBackend(CommandBackend):
    """In-process backend; no copies cross any transport boundary."""

    def __init__(self, tpm):
        self.tpm = tpm

    def send_command(self, frame):
        return self.tpm.handle_frame(frame)

    def close(self):
        pass


def _recv_exact(connection, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise BackendError("connection closed before frame was complete")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_frame(connection, frame):
    connection.sendall(struct.pack(">I", len(frame)) + frame)


def _recv_frame(connection):
    header = _recv_exact(connection, 4)
    (size,) = struct.unpack(">I", header)
    if size == 0 or size > 16 * 1024 * 1024:
        raise BackendError("invalid frame length %d" % size)
    return _recv_exact(connection, size)


class SocketCommandBackend(CommandBackend):
    """UNIX-domain-socket client backend."""

    def __init__(self, socket_path, timeout=10.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._socket = None

    def _connect(self):
        if self._socket is None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect(self.socket_path)
            except OSError as exc:
                sock.close()
                raise BackendError(
                    "cannot connect to swtpm socket %s: %s"
                    % (self.socket_path, exc)
                ) from exc
            self._socket = sock
        return self._socket

    def send_command(self, frame):
        try:
            connection = self._connect()
            _send_frame(connection, frame)
            return _recv_frame(connection)
        except OSError as exc:
            self.close()
            try:
                connection = self._connect()
                _send_frame(connection, frame)
                return _recv_frame(connection)
            except OSError as retry_exc:
                self.close()
                raise BackendError(
                    "socket command failed: %s" % retry_exc
                ) from retry_exc
            except BackendError:
                self.close()
                raise
        except BackendError:
            self.close()
            raise

    def close(self):
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None


class SocketCommandServer:
    """Serves one SwtpmRA over a UNIX domain socket."""

    def __init__(self, tpm, socket_path, backlog=8):
        self.tpm = tpm
        self.socket_path = socket_path
        self.backlog = backlog
        self._server = None
        self._stopped = False

    def start(self):
        self._cleanup_stale_socket()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(self.backlog)
        server.settimeout(0.5)
        self._server = server
        return self

    def serve_forever(self):
        if self._server is None:
            self.start()
        while not self._stopped:
            try:
                connection, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle_connection,
                args=(connection,),
                daemon=True,
            )
            thread.start()

    def handle_one_connection(self, timeout=1.0):
        """Process a single pending connection (used by tests)."""
        if self._server is None:
            self.start()
        self._server.settimeout(timeout)
        try:
            connection, _ = self._server.accept()
        except socket.timeout:
            return False
        thread = threading.Thread(
            target=self._handle_connection,
            args=(connection,),
            daemon=True,
        )
        thread.start()
        thread.join(timeout=timeout)
        return True

    def stop(self):
        self._stopped = True
        if self._server is not None:
            try:
                self._server.close()
            finally:
                self._server = None
        self._cleanup_stale_socket()

    def _handle_connection(self, connection):
        with connection:
            try:
                while True:
                    try:
                        frame = _recv_frame(connection)
                    except BackendError:
                        break
                    try:
                        response = self.tpm.handle_frame(frame)
                    except CodecError as exc:
                        response = encode_response(
                            TPM_RC_FAILURE, str(exc).encode("utf-8")
                        )
                    try:
                        _send_frame(connection, response)
                    except OSError:
                        break
            except OSError:
                pass

    def _cleanup_stale_socket(self):
        try:
            os.remove(self.socket_path)
        except FileNotFoundError:
            pass


def backend_from_uri(uri, tpm=None):
    """Instantiate a backend from `local://` or `unix://<path>` URIs."""
    if uri in ("local://", "memory://"):
        if tpm is None:
            raise BackendError("local backend requires a SwtpmRA instance")
        return LocalCommandBackend(tpm)
    if uri.startswith("unix://"):
        return SocketCommandBackend(uri[len("unix://"):])
    raise BackendError("unsupported command backend URI: %r" % uri)
