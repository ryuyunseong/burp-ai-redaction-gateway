from __future__ import annotations

import socket
from http.server import ThreadingHTTPServer


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    # Windows allows overlapping listeners with SO_REUSEADDR; do not share a port.
    allow_reuse_address = not hasattr(socket, "SO_EXCLUSIVEADDRUSE")

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()
