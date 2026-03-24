from __future__ import annotations

from concurrent import futures
import signal
import threading
import grpc

import control_plane_pb2_grpc as pb2_grpc

from .service import ControlPlaneService


STOP_EVENT = threading.Event()


def _handle_signal(signum, frame) -> None:
    STOP_EVENT.set()


def serve(host: str = "127.0.0.1", port: int = 50051) -> None:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_ControlPlaneServiceServicer_to_server(ControlPlaneService(), server)
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    print(f"GRPC_SERVER_STARTED {host}:{port}")

    try:
        while not STOP_EVENT.is_set():
            STOP_EVENT.wait(1.0)
    finally:
        server.stop(grace=3)
        print("GRPC_SERVER_STOPPED")


if __name__ == "__main__":
    serve()
