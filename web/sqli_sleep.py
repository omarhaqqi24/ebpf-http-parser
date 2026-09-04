import socket
import time

HOST = "192.168.0.2"
PORT = 8000

part1 = (
    b"GET /search?q="
    + b"A" * 100
    + b"UNION SE"
)

part2 = (
    b"LECT"
    + b"B" * 100
    + b" HTTP/1.1\r\n"
    + b"Host: 192.168.0.2:8000\r\n"
    + b"Connection: close\r\n"
    + b"\r\n"
)

with socket.create_connection((HOST, PORT)) as s:

    print("Sending part 1:", len(part1))
    s.sendall(part1)

    time.sleep(1)

    print("Sending part 2:", len(part2))
    s.sendall(part2)

    print(s.recv(4096).decode(errors="replace"))