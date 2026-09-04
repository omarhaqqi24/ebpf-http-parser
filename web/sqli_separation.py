import socket
import sys

HOST = "192.168.0.2"
PORT = 8000

REQUEST_SIZE = 6000
ATTACK = b"UNION SELECT"

offset = int(sys.argv[1])

prefix = b"A" * offset
suffix_len = REQUEST_SIZE - (
    len(b"GET /search?q=")
    + offset
    + len(ATTACK)
    + len(b" HTTP/1.1\r\nHost: 192.168.0.2:8000\r\nConnection: close\r\n\r\n")
)

if suffix_len < 0:
    raise ValueError("Attack offset is too large")

request = (
    b"GET /search?q="
    + prefix
    + ATTACK
    + (b"B" * suffix_len)
    + b" HTTP/1.1\r\n"
    + b"Host: 192.168.0.2:8000\r\n"
    + b"Connection: close\r\n"
    + b"\r\n"
)

print("Request length:", len(request))
print("Attack offset:", offset)

with socket.create_connection((HOST, PORT)) as connection:
    connection.sendall(request)
    response = connection.recv(4096)

print("Response:")
print(response.decode(errors="replace"))
