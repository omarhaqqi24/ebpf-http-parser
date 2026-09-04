import socket

HOST = "192.168.0.2"
PORT = 8000

padding = "A" * 1000

request = (
    "GET /admin?" + padding + " HTTP/1.1\r\n"
    "Host: 192.168.0.2:8000\r\n"
    "User-Agent: single-write-client\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode()

s = socket.create_connection((HOST, PORT))

print("sending one write:")
print(repr(request))
print("length:", len(request))

s.sendall(request)

response = s.recv(4096)

print("\nresponse:")
print(response.decode(errors="replace"))

s.close()