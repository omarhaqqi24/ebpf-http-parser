import socket

HOST = "192.168.0.2"
PORT = 8000

padding = "A" * 5000

request = (
    "GET /admin?" + padding + " HTTP/1.1\r\n"
    "Host: 192.168.0.2:8000\r\n"
    "User-Agent: single-write-client\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode()

s = socket.create_connection((HOST, PORT))

print("Sending ONE application write")
print("Request length:", len(request))

s.sendall(request)

response = s.recv(4096)

print("\nResponse:")
print(response.decode(errors="replace"))

s.close()