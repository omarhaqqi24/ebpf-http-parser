import socket
import time

s = socket.create_connection(("192.168.0.2", 8000))

parts = [
    b"GET /ad",
    b"min HTTP/1.1\r\n",
    b"Host: 192.168.0.2:8001\r\n",
    b"User-Agent: fragmented-client\r\n",
    b"Connection: close\r\n",
    b"\r\n",
]

for part in parts:
    print("sending:", repr(part))
    s.sendall(part)
    time.sleep(0.5)

response = s.recv(4096)

print("response:")
print(response.decode(errors="replace"))

s.close()