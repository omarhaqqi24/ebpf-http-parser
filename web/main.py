from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get('/')
def index(request: Request):
    headers = dict(request.headers)

    print("GET headers:")
    for name, value in headers.items():
        print(f"{name}: {value}")

    return {
        "status": "success",
        "message": "mantap",
        "headers": headers,
    }

@app.post('/{id}')
async def store(id: int, request: Request):
    headers = dict(request.headers)
    body = await request.body()

    print("POST headers:")
    for name, value in headers.items():
        print(f"{name}: {value}")

    print(f"POST body size: {len(body)} bytes")

    return {
        "status": "success",
        "message": "mantap",
        "headers": headers,
        "body_size": len(body),
        "response_data": "R" * 2000,
    }