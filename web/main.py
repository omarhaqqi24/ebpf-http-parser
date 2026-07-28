from fastapi import FastAPI
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
def index():
    return {
        "status": "success",
        "message": "mantap"
    }

@app.post('/{id}')
def store(id: int):
    id_resp = 'cihuuuuyyy ' + str(id)
    return {
        "status": "success",
        "message": id_resp
    }