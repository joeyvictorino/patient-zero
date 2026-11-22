import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])


@app.get("/notes/{note_id}")
def get_note(note_id: int):
    # No check that the caller owns this note.
    return requests.get(f"https://records.internal/notes/{note_id}", verify=False).json()
