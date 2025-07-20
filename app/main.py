from fastapi import FastAPI
from app.faiss_search import search_vector

app = FastAPI()

@app.get("/search/")
def search(query: str):
    results = search_vector(query)
    return {"results": results}

