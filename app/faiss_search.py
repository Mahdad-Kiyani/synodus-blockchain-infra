import faiss
import numpy as np

def search_vector(query: str):
    dim = 128  # Aantal dimensies in de FAISS index

    # FAISS index inlezen (zorg dat faiss_index.index aanwezig is)
    index = faiss.read_index("faiss_index.index")

    # Dummy vector als placeholder voor een echte embedding
    vector = np.random.random((1, dim)).astype('float32')

    # Zoek top-5 dichtstbijzijnde vectors
    D, I = index.search(vector, k=5)

    return {"distances": D.tolist(), "indices": I.tolist()}

