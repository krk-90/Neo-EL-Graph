from tools.RAG.ingest.processing import COLLECTION_NAME, get_chroma_store


def get_store(collection_name: str = COLLECTION_NAME, persist_directory: str | None = None):
    return get_chroma_store(
        collection_name=collection_name,
        persist_directory=persist_directory,
    )


def add_documents(documents, collection_name: str = COLLECTION_NAME, persist_directory: str | None = None):
    store = get_store(collection_name=collection_name, persist_directory=persist_directory)
    if documents:
        store.add_documents(documents)
    return store


def query(collection_name: str = COLLECTION_NAME, query: str = "", k: int = 4, persist_directory: str | None = None):
    if k <= 0:
        raise ValueError("k must be greater than zero.")
    store = get_store(collection_name=collection_name, persist_directory=persist_directory)
    if not query:
        return []
    return store.similarity_search(query, k=k)
