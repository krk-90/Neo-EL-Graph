import os
import chromadb
from langchain_chroma import Chroma
from tools.RAG.ingest import processing

local = processing.get_chroma_store(local=True)
cloud_client = chromadb.CloudClient(
    api_key=os.environ["CHROMA_API_KEY"],
    tenant=os.environ["CHROMA_TENANT"],
    database=os.environ["CHROMA_DATABASE"],
)
cloud = Chroma(
    client=cloud_client,
    collection_name=processing.COLLECTION_NAME,
    embedding_function=processing.get_embeddings(mode="local"),
)

total = local._collection.count()
for offset in range(0, total, 300):
    batch = local._collection.get(
        limit=min(300, total - offset),
        offset=offset,
        include=["documents", "metadatas"],
    )
    for start in range(0, len(batch["ids"]), 64):
        end = start + 64
        cloud.add_texts(
            texts=batch["documents"][start:end],
            metadatas=batch["metadatas"][start:end],
            ids=batch["ids"][start:end],
        )
    print(f"Uploaded {min(offset + len(batch['ids']), total)}/{total}")
