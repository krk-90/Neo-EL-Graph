from agent.rag_agent import RAGAgent
from  tools.RAG.Retriever import retrieve
rag_agent = RAGAgent(
    model=model,
    retriever=retrieve,
)

result = rag_agent.ask(
    "Find critical remote code execution vulnerabilities."
)

print(result.answer.content)
print(result.sources)