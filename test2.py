from langchain_ollama import OllamaLLM

model = OllamaLLM(model="gemma3:4b",temperature=0.7, max_tokens=1000)

print(model.invoke("Come up with 10 names for a song about parrots"))