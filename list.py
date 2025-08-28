import streamlit as st
import psutil
import requests
from langchain.chains import RetrievalQA
from langchain_community.llms import Ollama
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from sentence_transformers import SentenceTransformer

# API Keys
VIRUSTOTAL_API_KEY = "ffbc3e4aa3244075b443648bb3bea48db17bc691623e00016075717a3160c055"
SERPAPI_KEY = "YOUR_SERPAPI_API_KEY"  # Google Search API

# Initialize Ollama LLM
llm = Ollama(model="gemma3:4b")

# Initialize FAISS Vectorstore
try:
    # embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    # vectorstore = FAISS.from_texts(["Example process risk analysis data."], embeddings)
    # retriever = vectorstore.as_retriever()
    # qa = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

    # Create FAISS vectorstore
    vectorstore = FAISS.from_texts(["Example process risk analysis data."], embedding=embeddings)

    # Create retriever and RAG-based QA system
    retriever = vectorstore.as_retriever()
    qa = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)

except Exception as e:
    st.error(f"Error initializing FAISS: {e}")
    retriever = None
    qa = None


def get_running_processes():
    """Fetch list of running processes."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append(proc.info)
    return processes


def check_virustotal(process_name):
    """Check VirusTotal for process reputation."""
    url = f"https://www.virustotal.com/api/v3/search?query={process_name}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data']:
                return f"VirusTotal says: Suspicious or Harmful\n{data}"
        return "VirusTotal says: Safe"
    except Exception as e:
        return f"VirusTotal check failed for {process_name}: {e}"


def assess_risk_with_rag(process_name):
    """Use LangChain RAG to analyze the risk of a process."""
    if qa is None:
        return "RAG analysis unavailable"

    try:
        query = f"Is the process '{process_name}' safe?"
        response = qa.run(query)
        return f"Ollama (RAG) Analysis: {response}" if response else "Unknown"
    except Exception as e:
        return f"RAG analysis failed for {process_name}: {e}"


def google_search_risk(process_name):
    """Check Google Search for process risk information."""
    url = f"https://serpapi.com/search.json?q={process_name}+malware+threat&api_key={SERPAPI_KEY}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            results = data.get("organic_results", [])
            if results:
                return f"🔍 **Google Search Results:** {results[0]['snippet']}"
            return "Google Search found no risk reports."
        return "Google Search API error."
    except Exception as e:
        return f"Google Search failed: {e}"


def main():
    st.title("AI-Powered Risk Analysis for Running Processes")
    st.write("Scanning running processes and assessing risk...")

    processes = get_running_processes()
    process_data = []

    for process in processes:
        name = process['name']

        st.subheader(f"🔎 Analyzing: {name}")
        st.write(f"📌 **Process Name:** {name}")

        # Google Search Risk Analysis
        google_result = google_search_risk(name)
        st.write(f"🌍 **Google Search Analysis:** {google_result}")

        # VirusTotal
        vt_result = check_virustotal(name)
        st.write(f"🛡️ **VirusTotal Result:** {vt_result}")

        # Ollama (RAG-based) Analysis
        rag_result = assess_risk_with_rag(name)
        st.write(f"🤖 **Ollama AI Analysis:** {rag_result}")

        # Determine the final risk classification
        if "Harmful" in vt_result or "harmful" in rag_result or "malware" in google_result.lower():
            final_risk = "Harmful"
        elif "Suspicious" in rag_result or "Suspicious" in vt_result:
            final_risk = "Suspicious"
        elif "check failed" in vt_result or "analysis failed" in rag_result:
            final_risk = "Error"
        else:
            final_risk = "Safe"

        # Store result for table
        process_data.append((process['pid'], name, google_result, vt_result, rag_result, final_risk))

        # Print final assessment
        st.write(f"⚠️ **Final Assessment:** {final_risk}")
        st.markdown("---")

    # Display results
    st.subheader("📊 **Process Risk Report**")
    st.write("""
    - ✅ **Safe**: No detected risks.
    - 🟡 **Suspicious**: Might require further investigation.
    - ❌ **Harmful**: Known threat detected.
    - ⚠️ **Error**: Risk analysis failed (API issue).
    """)

    for pid, name, google_result, vt_result, rag_result, risk in process_data:
        color = {
            "Safe": "#4CAF50",
            "Suspicious": "#FFC107",
            "Harmful": "#F44336",
            "Error": "#808080"
        }.get(risk, "#000000")

        st.markdown(
            f"<p style='color:{color}; font-size:16px;'>"
            f"🔹 PID {pid}: {name}<br>"
            f"🌍 Google Search: {google_result}<br>"
            f"🛡️ VirusTotal: {vt_result}<br>"
            f"🤖 Ollama AI: {rag_result}<br>"
            f"⚠️ **Final Risk:** {risk}"
            f"</p>",
            unsafe_allow_html=True
        )


if __name__ == "__main__":
    main()
