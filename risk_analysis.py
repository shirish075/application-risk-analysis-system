import streamlit as st
import psutil
import requests
import time
import hashlib
import ollama
import socket
from duckduckgo_search import DDGS
from datetime import datetime
import pandas as pd
import threading
import queue

# CONFIG
VIRUSTOTAL_API_KEY = "ffbc3e4aa3244075b443648bb3bea48db17bc691623e00016075717a3160c055"
OLLAMA_MODEL = "llama3.2:3b"
SCAN_INTERVAL = 5
LOG_FILE = "risk_analysis.log"
WHITELIST = {"System Idle Process", "csrss.exe", "svchost.exe", "pet.exe"}
AUTO_KILL_HARMFUL = True



scanned_hashes = set()

# Utilities
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    log_queue.put(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

# Function to periodically update st.session_state.logs from the log queue
def update_logs():
    while not log_queue.empty():
        entry = log_queue.get()
        st.session_state.logs += entry + "\n"

def compute_file_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def check_virustotal(process_name):
    log(f"[VT] Checking VirusTotal for: {process_name}")
    url = f"https://www.virustotal.com/api/v3/search?query={process_name}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and 'data' in response.json():
            return "Suspicious or Harmful"
    except Exception as e:
        log(f"[VT] Error: {e}")
    return "Safe"

def get_search_snippets(query, max_results=5):
    snippets = []
    with DDGS() as ddgs:
        results = ddgs.text(query, max_results=max_results)
        for r in results:
            if "body" in r:
                snippets.append(r["body"])
    return snippets

def assess_with_llm(process_name, snippets):
    context = "\n".join(f"- {s}" for s in snippets)
    prompt = f"""
You are a cybersecurity assistant.
Classify the process '{process_name}' as Safe, Suspicious, or Harmful based on the context.
Also, explain in 1-2 sentences why you classified it that way.

Return exactly:
Verdict: <Safe/Suspicious/Harmful>
Reason: <short explanation>

Context:
{context}
"""
    try:
        response = ollama.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": prompt}])
        content = response['message']['content'].strip()
        verdict = "Error"
        reason = "Could not determine."
        for line in content.splitlines():
            if line.lower().startswith("verdict:"):
                verdict = line.split(":", 1)[1].strip()
            elif line.lower().startswith("reason:"):
                reason = line.split(":", 1)[1].strip()
        return verdict, reason
    except Exception as e:
        log(f"[LLM] Error: {e}")
        return "Error", "Error during LLM assessment."

# Core Analysis Logic
def analyze_process(proc):
    name = proc.info['name']
    if name in WHITELIST:
        return None

    path = proc.info.get('exe', '')
    file_hash = compute_file_hash(path)

    if file_hash and file_hash in scanned_hashes:
        return None
    if file_hash:
        scanned_hashes.add(file_hash)

    vt_result = check_virustotal(name)
    snippets = get_search_snippets(name)
    verdict, reason = assess_with_llm(name, snippets)

    if verdict == "Harmful" and AUTO_KILL_HARMFUL:
        try:
            proc.kill()
        except Exception as e:
            log(f"[KILL] Failed to terminate {name}: {e}")

    return {"PID": proc.pid, "Process": name, "Risk": verdict, "Reason": reason}

# Monitoring Functions
# Create a thread-safe dictionary for shared state
shared_state = {
    "process_monitoring": False,
    "network_monitoring": False
}
state_lock = threading.Lock()

# Create a thread-safe queue for process data
process_data_queue = queue.Queue()

# Update monitor_processes to use the thread-safe queue
def monitor_processes():
    previous_pids = set()
    while True:
        with state_lock:
            if not shared_state["process_monitoring"]:
                break

        current_pids = {p.pid for p in psutil.process_iter()}
        new_pids = current_pids - previous_pids
        previous_pids = current_pids

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.pid not in new_pids:
                continue
            result = analyze_process(proc)
            if result:
                process_data_queue.put(result)
        time.sleep(SCAN_INTERVAL)

# Function to periodically update st.session_state.process_data from the queue
def update_process_data():
    while not process_data_queue.empty():
        result = process_data_queue.get()
        st.session_state.process_data.append(result)

# Update monitor_network to use the thread-safe shared state
def monitor_network(host="127.0.0.1", port_range=(1, 1024)):
    while True:
        with state_lock:
            if not shared_state["network_monitoring"]:
                break

        open_ports = []
        for port in range(port_range[0], port_range[1] + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)

        network_info = []
        for port in open_ports:
            pid = "-"
            process_name = "-"
            risk = "Unknown"
            reason = "-"

            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr.port == port and conn.status == "LISTEN":
                    pid = conn.pid
                    try:
                        p = psutil.Process(pid)
                        process_name = p.name()
                        if process_name not in WHITELIST:
                            snippets = get_search_snippets(process_name)
                            risk, reason = assess_with_llm(process_name, snippets)
                        else:
                            risk = "Safe"
                            reason = "Whitelisted system process."
                    except Exception as e:
                        process_name = "Unknown"
                        risk = "Error"
                        reason = str(e)
                    break

            network_info.append({
                "Port": port,
                "PID": pid,
                "Process": process_name,
                "Risk": risk,
                "Reason": reason
            })
        st.session_state.network_data = network_info
        time.sleep(SCAN_INTERVAL)

# Ensure `log_queue` is defined globally
log_queue = queue.Queue()

# Define the `initialize_session_state` function to initialize session state attributes
def initialize_session_state():
    if 'process_monitoring' not in st.session_state:
        st.session_state.process_monitoring = False
    if 'network_monitoring' not in st.session_state:
        st.session_state.network_monitoring = False
    if 'process_data' not in st.session_state:
        st.session_state.process_data = []
    if 'network_data' not in st.session_state:
        st.session_state.network_data = []
    if 'logs' not in st.session_state:
        st.session_state.logs = ""

# Ensure session state attributes are initialized globally at the start of the script
initialize_session_state()

# Streamlit App
def main():
    st.set_page_config(layout="wide")

    st.title("🧠 AI Risk Analyzer: Processes & Network")
    tabs = st.tabs(["🖥 Process Monitor", "🌐 Network Scanner", "🔍 Manual Check", "📄 Logs"])

    with tabs[0]:
        st.subheader("Live Process Risk Table")
        if st.button("Start Process Monitoring"):
            with state_lock:
                shared_state["process_monitoring"] = True
            threading.Thread(target=monitor_processes, daemon=True).start()

        if st.button("Stop Process Monitoring"):
            with state_lock:
                shared_state["process_monitoring"] = False

        if st.session_state.process_data:
            df = pd.DataFrame(st.session_state.process_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No data yet. Click Start.")

    with tabs[1]:
        st.subheader("Live Network & Port Scanner")
        target_host = st.text_input("Target IP address or hostname", "127.0.0.1")
        start_port = st.number_input("Start port", min_value=1, max_value=65535, value=1)
        end_port = st.number_input("End port", min_value=1, max_value=65535, value=100)

        if st.button("Start Network Monitoring"):
            if not st.session_state.network_monitoring:
                st.session_state.network_monitoring = True
                threading.Thread(target=monitor_network, args=(target_host, (start_port, end_port)), daemon=True).start()

        if st.button("Stop Network Monitoring"):
            st.session_state.network_monitoring = False

        if st.session_state.network_data:
            df = pd.DataFrame(st.session_state.network_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No network data yet. Click Start.")

    with tabs[2]:
        st.subheader("Manual Process Name Check")
        process_name = st.text_input("Enter process name for manual analysis:")
        if st.button("Analyze Manually"):
            vt_result = check_virustotal(process_name)
            snippets = get_search_snippets(process_name)
            verdict, reason = assess_with_llm(process_name, snippets)
            st.markdown(f"**Final Verdict:** {verdict}")
            st.markdown(f"**Reason:** {reason}")

    with tabs[3]:
        st.subheader("Log Output")
        st.text_area("Logs", st.session_state.logs, height=400)

if __name__ == "__main__":
    main()
