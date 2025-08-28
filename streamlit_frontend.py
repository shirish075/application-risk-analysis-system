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
import logging

# CONFIG
VIRUSTOTAL_API_KEY = "ffbc3e4aa3244075b443648bb3bea48db17bc691623e00016075717a3160c055"
OLLAMA_MODEL = "llama3.2:3b"
SCAN_INTERVAL = 5
LOG_FILE = "risk_analysis.log"
WHITELIST = {"System Idle Process", "csrss.exe", "svchost.exe", "pet.exe"}
AUTO_KILL_HARMFUL = True
process_log_data = []
scanned_hashes = set()
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", handlers=[logging.StreamHandler()])

# Logging
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

# Hashing
def compute_file_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# VirusTotal
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

# DuckDuckGo search
def get_search_snippets(query, max_results=5):
    snippets = []
    retries = 3
    for attempt in range(retries):
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=max_results)
                for r in results:
                    if "body" in r:
                        snippets.append(r["body"])
                return snippets
        except Exception as e:
            log(f"[DuckDuckGo] Error on attempt {attempt + 1}: {e}")
            if attempt < retries - 1:
                time.sleep(2)  # Wait for 2 seconds before retrying
            else:
                log(f"[DuckDuckGo] Max retries reached for query: {query}")
    snippets.append("Error occurred while fetching search snippets after retries.") # Or return empty list
    return snippets

# LLM Assessment for Processes (Generic)
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

# Network scanner (Open Ports)
def assess_networking_with_llm(port, process_name, snippets):
    context = "\n".join(f"- {s}" for s in snippets)
    prompt = f"""
You are a cybersecurity assistant.
Classify the process '{process_name}' listening on port {port} as Safe, Suspicious, or Harmful based on the context.
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

# Network scanner (Open Ports)
def list_and_classify_open_ports():
    # Get all active network connections
    connections = psutil.net_connections(kind='inet')
    
    # Initialize process_log_data to store the classified ports
    process_log_data = []

    for conn in connections:
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            pid = conn.pid
            process_name = "-"
            risk = "Unknown"
            reason = "Unknown"

            try:
                # Get process name from pid
                p = psutil.Process(pid)
                process_name = p.name()
                query="{}'s {} is safe or not".format(process_name, port)
                snippet = get_search_snippets(query)
                # Check if the process is in the whitelist
                if process_name not in WHITELIST:
                    # If not whitelisted, classify it with the LLM function (replace with your function)
                    risk, reason = assess_networking_with_llm(port, process_name,snippets=snippet)
                else:
                    risk = "Safe"
                    reason = "Whitelisted system process."
            except Exception as e:
                process_name = "Unknown"
                risk = "Error"
                reason = str(e)

            # Add the data to the process_log_data list
            process_log_data.append([pid, process_name, port, risk, reason])

    return process_log_data

# Core analysis logic
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

    if verdict == "Suspicious":
        try:
            cpu_usage = proc.cpu_percent()
            memory_usage = proc.memory_info().rss
        except psutil.NoSuchProcess:
            log(f"[Process Gone] Process {name} (PID: {proc.pid}) disappeared.")
            return None  # Or return a default value indicating the process is gone

        # You could potentially add network usage here if you can easily get it

        extra_context_prompt = f"""
You are a cybersecurity assistant.
Re-evaluate the process '{name}' which was initially classified as Suspicious.
Consider the following resource usage to refine the classification as Safe, Suspicious, or Harmful.
Explain your reasoning in 1-2 sentences.

CPU Usage: {cpu_usage}%
Memory Usage: {memory_usage / (1024 * 1024):.2f} MB

Initial Reason: {reason}

Return exactly:
Verdict: <Safe/Suspicious/Harmful>
Reason: <short explanation incorporating resource usage>
"""
        try:
            response = ollama.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": extra_context_prompt}])
            content = response['message']['content'].strip()
            for line in content.splitlines():
                if line.lower().startswith("verdict:"):
                    verdict = line.split(":", 1)[1].strip()
                elif line.lower().startswith("reason:"):
                    reason = line.split(":", 1)[1].strip()
        except Exception as e:
            log(f"[LLM - Re-assess] Error: {e}")
            # Keep the initial suspicious verdict and reason in case of an error
    if name.lower() == "notepad.exe":
        verdict = "Harmful"
        reason = "Intentionally flagged note[].exe for auto-kill testing."


    if verdict == "Harmful" and AUTO_KILL_HARMFUL:
        try:
            proc.kill()
            log(f"[KILL] Terminated harmful process: {name} (PID: {proc.pid})")
        except Exception as e:
            log(f"[KILL] Failed to terminate {name} (PID: {proc.pid}): {e}")

    return {"pid": proc.pid, "name": name, "risk": verdict, "reason": reason, "cpu": proc.cpu_percent(), "memory": proc.memory_info().rss}
# Streamlit app
def main():
    st.set_page_config(layout="wide")
    st.title("🧠 AI Risk Analyzer: Processes & Network")
    
    tabs = st.tabs(["🖥 Process Monitor", "🌐 Network Scanner", "🔍 Manual Check", "📄 Logs"])

    # Flags to control process monitoring and network scanning
    monitoring_active = [False]
    network_scan_active = [False]

    # Process Monitor (with Start/Stop button)
    with tabs[0]:
        st.subheader("Live Process Risk Table")
        process_table = st.empty()
        previous_pids = set()
        process_log_data = []
        suspicious_processes_details = {}  

        start_process_monitoring = st.button("Start Process Monitoring")
        stop_process_monitoring = st.button("Stop Process Monitoring")

        if start_process_monitoring:
            monitoring_active[0] = True
            while monitoring_active[0]:
                current_pids = {p.pid for p in psutil.process_iter()}
                new_pids = current_pids - previous_pids
                previous_pids = current_pids

                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if proc.pid not in new_pids:
                        continue
                    result = analyze_process(proc)
                    if result:
                        process_log_data.append(result)

                        # Add suspicious processes to suspicious_processes_details
                        if result["risk"].lower() in ["suspicious", "harmful"]:
                            suspicious_processes_details[proc.pid] = {
                                "name": result["name"],
                                "reason": result["reason"]
                            }

                        # Update live process table
                        df = pd.DataFrame([{
                            "PID": p["pid"],
                            "Process": p["name"],
                            "Risk": p["risk"],
                            "Reason": p["reason"],
                            "CPU": p["cpu"],
                            "Memory": p["memory"]
                        } for p in process_log_data])
                        process_table.dataframe(df, use_container_width=True)

                    time.sleep(0.2)
                time.sleep(SCAN_INTERVAL)

        if stop_process_monitoring:
            monitoring_active[0] = False
            st.success("Process monitoring stopped.")

        if st.button("Show Details & Re-assess Suspicious Processes"):
            detailed_suspicious_table = st.empty()
            detailed_data = []

            if not suspicious_processes_details:
                detailed_suspicious_table.info("No suspicious processes found.")
            else:
                for pid, details in suspicious_processes_details.items():
                    try:
                        proc = psutil.Process(pid)
                        file_path = proc.exe()
                        cpu_usage = proc.cpu_percent(interval=0.1)
                        memory_usage = proc.memory_info().rss

                        re_assessment_prompt = f"""
    You are a cybersecurity expert.
    Re-evaluate the following process based on its details and the initial assessment.
    Provide a final verdict of "Safe" or "Not Safe". If "Not Safe", give 1-2 concise suggestions on what the user should do (e.g., investigate further, consider terminating).

    Process Name: {details['name']}
    PID: {pid}
    File Path: {file_path}
    CPU Usage: {cpu_usage}%
    Memory Usage: {memory_usage / (1024 * 1024):.2f} MB
    Initial LLM Assessment: {details['reason']}

    Return exactly:
    Final Verdict: <Safe/Not Safe>
    Suggestions: <1-2 concise suggestions if Not Safe>
    """
                        try:
                            response = ollama.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": re_assessment_prompt}])
                            content = response['message']['content'].strip()
                            final_verdict = "Unknown"
                            suggestions = "None"
                            for line in content.splitlines():
                                if line.lower().startswith("final verdict:"):
                                    final_verdict = line.split(":", 1)[1].strip()
                                elif line.lower().startswith("suggestions:"):
                                    suggestions = line.split(":", 1)[1].strip()

                            detailed_data.append({
                                "PID": pid,
                                "Process": details['name'],
                                "File Path": file_path,
                                "CPU Usage (%)": cpu_usage,
                                "Memory Usage (MB)": memory_usage / (1024 * 1024),
                                "Initial LLM Assessment": details['reason'],
                                "Final Verdict": final_verdict,
                                "Suggestions": suggestions,
                            })
                        except Exception as e:
                            log(f"[LLM - Final Assess] Error: {e}")
                            detailed_data.append({
                                "PID": pid,
                                "Process": details['name'],
                                "File Path": file_path,
                                "CPU Usage (%)": cpu_usage,
                                "Memory Usage (MB)": memory_usage / (1024 * 1024),
                                "Initial LLM Assessment": details['reason'],
                                "Final Verdict": "Error",
                                "Suggestions": "Could not re-assess.",
                            })

                    except psutil.NoSuchProcess:
                        detailed_data.append({
                            "PID": pid,
                            "Process": "Process Terminated",
                            "File Path": "N/A",
                            "CPU Usage (%)": "N/A",
                            "Memory Usage (MB)": "N/A",
                            "Initial LLM Assessment": details.get('reason', 'N/A'),
                            "Final Verdict": "N/A",
                            "Suggestions": "Process Terminated"
                        })

                if detailed_data:
                    df_detailed = pd.DataFrame(detailed_data)
                    detailed_suspicious_table.dataframe(df_detailed, use_container_width=True)

    # Network Scanner
    with tabs[1]:
        st.subheader("Live Network & Port Scanner")
        network_table_placeholder = st.empty()

        if "network_scan_active" not in st.session_state:
            st.session_state.network_scan_active = False
        if "live_network_data" not in st.session_state:
            st.session_state.live_network_data = []

        start_network_monitoring = st.button("Start Network Monitoring")
        stop_network_monitoring = st.button("Stop Network Monitoring")

        if start_network_monitoring:
            st.session_state.network_scan_active = True
            st.session_state.live_network_data = []  # Clear previous data
            st.success("Network monitoring started.")
            st.rerun()

        if stop_network_monitoring:
            st.session_state.network_scan_active = False
            st.success("Network monitoring stopped.")
            st.rerun()

        if st.session_state.network_scan_active:
            connections = psutil.net_connections(kind='inet')
            updated_data = []
            for conn in connections:
                if not st.session_state.network_scan_active:  # Allow stopping during scan
                    break
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    pid = conn.pid
                    process_name = "-"
                    risk = "Unknown"
                    reason = "Unknown"
                    try:
                        p = psutil.Process(pid)
                        process_name = p.name()
                        if process_name not in WHITELIST:
                            query = f"security risk {process_name} open port {port}"
                            snippets = get_search_snippets(query)
                            risk, reason = assess_networking_with_llm(port, process_name, snippets)
                        else:
                            risk = "Safe"
                            reason = "Whitelisted system process."
                    except Exception as e:
                        process_name = "Unknown"
                        risk = "Error"
                        reason = str(e)
                    updated_data.append({
                        "Port": port,
                        "PID": pid,
                        "Process": process_name,
                        "Risk": risk,
                        "Reason": reason
                    })
                    df = pd.DataFrame(updated_data)
                    network_table_placeholder.dataframe(df, use_container_width=True)
                    time.sleep(0.1)  # Small delay to visualize updates
            time.sleep(SCAN_INTERVAL)
            st.rerun()

        # Manual Check
# Manual Check
        with tabs[2]:
            st.subheader("Check Risk for a Process Name or File Hash")
            check_type = st.radio("Select Check Type:", ["Process Name", "File Hash"])

            if check_type == "Process Name":
                process_name = st.text_input("Enter process name")
                if st.button("Analyze Process"):
                    vt_result = check_virustotal(process_name)
                    snippets = get_search_snippets(process_name, max_results=7)  # Get more snippets for summary
                    verdict, reason = assess_with_llm(process_name, snippets)

                    st.subheader(f"Analysis for Process: {process_name}")
                    st.markdown(f"**VirusTotal Verdict:** {vt_result}")
                    st.markdown(f"**LLM Verdict:** {verdict}")
                    st.markdown(f"**LLM Reasoning:** {reason}")

                    if snippets:
                        st.subheader("Search Snippet Summary:")
                        summary_prompt = f"""
    You are a cybersecurity expert.
    Summarize the following search snippets related to the process '{process_name}' in 2-3 concise sentences, highlighting any potential risks or relevant information.

    Snippets:
    {' '.join(snippets)}
    """
                        try:
                            response = ollama.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": summary_prompt}])
                            summary = response['message']['content'].strip()
                            st.markdown(f"> {summary}")
                        except Exception as e:
                            st.error(f"Error generating snippet summary: {e}")
                    else:
                        st.info("No relevant search snippets found.")

            elif check_type == "File Hash":
                file_path = st.text_input("Enter file path for hash check (or upload file below)")
                uploaded_file = st.file_uploader("Or upload a file to analyze its hash", type=["*"])

                if uploaded_file:
                    file_bytes = uploaded_file.read()
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    st.info(f"SHA256 Hash of Uploaded File: {file_hash}")
                    if st.button("Analyze File Hash"):
                        vt_result = check_virustotal(file_hash)
                        snippets = get_search_snippets(file_hash, max_results=7) # Get more snippets for summary

                        st.subheader(f"Analysis for File Hash: {file_hash}")
                        st.markdown(f"**VirusTotal Verdict:** {vt_result}")

                        if snippets:
                            st.subheader("Search Snippet Summary:")
                            summary_prompt = f"""
    You are a cybersecurity expert.
    Summarize the following search snippets related to the file hash '{file_hash}' in 2-3 concise sentences, highlighting any potential risks or relevant information.

    Snippets:
    {' '.join(snippets)}
    """
                            try:
                                response = ollama.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": summary_prompt}])
                                summary = response['message']['content'].strip()
                                st.markdown(f"> {summary}")
                            except Exception as e:
                                st.error(f"Error generating snippet summary: {e}")
                        else:
                            st.info("No relevant search snippets found.")

                elif st.button("Analyze File Hash"):
                    if file_path:
                        file_hash = compute_file_hash(file_path)
                        if file_hash:
                            vt_result = check_virustotal(file_hash)
                            snippets = get_search_snippets(file_hash, max_results=7) # Get more snippets for summary

                            st.subheader(f"Analysis for File Hash: {file_hash}")
                            st.markdown(f"**VirusTotal Verdict:** {vt_result}")

                            if snippets:
                                st.subheader("Search Snippet Summary:")
                                summary_prompt = f"""
    You are a cybersecurity expert.
    Summarize the following search snippets related to the file hash '{file_hash}' in 2-3 concise sentences, highlighting any potential risks or relevant information.

    Snippets:
    {' '.join(snippets)}
    """
                                try:
                                    response = ollama.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": summary_prompt}])
                                    summary = response['message']['content'].strip()
                                    st.markdown(f"> {summary}")
                                except Exception as e:
                                    st.error(f"Error generating snippet summary: {e}")
                            else:
                                st.info("No relevant search snippets found.")
                        else:
                            st.error("Could not compute hash for the file.")
                    else:
                        st.error("Please provide a valid file path or upload a file.")                    
            # Log Output
            with tabs[3]:
                st.subheader("Log Output")
                with open(LOG_FILE, "r") as f:
                    logs = f.read()
                st.text_area("Log file", logs, height=400)

if __name__ == "__main__":
    main()
