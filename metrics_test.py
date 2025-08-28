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
import numpy as np

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

# Set page config as the very first Streamlit command
st.set_page_config(layout="wide")

# Global variables for metrics
items_processed_count = 0
total_processing_time = 0
total_scan_time_value = 0
api_lookup_success = 0
api_lookup_attempts = 0
memory_usage_values = []
cpu_usage_peak = 0
cpu_usage_values = []
processing_times = []
throughput_data = []
scan_start_time = None

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
    global api_lookup_success, api_lookup_attempts
    log(f"[VT] Checking VirusTotal for: {process_name}")
    url = f"https://www.virustotal.com/api/v3/search?query={process_name}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    api_lookup_attempts += 1
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and 'data' in response.json():
            api_lookup_success += 1
            return "Suspicious or Harmful"
    except Exception as e:
        log(f"[VT] Error: {e}")
    return "Safe"

# DuckDuckGo search
# Updated to handle DuckDuckGoSearchException and retry after a delay
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
    snippets.append("Error occurred while fetching search snippets after retries.")
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
                query = f"{process_name}'s {port} is safe or not"
                snippet = get_search_snippets(query)
                # Check if the process is in the whitelist
                if process_name not in WHITELIST:
                    # If not whitelisted, classify it with the LLM function (replace with your function)
                    risk, reason = assess_networking_with_llm(port, process_name, snippet)
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
    global items_processed_count, total_processing_time, cpu_usage_peak, cpu_usage_values, memory_usage_values, processing_times

    start_time = time.time()
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

    end_time = time.time()
    processing_time = end_time - start_time
    processing_times.append(processing_time)
    print(f"Process: {name}, Time Taken: {processing_time:.2f} seconds")  # Print time taken by each process

    total_processing_time += processing_time
    items_processed_count += 1
    print(f"Processed: {name}, Count: {items_processed_count}")  # Debug print
    print("\n--- Processing Metrics ---")
    print(f"Total Items Processed: {items_processed_count}")
    print(f"Average Processing Time: {total_processing_time / items_processed_count if items_processed_count > 0 else 0:.2f} seconds")
    print(f"Total Scan Time: {total_scan_time_value:.2f} seconds")
    print(f"API Lookup Success Rate: {(api_lookup_success / api_lookup_attempts * 100) if api_lookup_attempts > 0 else 0:.2f}%")
    print(f"Memory Usage (Avg): {np.mean(memory_usage_values) / (1024 * 1024) if memory_usage_values else 0:.2f} MB")
    print(f"CPU Usage (Peak/Avg): {cpu_usage_peak:.2f}% / {np.mean(cpu_usage_values) if cpu_usage_values else 0:.2f}%")
    print(f"Throughput: {throughput_data[-1]['Throughput']:.2f} items/second" if throughput_data else "Throughput: 0 items/second")
    print(f"Average Time per Item: {total_processing_time / items_processed_count if items_processed_count > 0 else 0:.2f} seconds")
    print("--------------------------\n")

    try:
        cpu_percent = proc.cpu_percent()
        cpu_usage_values.append(cpu_percent)
        cpu_usage_peak = max(cpu_usage_peak, cpu_percent)
        memory_usage_values.append(proc.memory_info().rss)
        return {"pid": proc.pid, "name": name, "risk": verdict, "reason": reason, "cpu": cpu_percent, "memory": proc.memory_info().rss}
    except psutil.NoSuchProcess:
        return None

def update_metrics():
    global total_scan_time_value, scan_start_time
    print("update_metrics called")  # Debug print
    print(f"Items Count in update: {items_processed_count}")  # Debug print

    if items_processed_count > 0:
        avg_processing_time = total_processing_time / items_processed_count
        avg_time_per_item = avg_processing_time
    else:
        avg_processing_time = 0
        avg_time_per_item = 0

    if scan_start_time is None:
        scan_start_time = time.time()  # Initialize scan_start_time if not already set

    total_scan_time_value = time.time() - scan_start_time if scan_start_time else 0

    if api_lookup_attempts > 0:
        api_lookup_rate = (api_lookup_success / api_lookup_attempts) * 100
    else:
        api_lookup_rate = 0

    avg_memory = np.mean(memory_usage_values) if memory_usage_values else 0
    avg_cpu = np.mean(cpu_usage_values) if cpu_usage_values else 0

    if processing_times:
        processing_time_series = pd.Series(processing_times)
    else:
        processing_time_series = pd.Series([])

    # Debug logs for metrics
    print(f"Average Processing Time: {avg_processing_time}")
    print(f"Total Scan Time: {total_scan_time_value}")
    print(f"API Lookup Success Rate: {api_lookup_rate}")
    print(f"Average Memory Usage: {avg_memory}")
    print(f"CPU Usage (Avg): {avg_cpu}")

    # Update Streamlit placeholders
    total_items_processed_placeholder.metric("Total Items Processed", items_processed_count)
    avg_processing_time_placeholder.metric("Average Processing Time", f"{avg_processing_time:.2f} seconds")
    total_scan_time_placeholder.metric("Total Scan Time", f"{total_scan_time_value:.2f} seconds")
    api_lookup_success_rate_placeholder.metric("API Lookup Success Rate", f"{api_lookup_rate:.2f}%")
    avg_memory_usage_placeholder.metric("Memory Usage (Avg)", f"{avg_memory / (1024 * 1024):.2f} MB")
    cpu_usage_placeholder.metric("CPU Usage (Peak/Avg)", f"{cpu_usage_peak:.2f}% / {avg_cpu:.2f}%")
    throughput_placeholder.metric("Throughput", f"{throughput_data[-1]['Throughput']:.2f} items/second" if throughput_data else "0 items/second")
    avg_time_per_item_placeholder.metric("Average Time per Item", f"{avg_time_per_item:.2f} seconds")

    # Debug log for throughput
    if throughput_data:
        print(f"Throughput (Last Batch): {throughput_data[-1]['Throughput']}")
    else:
        print("Throughput: 0 items/second")

    # Calculate and display throughput after one minute
    if scan_start_time and (time.time() - scan_start_time) >= 60:
        if processing_times:
            throughput = len(processing_times) / 60  # Calculate throughput as processes per minute
            print(f"Throughput: {throughput:.2f} processes per minute")
        else:
            print("Throughput: 0 processes per minute")

# Streamlit app
def main():
    st.title("🧠 AI Risk Analyzer: Processes & Network")

    tabs = st.tabs(["🖥 Process Monitor", "🌐 Network Scanner", "🔍 Manual Check", "📄 Logs"])

    # Placeholders for metrics
    metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
    metrics_col4, metrics_col5, metrics_col6 = st.columns(3)
    metrics_col7, metrics_col8 = st.columns(2)

    global total_items_processed_placeholder, avg_processing_time_placeholder, total_scan_time_placeholder, \
        api_lookup_success_rate_placeholder, avg_memory_usage_placeholder, cpu_usage_placeholder, \
        throughput_placeholder, avg_time_per_item_placeholder

    total_items_processed_placeholder = metrics_col1.empty()
    avg_processing_time_placeholder = metrics_col2.empty()
    total_scan_time_placeholder = metrics_col3.empty()
    api_lookup_success_rate_placeholder = metrics_col4.empty()
    avg_memory_usage_placeholder = metrics_col5.empty()
    cpu_usage_placeholder = metrics_col6.empty()
    throughput_placeholder = metrics_col7.empty()
    avg_time_per_item_placeholder = metrics_col8.empty()

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
            global scan_start_time, items_processed_count, total_processing_time, throughput_data, cpu_usage_peak, cpu_usage_values, memory_usage_values, processing_times
            scan_start_time = time.time()  # Initialize scan_start_time here
            print("time .time() in start_process_monitoring:", scan_start_time)  # Debug print
            items_processed_count = 0
            total_processing_time = 0
            throughput_data = []
            cpu_usage_peak = 0
            cpu_usage_values = []
            memory_usage_values = []
            processing_times = []
            while monitoring_active[0]:
                current_pids = {p.pid for p in psutil.process_iter()}
                new_pids = current_pids - previous_pids
                previous_pids = current_pids

                batch_start_time = time.time()
                processes_in_batch = 0
                current_batch_results = []
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if proc.pid not in new_pids:
                        continue
                    result = analyze_process(proc)
                    if result:
                        current_batch_results.append(result)
                        process_log_data.append(result)
                        processes_in_batch += 1
                        # Add suspicious processes to suspicious_processes_details
                        if result["risk"].lower() in ["suspicious", "harmful"]:
                            suspicious_processes_details[proc.pid] = {
                                "name": result["name"],
                                "reason": result["reason"]
                            }

                batch_end_time = time.time()
                batch_processing_time = batch_end_time - batch_start_time
                if processes_in_batch > 0 and batch_processing_time > 0:
                    throughput = processes_in_batch / batch_processing_time
                    throughput_data.append({"Batch Size": processes_in_batch, "Throughput": throughput})

                df = pd.DataFrame([
                    {
                        "PID":res["pid"],
                        "Name": res["name"],
                        "Risk": res["risk"],
                        "Reason": res["reason"],
                        "CPU (%)": f"{res['cpu']:.2f}",
                        "Memory (MB)": f"{res['memory'] / (1024 * 1024):.2f}",
                    }
                    for res in current_batch_results
                ])
                process_table.dataframe(df, height=300)
                # Print memory usage for individual processes
                for res in current_batch_results:
                    print(f"Process: {res['name']} (PID: {res['pid']}), Memory Usage: {res['memory'] / (1024 * 1024):.2f} MB")

                # Print processing time and memory usage for each process
                for i, (cpu, memory, processing_time) in enumerate(zip(cpu_usage_values, memory_usage_values, processing_times)):
                    print(f"Process {i + 1}: CPU Usage: {cpu:.2f}%, Memory Usage: {memory / (1024 * 1024):.2f} MB, Processing Time: {processing_time:.2f} seconds")

                # After 20 items, calculate and print averages, then stop
                if len(cpu_usage_values) >= 20:
                    avg_cpu = sum(cpu_usage_values) / len(cpu_usage_values)
                    avg_memory = sum(memory_usage_values) / len(memory_usage_values)
                    avg_processing_time = sum(processing_times) / len(processing_times)
                    print(f"Average CPU Usage after 20 items: {avg_cpu:.2f}%")
                    print(f"Average Memory Usage after 20 items: {avg_memory / (1024 * 1024):.2f} MB")
                    print(f"Average Processing Time after 20 items: {avg_processing_time:.2f} seconds")
                    monitoring_active[0] = False
                    break

                update_metrics()
                time.sleep(SCAN_INTERVAL)
        if stop_process_monitoring:
            monitoring_active[0] = False

        st.subheader("Details of Suspicious Processes")
        if suspicious_processes_details:
            suspicious_df = pd.DataFrame.from_dict(suspicious_processes_details, orient='index')
            st.dataframe(suspicious_df)
        else:
            st.info("No suspicious processes detected.")

    # Network Scanner (with Start/Stop button)
    with tabs[1]:
        st.subheader("Open Ports and Associated Processes")
        network_table = st.empty()
        start_network_scan = st.button("Start Network Scan")
        stop_network_scan = st.button("Stop Network Scan")

        if start_network_scan:
            network_scan_active[0] = True
            while network_scan_active[0]:
                open_ports_data = list_and_classify_open_ports()
                if open_ports_data:
                    df_network = pd.DataFrame(open_ports_data, columns=["PID", "Process Name", "Port", "Risk", "Reason"])
                    network_table.dataframe(df_network, height=300)
                else:
                    network_table.info("No listening ports found.")
                time.sleep(SCAN_INTERVAL)
        if stop_network_scan:
            network_scan_active[0] = False

    # Manual Check
    with tabs[2]:
        st.subheader("Manual Process Analysis")
        manual_process_name = st.text_input("Enter process name to manually check:")
        if st.button("Analyze Manually") and manual_process_name:
            vt_manual_result = check_virustotal(manual_process_name)
            snippets_manual = get_search_snippets(manual_process_name)
            verdict_manual, reason_manual = assess_with_llm(manual_process_name, snippets_manual)
            st.write(f"**VirusTotal Result:** {vt_manual_result}")
            st.write(f"**LLM Verdict:** {verdict_manual}")
            st.write(f"**LLM Reason:** {reason_manual}")

    # Logs
    with tabs[3]:
        st.subheader("Analysis Logs")
        try:
            with open(LOG_FILE, "r") as f:
                log_content = f.read()
                st.text_area("Logs", log_content, height=400)
        except FileNotFoundError:
            st.info("Log file not found.")

if __name__ == "__main__":
    main()