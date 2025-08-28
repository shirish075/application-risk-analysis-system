from flask import Flask, jsonify, request
import threading
import psutil
import hashlib
import requests
import time
import ollama
import socket
from datetime import datetime
import pandas as pd
import asyncio

app = Flask(__name__)

# CONFIG
VIRUSTOTAL_API_KEY = "ffbc3e4aa3244075b443648bb3bea48db17bc691623e00016075717a3160c055"
OLLAMA_MODEL = "llama3.2:3b"
SCAN_INTERVAL = 5
LOG_FILE = "risk_analysis.log"
WHITELIST = {"System Idle Process", "csrss.exe", "svchost.exe", "pet.exe"}
AUTO_KILL_HARMFUL = True

process_log_data = []
scanned_hashes = set()
monitoring = False
process_table = []

# Hashing
def compute_file_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# VirusTotal Check
def check_virustotal(process_name):
    url = f"https://www.virustotal.com/api/v3/search?query={process_name}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and 'data' in response.json():
            return "Suspicious or Harmful"
    except Exception as e:
        return "Safe"
    return "Safe"

# Process Monitor (running in background thread)
def monitor_processes():
    global monitoring, process_log_data
    previous_pids = set()
    while monitoring:
        current_pids = {p.pid for p in psutil.process_iter()}
        new_pids = current_pids - previous_pids
        previous_pids = current_pids

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.pid not in new_pids:
                continue

            name = proc.info['name']
            if name in WHITELIST:
                continue

            path = proc.info.get('exe', '')
            file_hash = compute_file_hash(path)

            if file_hash and file_hash in scanned_hashes:
                continue
            if file_hash:
                scanned_hashes.add(file_hash)

            vt_result = check_virustotal(name)
            process_log_data.append({"pid": proc.pid, "name": name, "risk": vt_result})

        time.sleep(SCAN_INTERVAL)

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global monitoring
    if not monitoring:
        monitoring = True
        thread = threading.Thread(target=monitor_processes)
        thread.daemon = True
        thread.start()
        return jsonify({"status": "Monitoring started"}), 200
    return jsonify({"status": "Monitoring already running"}), 400

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global monitoring
    monitoring = False
    return jsonify({"status": "Monitoring stopped"}), 200

@app.route('/get_process_log', methods=['GET'])
def get_process_log():
    return jsonify(process_log_data), 200

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    target_host = request.json.get('target_host', '127.0.0.1')
    start_port = request.json.get('start_port', 1)
    end_port = request.json.get('end_port', 100)
    open_ports = []

    async def scan_open_ports(host, port_range):
        nonlocal open_ports
        for port in range(port_range[0], port_range[1] + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((host, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass

    asyncio.run(scan_open_ports(target_host, (start_port, end_port)))

    return jsonify({"open_ports": open_ports}), 200

if __name__ == '__main__':
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5000)
