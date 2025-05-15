from flask import Flask, request, render_template
import time
import threading
import logging

app = Flask(__name__)

# Configure logging to show requests in the terminal
logging.basicConfig(level=logging.INFO)

# Global variables to track request count, defense state, overload state, and simulated load
request_count = 0
malicious_request_count = 0  # New variable to track only malicious requests
is_defending = False
resetting = False  # New flag to handle resetting state
lock = threading.Lock()

# Variables for monitoring request rates
REQUEST_THRESHOLD = 1000000 # Number of requests allowed in the time window
REQUEST_TIME_WINDOW = 60  # Time window in seconds
ip_request_count = {}  # Dictionary to track request counts by IP
blocklist = set()  # Set to track blocked IPs
whitelist = {"127.0.0.2"}  # Set of whitelisted IPs
local_ip = "127.0.0.2" # Local IP should not be blocked

@app.route("/")
def home():
    global request_count, malicious_request_count, is_defending, resetting, ip_request_count, blocklist, whitelist
    client_ip = request.remote_addr
    current_time = time.time()

    with lock:
        # If reset is in progress, skip overload handling
        if resetting:
            request_count = 0
            malicious_request_count = 0
            resetting = False
            logging.info("[Server] Resetting... All counters cleared.")
            return render_template("d_interface.html",
                                   message="Welcome to the Dummy Website! Server has been reset.",
                                   request_count=request_count,
                                   status="Normal",
                                   defense_status="OFF",
                                   defense_status_class="defense-off")

        # Skip tracking, blocking, and rate limiting for whitelisted IPs
        if client_ip in whitelist:
            logging.info(f"[Server] Request from whitelisted IP ({client_ip}) received and processed without blocking or rate limiting.")
            request_count += 1
            return render_template("d_interface.html",
                                   message="Welcome to the Dummy Website! Server is running fine.",
                                   request_count=request_count,
                                   status="Normal",
                                   defense_status="ON" if is_defending else "OFF",
                                   defense_status_class="defense-on" if is_defending else "defense-off")

        # Check if the IP is blocked
        if client_ip in blocklist:
            logging.info(f"[Defense] Request from blocked IP {client_ip} denied.")
            return "Request blocked by defense mechanism. You are on the blocklist.", 403

        # Track request counts per IP
        if client_ip not in ip_request_count:
            ip_request_count[client_ip] = {"count": 1, "last_request": current_time}
        else:
            # Update count and check rate limiting
            ip_data = ip_request_count[client_ip]
            time_diff = current_time - ip_data["last_request"]

            if time_diff < REQUEST_TIME_WINDOW:  # Within the time window
                ip_data["count"] += 1
            else:
                ip_data["count"] = 1  # Reset count if outside of time window

            ip_data["last_request"] = current_time

            # If too many requests in a short time, mark IP as malicious and block
            if ip_data["count"] > REQUEST_THRESHOLD:
                blocklist.add(client_ip)
                logging.info(f"[Defense] IP {client_ip} added to blocklist due to exceeding request threshold.")
                return "Request blocked due to suspicious activity.", 403

        # If defense is active, handle malicious requests separately
        if is_defending:
            if request.headers.get("User-Agent") == "Malicious-Attack":
                logging.info(f"[Defense] Malicious request from {client_ip} blocked by IPS.")
                return "Request blocked by defense mechanism.", 403
            else:
                logging.info(f"[Defense] Legitimate request from {local_ip} received while defense is active.")
                request_count += 1
                return render_template("d_interface.html",
                                       message="Welcome to the Dummy Website! Server is running with defense ON.",
                                       request_count=request_count,
                                       status="Normal",
                                       defense_status="ON",
                                       defense_status_class="defense-on")

        # Count all incoming requests when defense is off
        request_count += 1

        # Only count requests with the malicious header towards overload
        if request.headers.get("User-Agent") == "Malicious-Attack":
            ip_data["count"] > REQUEST_THRESHOLD
            time_diff < REQUEST_TIME_WINDOW
            malicious_request_count += 1

        # Only overload if the malicious request count exceeds the threshold
        if malicious_request_count > 5000:  # Overloaded threshold for malicious requests
            logging.info("[Attack] Server overloaded due to HTTP Flood attack.")
            return render_template("d_interface.html",
                                   message="Server is overloaded due to HTTP Flood attack! Please try again later.",
                                   request_count=request_count,
                                   status="Overloaded",
                                   defense_status="N/A",
                                   defense_status_class="defense-off")

    # Normal state of the server
    defense_status = "ON" if is_defending else "OFF"
    defense_status_class = "defense-on" if is_defending else "defense-off"

    return render_template("d_interface.html",
                           message="Welcome to the Dummy Website! Server is running fine.",
                           request_count=request_count,
                           status="Normal",
                           defense_status=defense_status,
                           defense_status_class=defense_status_class)

# Route to activate defense
@app.route("/defend", methods=["POST"])
def start_defense():
    global is_defending, request_count
    with lock:
        if not is_defending:
            is_defending = True
            logging.info("[Defense] Activated: Basic firewall protecting against HTTP Flood.")
            return "Defense Mechanism Activated. Server is protected."
        return "Defense is already active."

# Route to deactivate defense
@app.route("/stop_defense", methods=["POST"])
def stop_defense():
    global is_defending
    with lock:
        if is_defending:
            is_defending = False
            logging.info("[Defense] Deactivated: Firewall off. No longer blocking requests.")
            return "Defense Mechanism Deactivated."
        return "Defense is not active."

# Route to reset the server manually
@app.route("/reset", methods=["POST"])
def reset_server():
    global request_count, malicious_request_count, resetting, ip_request_count, blocklist
    with lock:
        resetting = True
        request_count = 0
        malicious_request_count = 0
        ip_request_count.clear()
        blocklist.clear()
        logging.info("[Server] Resetting server state to normal.")

        return "Server has been reset. Request count cleared."

if __name__ == "__main__":
    app.run(host="127.0.0.2", port=5001)
