import os
import smtplib
import sqlite3
import subprocess
import joblib
import pandas as pd
import time
from collections import Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Load trained ML model and scaler
model = joblib.load("lr.joblib")
scaler = joblib.load("scaler.joblib")

# Parameters for detection
TIME_WINDOW = 10  # Time window in seconds for traffic aggregation
PACKET_THRESHOLD = 500  # Minimum packet count in a time window to trigger detection

# Trusted IP that should NEVER be blocked
TRUSTED_IP = "192.168.29.217"

# Email credentials
SENDER_EMAIL = "hackerantharababu@gmail.com"
SENDER_PASSWORD = "dfcv bbqd qucv shnq"
RECEIVER_EMAIL = "lingojikarthikchary@gmail.com"

# Traffic statistics
traffic_stats = {
    "pkt_count": 0,
    "byte_count": 0,
    "protocol_counter": Counter(),
    "src_ips": set(),
    "start_time": time.time(),
}

def setup_db():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS detected_attacks (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ip_address TEXT,
                      reason TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ip_address TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def reset_traffic_stats():
    global traffic_stats
    traffic_stats = {
        "pkt_count": 0,
        "byte_count": 0,
        "protocol_counter": Counter(),
        "src_ips": set(),
        "start_time": time.time(),
    }

def process_packet(packet):
    global traffic_stats
    current_time = time.time()

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip == TRUSTED_IP:
            return  # Do not process trusted IP
        
        traffic_stats["pkt_count"] += 1
        traffic_stats["byte_count"] += len(packet)
        traffic_stats["src_ips"].add(src_ip)

        if packet.haslayer(TCP):
            traffic_stats["protocol_counter"]["TCP"] += 1
        elif packet.haslayer(UDP):
            traffic_stats["protocol_counter"]["UDP"] += 1
        elif packet.haslayer(ICMP):
            traffic_stats["protocol_counter"]["ICMP"] += 1

        if current_time - traffic_stats["start_time"] >= TIME_WINDOW:
            analyze_traffic()

def analyze_traffic():
    global traffic_stats
    
    feature_values = pd.DataFrame([{
        "pkt_count": traffic_stats["pkt_count"],
        "byte_count": traffic_stats["byte_count"],
        "flow_duration": TIME_WINDOW,
        "src_ip_diversity": len(traffic_stats["src_ips"]),
        "protocol_tcp": traffic_stats["protocol_counter"]["TCP"],
        "protocol_udp": traffic_stats["protocol_counter"]["UDP"],
        "protocol_icmp": traffic_stats["protocol_counter"]["ICMP"],
        "pkt_rate": traffic_stats["pkt_count"] / TIME_WINDOW,
        "byte_rate": traffic_stats["byte_count"] / TIME_WINDOW,
    }])
    
    try:
        scaled_values = scaler.transform(feature_values)
        prediction = model.predict(scaled_values)[0]
        
        if prediction == 1 and traffic_stats["pkt_count"] >= PACKET_THRESHOLD:
            print("\n🚨 DDoS Attack Detected!")
            for ip in traffic_stats["src_ips"]:
                log_attack(ip, "DDoS Attack")
                block_ip(ip)
                send_email_alert(ip)
        else:
            print("\n✅ Normal Traffic Detected.")
    except Exception as e:
        print(f"❌ Error during traffic analysis: {e}")
    
    reset_traffic_stats()

def log_attack(ip, reason):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO detected_attacks (ip_address, reason) VALUES (?, ?)", (ip, reason))
    conn.commit()
    conn.close()
    print(f"[!] Attack Logged: {ip} ({reason})")

def block_ip(ip):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips WHERE ip_address=?", (ip,))
    if cursor.fetchone() is None:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (?)", (ip,))
        conn.commit()
        print(f"[🔥] Blocked IP: {ip}")
    conn.close()

def send_email_alert(ip):
    subject = "🚨 DDoS Attack Detected!"
    body = f"A DDoS attack has been detected from IP: {ip}. The IP has been blocked."
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(f"[📧] Email Alert Sent to {RECEIVER_EMAIL}")
    except Exception as e:
        print(f"[⚠] Error sending email: {e}")

if __name__ == "__main__":
    setup_db()
    print("🚀 Monitoring network traffic with ML-based DDoS detection...")
    sniff(filter="ip", prn=process_packet, store=0)
