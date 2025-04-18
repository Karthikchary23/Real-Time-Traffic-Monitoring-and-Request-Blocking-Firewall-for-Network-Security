import os
import sqlite3

def block_ip(ip):
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (?)", (ip,))
    conn.commit()
    conn.close()
    print(f"[+] Blocked IP: {ip}")

def unblock_ip(ip):
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()
    print(f"[-] Unblocked IP: {ip}")
