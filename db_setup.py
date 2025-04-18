import sqlite3

def setup_db():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()

    # Table for logging detected attacks
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detected_attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Table for blocked IPs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("Database setup complete.")

if __name__ == "__main__":
    setup_db() 
