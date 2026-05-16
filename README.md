🛡️ Simple Python Honeypot with Real-time Dashboard
This is a personal security project I built to understand how attackers interact with open services. Instead of just a command-line tool, I wanted a visual way to track connection attempts in real-time.

💡 Why I built this?
As someone moving into Cloud Security and DevSecOps, I wanted to bridge the gap between "Defensive Security" and "Web Development". This project simulates a vulnerable service and captures metadata from anyone trying to connect.

🚀 Key Features
Multi-Port Listener: Mimics common services to attract automated bots.

Live Dashboard: A clean web interface (Flask) to visualize incoming "attacks".

Connection Logging: Captures IP addresses, timestamps, and attempted payloads.

Lightweight: Runs easily on any Linux environment or a small AWS EC2 instance.

🛠️ Tech Stack
Backend: Python (Flask)

Frontend: HTML5, CSS3, JavaScript (for the live updates)

Security Logic: Custom Python socket handling for connection interception.

📂 How it works
The script opens specific ports and waits for a connection.

When a "bot" or "attacker" connects, the script logs their IP and metadata.

The Flask app serves a dashboard that reads these logs and displays them instantly.
