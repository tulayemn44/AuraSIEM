# 🌸 AuraSIEM — Pink, Pretty, Powerful Threat Detection Engine

AuraSIEM is a lightweight, visually striking SIEM (Security Information and Event Management) and SOC automation simulator written in Python. It generates synthetic system logs, detects cyber threats in real-time using regex-based correlation rules, and instantly dispatches high-severity alerts to a Telegram Bot, all while serving a gorgeous, dark-pink cybersecurity dashboard.

---

## 🎯 Features
- **Real-Time Log Ingestion Simulation:** Simulates Linux Syslog, Nginx Web Server logs, SSH connections, and Kernel drops.
- **Threat Detection Engine:** Rule-based correlation patterns for **Brute-Force Attacks, Port Scans, and Web Application Reconnaissance** (Log4j, Directory Traversal, etc.).
- **Incident Response Automation (SOAR):** Automated alerts sent directly to a SOC Telegram channel via Telegram Bot API.
- **Aesthetic SOC Dashboard:** A responsive Flask web application styled with a custom purple/pink cyberpunk theme.

---

## ⚙️ How It Works (Correlation Rules)
1. **Brute Force:** If the same IP address triggers `4` failed login attempts, the engine correlates these events and flags it as a Brute Force attack.
2. **Port Scan:** Recognizes `DROP` logs from specific kernel patterns indicating automated scanning tools like Nmap.
3. **Web Attacks:** Detects directory traversal patterns (e.g., `etc/passwd`) or exposure attempts on `.env` files.

---

## 🚀 Installation & Setup

1. Clone the repository and install the required Python libraries:
   ```bash
   pip install flask requests python-dotenv
   2. Create a `.env` file in the root directory of the project and add your Telegram credentials:
   ```env
   TELEGRAM_TOKEN=your_bot_token_here
   TELEGRAM_CHAT_ID=your_chat_id_here
   3. Run the engine:
   ```bash
   python3 aura_siem.py
   Open the dashboard in your browser:
   http://localhost:8080

   Developed for educational purposes to demonstrate SIEM correlation principles and automated incident response. 🌸

---
### 💖 Credits & Acknowledgments
Special thanks to brilliant (https://github.com/shadowport1609) for their , guidance, and inspiration during the development of this project! 
