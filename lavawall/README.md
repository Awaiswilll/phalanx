# PHALANX LAVAWALL (UNDER DEVELOPMENT)
```
    ██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
    ██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
    ██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
```

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

PHALANX LAVAWALL is a high‑performance, agent‑based defensive framework that simulates a swarm of 100 intelligent agents working together to monitor network traffic, detect intrusions, block malicious IPs (via `iptables`), and track VPN status. It provides a rich **curses TUI** for real‑time monitoring and a **headless console mode** for servers or containers.

---

## Features

- **100 Autonomous Agents** – Roles: Scanner, Firewall, MemoryCleaner, AttackDetector, Encryptor, VPNChecker. Agents regenerate dynamically.
- **Real‑time Firewall** – Integrates with `iptables` (requires root) or runs in safe simulation mode.
- **VPN Monitoring** – Detects OpenVPN (`tun0`) and WireGuard (`wg0`) interfaces.
- **Live TUI** – Curses‑based dashboard with logo, stats, agent table, live logs, and help overlay.
- **Headless Mode** – Console logging with rotating file backend, signal handlers for graceful shutdown.
- **Fully Configurable** – `config.json` (auto‑created) controls agent count, network ranges, thresholds, log rotation, and more.
- **Log Rotation** – Disk logs rotate at 10 MB (5 backups), in‑memory deque for TUI.
- **Dynamic IP Scanning** – Priority scanning of active (high‑risk) IPs, configurable port list.
- **Ctrl+Key Shortcuts** – Intuitive TUI controls (Ctrl+Q quit, Ctrl+R reset, Ctrl+L save logs, etc.).

---

## 📦 Requirements

- **Python 3.8+**
- **Linux** (for `iptables`, `ip` commands; macOS may work partially)
- Optional (but recommended):
  - `curses` – usually included, else `sudo apt install python3-dev`
  - `iptables` – for real blocking (`sudo` required)

No external Python libraries are needed – only the standard library.

---

## Installation


# Install development
```
sudo apt install python3-dev
```

# Run
```bash
cd ~/phalanx_lavawall/ (folder)
python3 phalanx.py
```

On first run, a `config.json` file is created in the current directory.

---

## Usage

### TUI Mode (default)
```bash
# For real iptables blocking (recommended)
sudo python3 phalanx.py

# Without root – simulation mode (no real blocking)
python3 phalanx.py
```

### Headless Mode (console logging)
```bash
python3 phalanx.py --headless

# With custom heartbeat interval (overrides config)
python3 phalanx.py --headless --heartbeat 10
```

---

## TUI Controls

Press `Ctrl+H` at any time to see the help overlay.

| Shortcut          | Action                         |
|-------------------|--------------------------------|
| `Ctrl+Q` / `ESC` / `Ctrl+C` | Quit                           |
| `Ctrl+R`          | Reset threat level & blocked IPs |
| `Ctrl+L`          | Save current logs & report to disk |
| `Ctrl+B`          | Manually block an IP (prompt)  |
| `Ctrl+V`          | Refresh VPN status             |
| `Ctrl+S`          | Show last saved report path    |
| `Ctrl+H`          | Toggle help overlay            |

---

## Logs & Reports

- **Log files** – `./defense_logs/defense_YYYYMMDD_HHMMSS.log` (rotated at 10 MB, keeps 5 backups)
- **Reports** – `./defense_reports/report_YYYYMMDD_HHMMSS.json` (saved via `Ctrl+L`)

The report contains session statistics, blocked IPs, VPN status, and a snapshot of agent states.

---

1. **Agent Network** – 100 agents are created with balanced roles. Each agent can perform its specialised task(s).
2. **Network Monitor Thread** – Simulates connections (or can be extended to use `psutil` for real traffic). It maintains shared state: IP logs, connection attempts, suspect IPs, active IPs.
3. **Task Assignment** – Every few seconds, the monitor assigns tasks to agents (scan, firewall, detect attack, clear memory, VPN check, contribute to key).
4. **Attack Detection** – Uses configurable thresholds (unique IPs, attempt spikes, suspect IPs, attack load) to raise the threat level.
5. **Firewall** – If `iptables` is available and the script runs as root, blocked IPs are actually dropped; otherwise, simulation mode is used.
6. **Logging** – All events are written to rotating files and also kept in memory for the TUI.

---

## 🤝 License

MIT License 

## ⚠️ Disclaimer

This tool is intended for **defensive and educational purposes only**. Use it only on systems you own or have explicit permission to monitor. The author is not responsible for any misuse or damage.

---

## 📬 Contact & Contributions

Issues and pull requests are welcome!  
For questions, open an issue on GitHub.

**Happy defending!** 🛡️
```
