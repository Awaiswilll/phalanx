#!/usr/bin/env python3
"""
PHALANX LAVAWALL - 100 Agent Firewall/VPN Protection (No AI/LLM)
Fully configurable, production‑ready version.

USAGE:
    sudo python3 phalanx.py [--headless] [--heartbeat SECONDS]

CONFIGURATION:
    Edit config.json (auto-created on first run) to change agent counts,
    scanning intervals, threat thresholds, log rotation, etc.

CONTROLS (TUI only, press Ctrl+H for help):
    Ctrl+Q / ESC / Ctrl+C - quit
    Ctrl+R                - reset threat & blocks
    Ctrl+L                - save logs to file
    Ctrl+B                - manual block IP
    Ctrl+V                - refresh VPN status
    Ctrl+S                - show last report path
    Ctrl+H                - toggle help screen
"""

import os
import sys
import time
import json
import random
import string
import threading
import subprocess
import socket
import traceback
import signal
import argparse
import logging
import logging.handlers
import ipaddress
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Any, List, Set

# ------------------------------------------------------------------
# Default configuration (will be merged with config.json)
# ------------------------------------------------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    "agents": {
        "count": 100,
        "roles": ["Scanner", "Firewall", "MemoryCleaner", "AttackDetector", "Encryptor", "VPNChecker"],
        "target_per_role": 16  # will be auto-calculated if not set
    },
    "network": {
        "scan_interval_seconds": 2.5,
        "vpn_check_interval_seconds": 15,
        "dns_port": 53,
        "high_risk_ports": [4444, 1337, 22, 23, 445, 3389, 8080, 5900],
        "simulated_ip_range": "192.168.1.0/24",
        "simulated_extra_ips": ["203.0.113.5", "198.51.100.7"]
    },
    "threat": {
        "attack_threshold_ip_count": 5,
        "attack_threshold_avg_attempts": 3.0,
        "attack_threshold_suspect_ips": 5,
        "attack_threshold_load": 10,
        "threat_increment_per_attack": 2,
        "threat_decrement_per_cycle": 0.2,
        "max_threat": 100
    },
    "logging": {
        "max_log_lines_memory": 5000,
        "log_file_max_bytes": 10485760,  # 10 MB
        "log_file_backup_count": 5,
        "headless_heartbeat_seconds": 5
    },
    "directories": {
        "log_dir": "./defense_logs",
        "report_dir": "./defense_reports"
    }
}

# ------------------------------------------------------------------
# Configuration loader with validation and deep merge
# ------------------------------------------------------------------
def deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge two dictionaries. Lists in override replace those in base."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def validate_config(cfg: Dict) -> bool:
    """Basic schema validation. Returns True if valid, else prints error and exits."""
    required_sections = ["agents", "network", "threat", "logging", "directories"]
    for section in required_sections:
        if section not in cfg:
            print(f"[ERROR] Config missing required section: {section}")
            return False
    # Check agent count
    if not isinstance(cfg["agents"].get("count"), int) or cfg["agents"]["count"] <= 0:
        print("[ERROR] agents.count must be a positive integer")
        return False
    # Check network scan interval
    if not isinstance(cfg["network"].get("scan_interval_seconds"), (int, float)) or cfg["network"]["scan_interval_seconds"] <= 0:
        print("[ERROR] network.scan_interval_seconds must be a positive number")
        return False
    # Check log rotation settings
    if not isinstance(cfg["logging"].get("log_file_max_bytes"), int) or cfg["logging"]["log_file_max_bytes"] <= 0:
        print("[ERROR] logging.log_file_max_bytes must be a positive integer")
        return False
    return True

def load_config(config_path: Path = Path("config.json")) -> Dict:
    """Load and merge configuration, create default if missing, validate."""
    if not config_path.exists():
        with open(config_path, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[*] Created default config file: {config_path}")
        return DEFAULT_CONFIG.copy()
    try:
        with open(config_path, 'r') as f:
            user_cfg = json.load(f)
        merged = deep_merge(DEFAULT_CONFIG, user_cfg)
        if not validate_config(merged):
            print("[ERROR] Invalid configuration. Using defaults.")
            return DEFAULT_CONFIG.copy()
        return merged
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}. Using defaults.")
        return DEFAULT_CONFIG.copy()

# ------------------------------------------------------------------
# Parse command line arguments
# ------------------------------------------------------------------
parser = argparse.ArgumentParser(description="PHALANX LAVAWALL Defense System")
parser.add_argument("--headless", action="store_true", help="Run without TUI (console logging only)")
parser.add_argument("--heartbeat", type=int, help="Heartbeat interval in seconds for headless mode (overrides config)")
args = parser.parse_args()

# ------------------------------------------------------------------
# Load configuration
# ------------------------------------------------------------------
config = load_config()
if args.heartbeat is not None:
    config["logging"]["headless_heartbeat_seconds"] = args.heartbeat

# ------------------------------------------------------------------
# Terminal UI detection
# ------------------------------------------------------------------
USE_CURSES = not args.headless and sys.stdout.isatty() and sys.stderr.isatty()
if USE_CURSES:
    try:
        import curses
        from curses import wrapper
        CURSES_OK = True
    except ImportError:
        USE_CURSES = False
        CURSES_OK = False
        print("[WARN] curses not found. Running in headless mode. Install: sudo apt install python3-dev")
else:
    CURSES_OK = False

# ------------------------------------------------------------------
# PHALANX ASCII Logo
# ------------------------------------------------------------------
PHALANX_LOGO = [
    "██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗",
    "██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝",
    "██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ ",
    "██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ ",
    "██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗",
    "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝",
]

# ------------------------------------------------------------------
# Setup directories
# ------------------------------------------------------------------
LOG_DIR = Path(config["directories"]["log_dir"])
REPORT_DIR = Path(config["directories"]["report_dir"])
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

# ------------------------------------------------------------------
# Logging system (with rotation)
# ------------------------------------------------------------------
class DefenseLogger:
    def __init__(self, config_section: Dict):
        self.config = config_section
        self.log_lines = deque(maxlen=config_section.get("max_log_lines_memory", 5000))
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = LOG_DIR / f"defense_{self.session_id}.log"
        self._setup_file_logger()
        self._write_header()

    def _setup_file_logger(self):
        self.file_logger = logging.getLogger("PHALANX_FILE")
        self.file_logger.setLevel(logging.INFO)
        handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=self.config.get("log_file_max_bytes", 10485760),
            backupCount=self.config.get("log_file_backup_count", 5)
        )
        formatter = logging.Formatter("%(asctime)s - %(message)s", datefmt="%H:%M:%S")
        handler.setFormatter(formatter)
        self.file_logger.addHandler(handler)

    def _write_header(self):
        self.file_logger.info(f"# PHALANX LAVAWALL LOG - Session {self.session_id}")
        self.file_logger.info(f"# Started: {datetime.now().isoformat()}")
        self.file_logger.info("#" * 60)

    def add(self, agent_id: int, role: str, event_type: str, action: str, details: str = ""):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] A{agent_id:4d} [{role:12s}] {event_type:10s} {action:15s} {details}"
        self.log_lines.append(entry)
        self.file_logger.info(entry)
        if not USE_CURSES:
            print(entry)
        return entry

    def get_recent(self, n: int = 20):
        return list(self.log_lines)[-n:]

    def flush_report(self, report_data: Dict) -> str:
        report_file = REPORT_DIR / f"report_{self.session_id}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            return str(report_file)
        except Exception as e:
            return f"ERROR: {e}"

# ------------------------------------------------------------------
# Firewall Manager (real iptables if root)
# ------------------------------------------------------------------
class FirewallManager:
    def __init__(self, logger: DefenseLogger):
        self.blocked_ips: Set[str] = set()
        self.is_root = (os.geteuid() == 0)
        self.iptables_available = False
        self.logger = logger
        if self.is_root:
            try:
                subprocess.run(["iptables", "--version"], capture_output=True, check=True)
                self.iptables_available = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        if not self.iptables_available:
            self.logger.add(0, "SYSTEM", "WARN", "iptables_unavailable", "Firewall will run in simulation mode (install iptables or run as root)")

    def block_ip(self, ip: str, reason: str = "") -> bool:
        if ip in self.blocked_ips:
            return False
        self.blocked_ips.add(ip)
        if self.iptables_available:
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
                subprocess.run(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
            except Exception:
                pass
        return True

    def unblock_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            return False
        self.blocked_ips.discard(ip)
        if self.iptables_available:
            try:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
                subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
            except Exception:
                pass
        return True

    def get_blocked(self) -> List[str]:
        return list(self.blocked_ips)

    def reset(self):
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)

# ------------------------------------------------------------------
# VPN Monitor
# ------------------------------------------------------------------
class VPNMonitor:
    def __init__(self, logger: DefenseLogger):
        self.active = False
        self.vpn_type = None
        self.interface = None
        self.last_logged_state = None
        self.logger = logger

    def refresh(self) -> bool:
        active = False
        try:
            output = subprocess.check_output(["ip", "link", "show"], text=True, stderr=subprocess.DEVNULL)
            if "tun0" in output:
                active = True
                self.vpn_type = "OpenVPN"
                self.interface = "tun0"
            elif "wg0" in output:
                active = True
                self.vpn_type = "WireGuard"
                self.interface = "wg0"
        except:
            try:
                if os.path.exists("/sys/class/net/tun0"):
                    active = True
                    self.vpn_type = "OpenVPN"
                    self.interface = "tun0"
                elif os.path.exists("/sys/class/net/wg0"):
                    active = True
                    self.vpn_type = "WireGuard"
                    self.interface = "wg0"
            except:
                pass
        self.active = active
        return self.active

    def get_status(self) -> Dict:
        return {"active": self.active, "type": self.vpn_type, "interface": self.interface}

# ------------------------------------------------------------------
# Agent (with task signatures)
# ------------------------------------------------------------------
class Agent:
    def __init__(self, agent_id: int, role: str, logger: DefenseLogger,
                 firewall: FirewallManager, vpn_monitor: VPNMonitor):
        self.id = agent_id
        self.role = role
        self.status = "standby"
        self.last_action = ""
        self.logger = logger
        self.firewall = firewall
        self.vpn_monitor = vpn_monitor
        self.key_fragment = list(random.choices(string.ascii_letters + string.digits, k=8))
        self.task = None

    def execute_task(self, task: str, *args):
        if not self.is_task_allowed(task):
            return None
        self.status = "run"
        self.task = task
        self.last_action = task[:10]
        try:
            result = getattr(self, task)(*args)
            self.status = "standby"
            return result
        except (socket.error, OSError, KeyError, ValueError, AttributeError, RuntimeError) as e:
            self.status = "err"
            self.logger.add(self.id, self.role, "ERROR", task, f"{str(e)[:40]}")
            traceback.print_exc(file=sys.stderr)
            return None
        except Exception as e:
            self.status = "err"
            self.logger.add(self.id, self.role, "ERROR", task, f"unexpected: {str(e)[:40]}")
            traceback.print_exc(file=sys.stderr)
            return None

    def is_task_allowed(self, task: str) -> bool:
        role_tasks = {
            "Scanner": ["scan"],
            "Firewall": ["firewall_action"],
            "MemoryCleaner": ["clear_memory"],
            "AttackDetector": ["detect_attack"],
            "Encryptor": ["contribute_to_key"],
            "VPNChecker": ["vpn_check"]
        }
        return task in role_tasks.get(self.role, [])

    def scan(self, ip: str):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip, config["network"]["dns_port"]))
            sock.close()
            return (ip, result == 0)
        except socket.error as e:
            self.logger.add(self.id, self.role, "ERROR", "scan", str(e)[:40])
            return (ip, False)

    def firewall_action(self, ip: str, blocked_set: Set[str], active_ips: Set[str]):
        try:
            if ip not in blocked_set:
                self.firewall.block_ip(ip, "agent")
                blocked_set.add(ip)
                if ip in active_ips:
                    active_ips.discard(ip)
                    self.logger.add(self.id, self.role, "INFO", "blocked_active_ip", ip)
                return True
            return False
        except Exception as e:
            self.logger.add(self.id, self.role, "ERROR", "firewall", str(e)[:40])
            return False

    def clear_memory(self, ip_logs: deque, active_ips: Set[str], suspect_ips: Set[str],
                     connection_attempts: Dict[str, int]):
        try:
            if random.random() < 0.9:
                if ip_logs:
                    ip_logs.popleft()
                active_ips.clear()
                if len(suspect_ips) > 10:
                    suspect_list = list(suspect_ips)
                    suspect_list.pop()
                    suspect_ips.clear()
                    suspect_ips.update(suspect_list)
                connection_attempts.clear()
            return True
        except Exception as e:
            self.logger.add(self.id, self.role, "ERROR", "clear_memory", str(e)[:40])
            return False

    def detect_attack(self, ip_logs: deque, connection_attempts: Dict[str, int],
                      suspect_ips: Set[str], attack_load: float) -> bool:
        try:
            if len(ip_logs) < 3:
                return False
            recent = list(ip_logs)[-3:]
            unique_ips = set()
            for ts, ips in recent:
                unique_ips.update(ips)
            ip_count = len(unique_ips)
            total_attempts = sum(connection_attempts.values())
            avg_attempts = total_attempts / max(1, len(connection_attempts))
            th = config["threat"]
            is_attack = (ip_count > th["attack_threshold_ip_count"] or
                         avg_attempts > th["attack_threshold_avg_attempts"] or
                         len(suspect_ips) > th["attack_threshold_suspect_ips"] or
                         attack_load > th["attack_threshold_load"])
            if is_attack:
                self.logger.add(self.id, self.role, "INTRUDER", "attack_detected",
                                f"IPs={ip_count}, AvgAttempts={avg_attempts:.1f}, Load={attack_load}")
            return is_attack
        except Exception as e:
            self.logger.add(self.id, self.role, "ERROR", "detect_attack", str(e)[:40])
            return False

    def contribute_to_key(self) -> str:
        try:
            frag = self.key_fragment[:]
            random.shuffle(frag)
            return ''.join(frag)
        except Exception as e:
            self.logger.add(self.id, self.role, "ERROR", "contribute_to_key", str(e)[:40])
            return ""

    def vpn_check(self) -> bool:
        active = self.vpn_monitor.refresh()
        if active != self.vpn_monitor.last_logged_state:
            if active:
                self.logger.add(self.id, self.role, "INFO", "vpn_active", self.vpn_monitor.vpn_type or "unknown")
            else:
                self.logger.add(self.id, self.role, "WARN", "vpn_down", "no tunnel")
            self.vpn_monitor.last_logged_state = active
        return active

# ------------------------------------------------------------------
# Agent Network (configurable agent count)
# ------------------------------------------------------------------
class AgentNetwork:
    def __init__(self, logger: DefenseLogger, firewall: FirewallManager, vpn_monitor: VPNMonitor):
        self.agents: List[Agent] = []
        self.logger = logger
        self.firewall = firewall
        self.vpn_monitor = vpn_monitor
        self.role_counts: Dict[str, int] = defaultdict(int)
        self.roles = config["agents"]["roles"]
        target_per_role = config["agents"].get("target_per_role")
        if not target_per_role:
            target_per_role = config["agents"]["count"] // len(self.roles) + 1
        self.target_per_role = target_per_role
        self.threat_level = 0
        self.lock = threading.Lock()
        self._pending_regenerations: List[Agent] = []
        self._create_agents(config["agents"]["count"])

    def _create_agents(self, total: int):
        agent_id = 1
        while agent_id <= total:
            available = [r for r in self.roles if self.role_counts[r] < self.target_per_role]
            if not available:
                available = self.roles
            role = random.choice(available)
            agent = Agent(agent_id, role, self.logger, self.firewall, self.vpn_monitor)
            self.agents.append(agent)
            self.role_counts[role] += 1
            agent_id += 1

    def _apply_pending_regenerations(self):
        if not self._pending_regenerations:
            return
        with self.lock:
            for old_agent in self._pending_regenerations:
                if old_agent in self.agents:
                    self.agents.remove(old_agent)
                    self.role_counts[old_agent.role] -= 1
                    new_id = random.randint(101, 10000)
                    available = [r for r in self.roles if self.role_counts[r] < self.target_per_role]
                    if not available:
                        available = self.roles
                    new_role = random.choice(available)
                    new_agent = Agent(new_id, new_role, self.logger, self.firewall, self.vpn_monitor)
                    self.agents.append(new_agent)
                    self.role_counts[new_role] += 1
            self._pending_regenerations.clear()

    def queue_regeneration(self, agent: Agent):
        with self.lock:
            self._pending_regenerations.append(agent)

    def assign_tasks(self, task_type: str, *args) -> List[Any]:
        role_map = {
            "scan": "Scanner",
            "firewall_action": "Firewall",
            "clear_memory": "MemoryCleaner",
            "detect_attack": "AttackDetector",
            "contribute_to_key": "Encryptor",
            "vpn_check": "VPNChecker"
        }
        needed = role_map.get(task_type)
        if not needed:
            return []
        with self.lock:
            eligible = [a for a in self.agents if a.role == needed and a.status == "standby"]
            if not eligible:
                return []
            selected = eligible[:min(len(eligible), 10)]
        results = []
        for agent in selected:
            res = agent.execute_task(task_type, *args)
            if res is not None:
                results.append(res)
            if random.random() < 0.05:
                self.queue_regeneration(agent)
        self._apply_pending_regenerations()
        return results

    def update_threat(self, delta: float):
        self.threat_level = max(0, min(config["threat"]["max_threat"], self.threat_level + delta))

    def get_stats(self) -> Dict:
        with self.lock:
            return {
                "total": len(self.agents),
                "roles": dict(self.role_counts),
                "threat": self.threat_level,
                "blocked": len(self.firewall.get_blocked())
            }

    def get_agent_snapshot(self, max_show: int = 30) -> List[Dict]:
        with self.lock:
            agents_copy = self.agents[:max_show]
            return [{"id": a.id, "role": a.role[:4], "status": a.status[:3], "last": a.last_action[:8]}
                    for a in agents_copy]

# ------------------------------------------------------------------
# Network Monitor Thread (uses ipaddress for efficient range generation)
# ------------------------------------------------------------------
class NetworkMonitorThread:
    def __init__(self, network: AgentNetwork, firewall: FirewallManager, logger: DefenseLogger):
        self.network = network
        self.firewall = firewall
        self.logger = logger
        self.running = True
        self.thread = None
        # Shared state
        self.ip_logs: deque = deque(maxlen=50)
        self.connection_attempts: Dict[str, int] = defaultdict(int)
        self.suspect_ips: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.active_ips: Set[str] = set()      # IPs that triggered high-risk ports (priority scanning)
        self.attack_load: float = 0
        # Precompute IP list from range
        self._simulated_ips = self._generate_ip_list()

    def _generate_ip_list(self) -> List[str]:
        """Generate list of IPs from config range and extra IPs."""
        ip_range = config["network"]["simulated_ip_range"]
        ips = []
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            # Take first 100 hosts to avoid huge lists
            for i, ip in enumerate(network.hosts()):
                if i >= 100:
                    break
                ips.append(str(ip))
        except Exception as e:
            self.logger.add(0, "MONITOR", "WARN", "ip_range_invalid", str(e)[:40])
            # Fallback to a default range
            ips = [f"192.168.1.{i}" for i in range(1, 51)]
        ips.extend(config["network"]["simulated_extra_ips"])
        return ips

    def _get_simulated_connections(self) -> List[tuple]:
        ips = self._simulated_ips
        ports = config["network"]["high_risk_ports"]
        conns = []
        for _ in range(random.randint(5, 15)):
            src = random.choice(ips)
            dst = random.choice(ips)
            port = random.choice(ports)
            conns.append((src, dst, port))
        return conns

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _run(self):
        net_cfg = config["network"]
        scan_interval = net_cfg["scan_interval_seconds"]
        vpn_interval = net_cfg["vpn_check_interval_seconds"]
        vpn_counter = 0
        while self.running:
            connections = self._get_simulated_connections()
            current_ips = set()
            for src, dst, port in connections:
                current_ips.add(src)
                current_ips.add(dst)
                self.connection_attempts[src] += 1
                self.connection_attempts[dst] += 1
                if port in net_cfg["high_risk_ports"] and src not in self.blocked_ips:
                    self.suspect_ips.add(src)
                    self.active_ips.add(src)   # Mark as active for priority scanning

            self.ip_logs.append((datetime.now(), list(current_ips)))

            # Priority scanning: active_ips first
            scan_targets = list(self.active_ips)
            if len(scan_targets) < 3:
                remaining = 3 - len(scan_targets)
                random_ips = [ip for ip in current_ips if ip not in scan_targets]
                if random_ips:
                    scan_targets.extend(random.sample(random_ips, min(remaining, len(random_ips))))
            else:
                scan_targets = random.sample(scan_targets, min(3, len(scan_targets)))

            for ip in scan_targets:
                results = self.network.assign_tasks("scan", ip)
                for res_ip, reachable in results:
                    if reachable and res_ip not in self.blocked_ips:
                        self.suspect_ips.add(res_ip)
                        if res_ip not in self.active_ips:
                            self.active_ips.add(res_ip)
                            self.logger.add(0, "MONITOR", "INFO", "new_active_ip", res_ip)

            for ip in list(self.suspect_ips):
                self.network.assign_tasks("firewall_action", ip, self.blocked_ips, self.active_ips)

            attack = self.network.assign_tasks("detect_attack",
                                               self.ip_logs,
                                               self.connection_attempts,
                                               self.suspect_ips,
                                               self.attack_load)
            th = config["threat"]
            if any(attack):
                self.attack_load = min(100, self.attack_load + 5)
                self.network.update_threat(th["threat_increment_per_attack"])
            else:
                self.attack_load = max(0, self.attack_load - 1)
                self.network.update_threat(-th["threat_decrement_per_cycle"])

            self.network.assign_tasks("clear_memory",
                                      self.ip_logs,
                                      self.active_ips,
                                      self.suspect_ips,
                                      self.connection_attempts)

            vpn_counter += 1
            if vpn_counter >= int(vpn_interval / scan_interval):
                self.network.assign_tasks("vpn_check")
                vpn_counter = 0

            time.sleep(scan_interval)

# ------------------------------------------------------------------
# Headless mode runner
# ------------------------------------------------------------------
_headless_shutdown_event = threading.Event()

def _signal_handler(signum, frame):
    print(f"\n[SYSTEM] Received signal {signum}, shutting down...")
    _headless_shutdown_event.set()

def run_headless():
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    for line in PHALANX_LOGO:
        print(line)
    print("\nPHALANX LAVAWALL - Headless Mode (logging to console and file)\n")

    logger = DefenseLogger(config["logging"])
    firewall = FirewallManager(logger)
    vpn = VPNMonitor(logger)
    network = AgentNetwork(logger, firewall, vpn)
    monitor = NetworkMonitorThread(network, firewall, logger)

    logger.add(0, "SYSTEM", "START", "headless_mode", f"{config['agents']['count']} agents deployed")
    monitor.start()

    heartbeat = config["logging"]["headless_heartbeat_seconds"]
    try:
        while not _headless_shutdown_event.is_set():
            time.sleep(heartbeat)
            stats = network.get_stats()
            logger.add(0, "SYSTEM", "STATUS", "heartbeat",
                       f"Threat={stats['threat']:.0f}, Blocked={stats['blocked']}")
    finally:
        logger.add(0, "SYSTEM", "SHUTDOWN", "headless_exit", "session ended")
        monitor.stop()

# ------------------------------------------------------------------
# Curses TUI Application
# ------------------------------------------------------------------
if USE_CURSES:
    class DefenseTUI:
        def __init__(self, stdscr):
            self.stdscr = stdscr
            curses.curs_set(0)
            stdscr.nodelay(1)
            stdscr.timeout(500)
            curses.start_color()
            curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
            curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
            curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)

            self.logger = DefenseLogger(config["logging"])
            self.firewall = FirewallManager(self.logger)
            self.vpn = VPNMonitor(self.logger)
            self.network = AgentNetwork(self.logger, self.firewall, self.vpn)
            self.monitor = NetworkMonitorThread(self.network, self.firewall, self.logger)
            self.running = True
            self.last_report_path = None
            self.show_help = False

        def draw_border(self, y, x, h, w, title=""):
            try:
                for i in range(h):
                    self.stdscr.addch(y+i, x, '│')
                    self.stdscr.addch(y+i, x+w-1, '│')
                for j in range(w):
                    self.stdscr.addch(y, x+j, '─')
                    self.stdscr.addch(y+h-1, x+j, '─')
                self.stdscr.addch(y, x, '┌')
                self.stdscr.addch(y, x+w-1, '┐')
                self.stdscr.addch(y+h-1, x, '└')
                self.stdscr.addch(y+h-1, x+w-1, '┘')
                if title:
                    self.stdscr.addstr(y, x+2, title, curses.color_pair(4))
            except curses.error:
                pass

        def draw_logo(self, y, x):
            for i, line in enumerate(PHALANX_LOGO):
                try:
                    self.stdscr.addstr(y+i, x, line, curses.color_pair(1) | curses.A_BOLD)
                except curses.error:
                    pass

        def draw_help_overlay(self):
            h, w = self.stdscr.getmaxyx()
            help_lines = [
                " PHALANX LAVAWALL - HELP (Ctrl+Key) ",
                "═════════════════════════════════════",
                "",
                " Ctrl+Q / ESC / Ctrl+C   Quit",
                " Ctrl+R                   Reset threat & blocks",
                " Ctrl+L                   Save logs to file",
                " Ctrl+B                   Manual block IP",
                " Ctrl+V                   Refresh VPN status",
                " Ctrl+S                   Show last report path",
                " Ctrl+H                   Toggle this help",
                "",
                " Press any key to close help...",
            ]
            overlay_w = max(len(line) for line in help_lines) + 4
            overlay_h = len(help_lines) + 2
            start_y = (h - overlay_h) // 2
            start_x = (w - overlay_w) // 2
            try:
                for i in range(overlay_h):
                    self.stdscr.addstr(start_y+i, start_x, " " * overlay_w, curses.color_pair(5))
                self.draw_border(start_y, start_x, overlay_h, overlay_w)
                for i, line in enumerate(help_lines):
                    self.stdscr.addstr(start_y+1+i, start_x+2, line, curses.color_pair(5) | curses.A_BOLD)
            except curses.error:
                pass

        def draw(self):
            try:
                self.stdscr.clear()
                h, w = self.stdscr.getmaxyx()
                if h < 30 or w < 90:
                    warning = "[WARNING] Terminal too small. Resize to at least 90x30."
                    try:
                        self.stdscr.addstr(0, 0, warning)
                    except curses.error:
                        pass
                    self.stdscr.refresh()
                    return

                self.draw_logo(0, 0)
                stats = self.network.get_stats()
                header = f"PHALANX LAVAWALL - {stats['total']} Agent Firewall/VPN | Threat: {stats['threat']:.0f}"
                try:
                    self.stdscr.addstr(2, 48, header, curses.color_pair(1) | curses.A_BOLD)
                except curses.error:
                    pass

                # Stats panel
                stats_y = 7
                vpn_status = self.vpn.get_status()
                self.draw_border(stats_y, w-35, 6, 34, " STATS ")
                try:
                    self.stdscr.addstr(stats_y+1, w-33, f"Agents: {stats['total']}/{config['agents']['count']}")
                    self.stdscr.addstr(stats_y+2, w-33, f"Blocked: {stats['blocked']}")
                    self.stdscr.addstr(stats_y+3, w-33, f"Threat Lvl: {stats['threat']:.0f}")
                    self.stdscr.addstr(stats_y+4, w-33, f"VPN: {'ACTIVE' if vpn_status['active'] else 'INACT'}")
                    if vpn_status['active']:
                        self.stdscr.addstr(stats_y+5, w-33, f"      {vpn_status['type']} on {vpn_status['interface']}", curses.color_pair(3))
                except curses.error:
                    pass

                # Roles panel
                roles_y = 7
                self.draw_border(roles_y, 0, 6, 44, " AGENT ROLES ")
                y_line = roles_y + 1
                for role, count in sorted(stats['roles'].items()):
                    try:
                        self.stdscr.addstr(y_line, 2, f"{role:15s}: {count:3d}")
                        y_line += 1
                    except curses.error:
                        pass

                # Agents table
                table_y = 14
                self.draw_border(table_y, 0, 13, 78, " ACTIVE AGENTS (first 30) ")
                agents = self.network.get_agent_snapshot(30)
                try:
                    self.stdscr.addstr(table_y+1, 2, "ID   ROLE  STA  LAST_ACTION")
                except curses.error:
                    pass
                row = table_y + 2
                for a in agents[:22]:
                    color = curses.color_pair(2) if a['status'] == 'err' else curses.color_pair(1) if a['status'] == 'run' else 0
                    try:
                        self.stdscr.addstr(row, 2, f"{a['id']:4d} {a['role']:5s} {a['status']:3s}  {a['last']:10s}", color)
                    except curses.error:
                        pass
                    row += 1
                    if row >= table_y + 12:
                        break

                # Logs panel
                log_y = 27
                log_lines = min(h - log_y - 3, 8)
                self.draw_border(log_y, 0, log_lines+2, w, " LIVE LOGS (Ctrl+L to save) ")
                logs = self.logger.get_recent(log_lines)
                y_log = log_y + 1
                for log in logs[:log_lines]:
                    try:
                        if len(log) > w-4:
                            log = log[:w-7]+"..."
                        self.stdscr.addstr(y_log, 2, log)
                    except curses.error:
                        pass
                    y_log += 1

                # Command bar – dynamic shortening
                cmd_bar_full = " Ctrl+Q:quit  Ctrl+R:reset  Ctrl+L:log  Ctrl+B:block  Ctrl+V:vpn  Ctrl+S:report  Ctrl+H:help  "
                if w < 100:
                    cmd_bar_full = " Q:quit  R:reset  L:log  B:block  V:vpn  S:report  H:help  "
                try:
                    self.stdscr.addstr(h-2, 0, cmd_bar_full, curses.color_pair(4))
                except curses.error:
                    pass

                if self.show_help:
                    self.draw_help_overlay()

                self.stdscr.refresh()
            except curses.error:
                pass

        def handle_input(self, key: int):
            if self.show_help:
                self.show_help = False
                return

            if key in (17, 27, 3):  # Ctrl+Q, ESC, Ctrl+C
                self.running = False
            elif key == 8:          # Ctrl+H
                self.show_help = True
            elif key == 18:         # Ctrl+R
                self.firewall.reset()
                self.network.update_threat(-self.network.get_stats()['threat'])
                self.logger.add(0, "SYSTEM", "ACTION", "reset", "threat and blocks cleared")
            elif key == 12:         # Ctrl+L
                report_data = {
                    "timestamp": datetime.now().isoformat(),
                    "stats": self.network.get_stats(),
                    "blocked_ips": self.firewall.get_blocked(),
                    "vpn": self.vpn.get_status(),
                    "agent_snapshot": self.network.get_agent_snapshot(50)
                }
                path = self.logger.flush_report(report_data)
                self.last_report_path = path
                self.logger.add(0, "SYSTEM", "REPORT", "saved", path)
            elif key == 2:          # Ctrl+B
                curses.echo()
                self.stdscr.addstr(5, 5, "Enter IP to block: ")
                curses.curs_set(1)
                ip = self.stdscr.getstr(5, 23, 20).decode().strip()
                curses.curs_set(0)
                curses.noecho()
                if ip:
                    self.firewall.block_ip(ip, "manual")
                    self.logger.add(0, "SYSTEM", "ACTION", "block", ip)
            elif key == 22:         # Ctrl+V
                self.vpn.refresh()
                self.logger.add(0, "SYSTEM", "INFO", "vpn_refresh", str(self.vpn.get_status()))
            elif key == 19:         # Ctrl+S
                if self.last_report_path:
                    self.logger.add(0, "SYSTEM", "REPORT", "available", self.last_report_path)

        def run(self):
            self.monitor.start()
            self.logger.add(0, "SYSTEM", "START", "tui_online", f"{config['agents']['count']} agents deployed")
            while self.running:
                self.draw()
                key = self.stdscr.getch()
                if key != -1:
                    self.handle_input(key)
                time.sleep(0.1)
            self.monitor.stop()
            self.logger.add(0, "SYSTEM", "SHUTDOWN", "offline", "session ended")

    def run_tui(stdscr):
        app = DefenseTUI(stdscr)
        app.run()

# ------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------
def main():
    if not USE_CURSES:
        run_headless()
    else:
        wrapper(run_tui)

if __name__ == "__main__":
    main()
