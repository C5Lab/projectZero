#!/usr/bin/env python3
"""
JanOS - ESP32-C5 Controller

Usage: ./JanOS_app.py <device>
Example: ./JanOS_app.py /dev/ttyUSB0
"""

import sys
import os
import time
import serial
import threading
import select
import termios
import fcntl
import tempfile
import re
import readline  # For better input handling
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any

# ============================================================================
# Configuration
# ============================================================================
BAUD_RATE = 115200
SCAN_TIMEOUT = 15
READ_TIMEOUT = 2
SNIFFER_UPDATE_INTERVAL = 1  # seconds
PORTAL_UPDATE_INTERVAL = 2   # seconds for portal monitoring
EVIL_TWIN_UPDATE_INTERVAL = 2  # seconds for evil twin monitoring

# ============================================================================
# Colors and Styling
# ============================================================================
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    GRAY = '\033[0;90m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'
    DIM = '\033[2m'

# Box drawing characters
BOX_TL = '╔'
BOX_TR = '╗'
BOX_BL = '╚'
BOX_BR = '╝'
BOX_H = '═'
BOX_V = '║'
BOX_LT = '╠'
BOX_RT = '╣'

# ============================================================================
# Utility Functions
# ============================================================================
def detect_os() -> str:
    """Detect the operating system."""
    if sys.platform.startswith('linux'):
        return 'linux'
    elif sys.platform.startswith('darwin'):
        return 'macos'
    else:
        return 'unknown'

def get_terminal_width() -> int:
    """Get terminal width."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        return 80

def center_text(text: str) -> str:
    """Center text in terminal."""
    width = get_terminal_width()
    text_len = len(strip_ansi(text))
    padding = max(0, (width - text_len) // 2)
    return " " * padding + text

def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def print_line(char: str = '═') -> None:
    """Print a horizontal line."""
    width = get_terminal_width()
    print(char * width)

def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('clear' if os.name != 'nt' else 'cls')

# ============================================================================
# UI Components
# ============================================================================
class UI:
    @staticmethod
    def print_box_top() -> None:
        width = get_terminal_width()
        inner_width = max(0, width - 2)
        print(f"{Colors.CYAN}{BOX_TL}{BOX_H * inner_width}{BOX_TR}{Colors.NC}")

    @staticmethod
    def print_box_bottom() -> None:
        width = get_terminal_width()
        inner_width = max(0, width - 2)
        print(f"{Colors.CYAN}{BOX_BL}{BOX_H * inner_width}{BOX_BR}{Colors.NC}")

    @staticmethod
    def print_box_separator() -> None:
        width = get_terminal_width()
        inner_width = max(0, width - 2)
        print(f"{Colors.CYAN}{BOX_LT}{BOX_H * inner_width}{BOX_RT}{Colors.NC}")

    @staticmethod
    def print_box_line() -> None:
        width = get_terminal_width()
        inner_width = max(0, width - 2)
        print(f"{Colors.CYAN}{BOX_V}{Colors.NC}{' ' * inner_width}{Colors.CYAN}{BOX_V}{Colors.NC}")

    @staticmethod
    def print_box_text(text: str, color: str = Colors.NC) -> None:
        width = get_terminal_width()
        inner_width = max(0, width - 4)
        text_clean = strip_ansi(text)
        text_len = len(text_clean)
        padding = max(0, inner_width - text_len)
        print(f"{Colors.CYAN}{BOX_V}{Colors.NC} {color}{text}{Colors.NC}{' ' * padding}{Colors.CYAN}{BOX_V}{Colors.NC}")

    @staticmethod
    def print_box_text_centered(text: str, color: str = Colors.NC) -> None:
        width = get_terminal_width()
        inner_width = max(0, width - 4)
        text_clean = strip_ansi(text)
        text_len = len(text_clean)
        left_pad = max(0, (inner_width - text_len) // 2)
        right_pad = max(0, inner_width - text_len - left_pad)
        print(f"{Colors.CYAN}{BOX_V}{Colors.NC}{' ' * left_pad}{color}{text}{Colors.NC}{' ' * right_pad}{Colors.CYAN}{BOX_V}{Colors.NC}")

    @staticmethod
    def print_banner(device: str, attack_running: bool = False, blackout_running: bool = False, 
                    sniffer_running: bool = False, sae_overflow_running: bool = False,
                    handshake_running: bool = False, portal_running: bool = False,
                    evil_twin_running: bool = False) -> None:
        banner = f"""{Colors.CYAN}
      ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗
      ██║██╔══██╗████╗  ██║██╔═══██╗██╔════╝
      ██║███████║██╔██╗ ██║██║   ██║███████╗
 ██   ██║██╔══██║██║╚██╗██║██║   ██║╚════██║
 ╚█████╔╝██║  ██║██║ ╚████║╚██████╔╝███████║
  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
{Colors.NC}"""
        print(banner)
        print(f"{Colors.GRAY}              for /LAB5/ devices{Colors.NC}")
        print(f"{Colors.GRAY}              Device: {Colors.WHITE}{device}{Colors.NC}")
        if attack_running:
            print(f"{Colors.RED}              ⚠  DEAUTH ATTACK RUNNING  ⚠{Colors.NC}")
        if blackout_running:
            print(f"{Colors.RED}              ⚠  BLACKOUT ATTACK RUNNING  ⚠{Colors.NC}")
        if sniffer_running:
            print(f"{Colors.CYAN}              📡  SNIFFER RUNNING  📡{Colors.NC}")
        if sae_overflow_running:
            print(f"{Colors.MAGENTA}              ⚠  WPA3 SAE OVERFLOW RUNNING  ⚠{Colors.NC}")
        if handshake_running:
            print(f"{Colors.YELLOW}              ⚠  HANDSHAKE CAPTURE RUNNING  ⚠{Colors.NC}")
        if portal_running:
            print(f"{Colors.BLUE}              🌐  CAPTIVE PORTAL RUNNING  🌐{Colors.NC}")
        if evil_twin_running:
            print(f"{Colors.MAGENTA}              👥  EVIL TWIN ATTACK RUNNING  👥{Colors.NC}")

    @staticmethod
    def print_main_menu() -> None:
        """Print the main menu with categories."""
        width = 60
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                      {Colors.WHITE}{Colors.BOLD}MAIN MENU{Colors.NC}                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}1){Colors.NC}  Scan Menu                                         {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}2){Colors.NC}  Sniffer Menu                                      {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}3){Colors.NC}  Attacks Menu                                      {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GRAY}0){Colors.NC}  Exit                                               {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()

    @staticmethod
    def print_scan_menu(network_count: int, selected_networks: str) -> None:
        """Print the scan submenu."""
        width = 60
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                     {Colors.WHITE}{Colors.BOLD}SCAN MENU{Colors.NC}                             {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}1){Colors.NC}  Scan Networks                                    {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}2){Colors.NC}  Show Scan Results                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}3){Colors.NC}  Select Networks                                  {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GRAY}0){Colors.NC}  Back to Main Menu                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Status line
        if network_count > 0:
            print(f"{Colors.GREEN}[+] Networks found: {network_count}{Colors.NC}")
        else:
            print(f"{Colors.GRAY}[-] No networks scanned{Colors.NC}")
        
        if selected_networks:
            print(f"{Colors.GREEN}[+] Selected: {selected_networks}{Colors.NC}")
        
        print()

    @staticmethod
    def print_sniffer_menu(sniffer_running: bool, packets_captured: int = 0) -> None:
        """Print the sniffer submenu."""
        width = 60
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                    {Colors.WHITE}{Colors.BOLD}SNIFFER MENU{Colors.NC}                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}1){Colors.NC}  Start Sniffer                                     {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}2){Colors.NC}  Show Results                                      {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}3){Colors.NC}  Show Probes                                       {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GRAY}0){Colors.NC}  Back to Main Menu                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Status line
        if sniffer_running:
            print(f"{Colors.CYAN}[📡] Sniffer is RUNNING{Colors.NC}")
            print(f"{Colors.CYAN}[+] Packets captured: {packets_captured}{Colors.NC}")
        else:
            print(f"{Colors.GRAY}[-] Sniffer not running{Colors.NC}")
        
        print()

    @staticmethod
    def print_attacks_menu(selected_networks: str, attack_running: bool, blackout_running: bool, 
                          sae_overflow_running: bool, handshake_running: bool, portal_running: bool,
                          evil_twin_running: bool) -> None:
        """Print the attacks submenu."""
        width = 60
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                    {Colors.WHITE}{Colors.BOLD}ATTACKS MENU{Colors.NC}                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}1){Colors.NC}  Start Deauth Attack                              {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}2){Colors.NC}  Blackout Attack                                  {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}3){Colors.NC}  WPA3 SAE Overflow                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}4){Colors.NC}  Handshake Capture                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}5){Colors.NC}  Portal Setup                                     {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.MAGENTA}6){Colors.NC}  Evil Twin Attack                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.RED}9){Colors.NC}  Stop All Attacks                                 {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GRAY}0){Colors.NC}  Back to Main Menu                                {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Status line
        if selected_networks:
            print(f"{Colors.GREEN}[+] Selected: {selected_networks}{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[!] No networks selected{Colors.NC}")
        
        if attack_running:
            print(f"{Colors.RED}[!] Deauth Attack is RUNNING{Colors.NC}")
        if blackout_running:
            print(f"{Colors.RED}[!] Blackout Attack is RUNNING{Colors.NC}")
        if sae_overflow_running:
            print(f"{Colors.MAGENTA}[!] WPA3 SAE Overflow is RUNNING{Colors.NC}")
        if handshake_running:
            print(f"{Colors.YELLOW}[!] Handshake Capture is RUNNING{Colors.NC}")
        if portal_running:
            print(f"{Colors.BLUE}[!] Captive Portal is RUNNING{Colors.NC}")
        if evil_twin_running:
            print(f"{Colors.MAGENTA}[!] Evil Twin Attack is RUNNING{Colors.NC}")
        if not attack_running and not blackout_running and not sae_overflow_running and not handshake_running and not portal_running and not evil_twin_running:
            print(f"{Colors.GRAY}[-] No attacks running{Colors.NC}")
        
        print()

    @staticmethod
    def print_portal_menu() -> None:
        """Print the portal setup submenu."""
        width = 60
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                    {Colors.WHITE}{Colors.BOLD}PORTAL SETUP{Colors.NC}                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}1){Colors.NC}  Setup and Start Captive Portal                   {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}2){Colors.NC}  Show Captured Data                               {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GRAY}0){Colors.NC}  Back to Attacks Menu                             {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()

    @staticmethod
    def print_evil_twin_menu() -> None:
        """Print the evil twin setup submenu."""
        width = 60
        
        print()
        print(f"{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                   {Colors.WHITE}{Colors.BOLD}EVIL TWIN SETUP{Colors.NC}                           {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}1){Colors.NC}  Setup and Start Evil Twin Attack                 {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GREEN}2){Colors.NC}  Show Captured Data                               {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}   {Colors.GRAY}0){Colors.NC}  Back to Attacks Menu                             {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()

# ============================================================================
# Serial Communication
# ============================================================================
class SerialManager:
    def __init__(self, device: str):
        self.device = device
        self.serial_conn = None
        self.baud_rate = BAUD_RATE
        self.os_type = detect_os()
        self.setup_serial()
    
    def setup_serial(self) -> None:
        """Setup serial connection."""
        if not os.path.exists(self.device):
            print(f"{Colors.RED}Error: Device {self.device} does not exist{Colors.NC}")
            sys.exit(1)
        
        # Check permissions
        if not os.access(self.device, os.R_OK | os.W_OK):
            print(f"{Colors.RED}Error: No read/write access to '{self.device}'{Colors.NC}")
            print()
            print("Try running with sudo or add your user to the dialout group:")
            print("  sudo usermod -a -G dialout $USER  # Linux")
            print("  # Then log out and log back in")
            sys.exit(1)
        
        try:
            # Use Python's serial library for better cross-platform support
            self.serial_conn = serial.Serial(
                port=self.device,
                baudrate=self.baud_rate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=READ_TIMEOUT,
                write_timeout=2
            )
            # Clear any existing data
            self.serial_conn.reset_input_buffer()
            self.serial_conn.reset_output_buffer()
            
        except Exception as e:
            print(f"{Colors.RED}Error opening serial port: {e}{Colors.NC}")
            sys.exit(1)
    
    def send_command(self, command: str) -> None:
        """Send command to ESP32."""
        if not self.serial_conn:
            print(f"{Colors.RED}Serial connection not established{Colors.NC}")
            return
        
        try:
            full_command = command + "\r\n"
            self.serial_conn.write(full_command.encode('utf-8'))
            self.serial_conn.flush()
            time.sleep(0.1)
        except Exception as e:
            print(f"{Colors.RED}Error sending command: {e}{Colors.NC}")
    
    def read_response(self, timeout: float = SCAN_TIMEOUT) -> List[str]:
        """Read response from ESP32 with timeout."""
        if not self.serial_conn:
            return []
        
        lines = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.serial_conn.in_waiting:
                try:
                    line = self.serial_conn.readline().decode('utf-8', errors='replace').strip()
                    if line:
                        lines.append(line)
                except Exception as e:
                    print(f"{Colors.YELLOW}Read error: {e}{Colors.NC}")
                    continue
            else:
                # Small sleep to prevent CPU spinning
                time.sleep(0.1)
        
        return lines
    
    def read_sniffer_data(self, update_callback, stop_event) -> None:
        """Read sniffer data with dynamic update."""
        if not self.serial_conn:
            return
        
        while not stop_event.is_set():
            if self.serial_conn.in_waiting:
                try:
                    line = self.serial_conn.readline().decode('utf-8', errors='replace').strip()
                    if line:
                        # Look for packet count in sniffer output
                        if "packets" in line.lower() or "captured" in line.lower():
                            update_callback(line)
                except Exception:
                    pass
            time.sleep(0.1)
    
    def read_portal_data(self, update_callback, stop_event) -> None:
        """Read portal data with real-time updates."""
        if not self.serial_conn:
            return
        
        while not stop_event.is_set():
            if self.serial_conn.in_waiting:
                try:
                    line = self.serial_conn.readline().decode('utf-8', errors='replace').strip()
                    if line:
                        update_callback(line)
                except Exception:
                    pass
            time.sleep(0.1)
    
    def read_evil_twin_data(self, update_callback, stop_event) -> None:
        """Read evil twin data with real-time updates."""
        if not self.serial_conn:
            return
        
        while not stop_event.is_set():
            if self.serial_conn.in_waiting:
                try:
                    line = self.serial_conn.readline().decode('utf-8', errors='replace').strip()
                    if line:
                        update_callback(line)
                except Exception:
                    pass
            time.sleep(0.1)
    
    def close(self) -> None:
        """Close serial connection."""
        if self.serial_conn:
            self.serial_conn.close()

# ============================================================================
# Network Management
# ============================================================================
class NetworkManager:
    def __init__(self):
        self.networks: List[Dict[str, str]] = []
        self.network_count = 0
        self.selected_networks = ""
        self.scan_done = False
    
    def parse_network_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a network line from ESP32 output."""
        # Expected format: "index","ssid","vendor","bssid","channel","auth","rssi","band"
        if not line.startswith('"'):
            return None
        
        try:
            # Simple CSV parsing
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 8:
                return None
            
            network = {
                'index': parts[0],
                'ssid': parts[1] if parts[1] else "<hidden>",
                'vendor': parts[2],
                'bssid': parts[3],
                'channel': parts[4],
                'auth': parts[5],
                'rssi': parts[6],
                'band': parts[7]
            }
            return network
        except:
            return None
    
    def add_network(self, line: str) -> None:
        """Add a network from parsed line."""
        network = self.parse_network_line(line)
        if network:
            self.networks.append(network)
            self.network_count += 1
    
    def clear_networks(self) -> None:
        """Clear all networks."""
        self.networks.clear()
        self.network_count = 0
        self.scan_done = False
    
    def set_selected_networks(self, selection: str) -> None:
        """Set selected networks."""
        self.selected_networks = selection
    
    def get_rssi_color(self, rssi_str: str) -> str:
        """Get color code for RSSI value."""
        if not rssi_str:
            return Colors.GRAY
        
        try:
            # Extract numeric value
            rssi_num = int(rssi_str.replace('dBm', '').strip())
            if rssi_num < -70:
                return Colors.RED
            elif rssi_num < -50:
                return Colors.YELLOW
            else:
                return Colors.GREEN
        except:
            return Colors.GRAY
    
    def display_networks(self) -> None:
        """Display networks in a table."""
        if self.network_count == 0:
            print(f"{Colors.YELLOW}[!] No networks scanned yet. Run a scan first.{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        clear_screen()
        print()
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.WHITE}#{Colors.NC}   {Colors.WHITE}SSID{Colors.NC}                        {Colors.WHITE}BSSID{Colors.NC}              {Colors.WHITE}CH{Colors.NC}  {Colors.WHITE}RSSI{Colors.NC}  {Colors.WHITE}Auth{Colors.NC}         {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        
        for network in self.networks:
            idx = network.get('index', '?')
            ssid = network.get('ssid', '?')
            bssid = network.get('bssid', '?')
            channel = network.get('channel', '?')
            auth = network.get('auth', '?')
            rssi = network.get('rssi', '?')
            
            # Truncate SSID if too long
            if len(ssid) > 24:
                ssid = ssid[:21] + "..."
            
            # Truncate auth if too long
            if len(auth) > 12:
                auth = auth[:10] + ".."
            
            rssi_color = self.get_rssi_color(rssi)
            
            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GREEN}{idx:<3}{Colors.NC} {ssid:<26} {Colors.GRAY}{bssid:<17}{Colors.NC} {channel:<3} {rssi_color}{rssi:<5}{Colors.NC} {auth:<12}{Colors.CYAN}║{Colors.NC}")
        
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        if self.selected_networks:
            print(f"{Colors.GREEN}[+] Selected networks: {Colors.WHITE}{self.selected_networks}{Colors.NC}")
        
        print()
        input("Press Enter to continue...")

# ============================================================================
# Main Application
# ============================================================================
class JanOS:
    def __init__(self, device: str):
        self.device = device
        self.serial_mgr = SerialManager(device)
        self.network_mgr = NetworkManager()
        self.attack_running = False
        self.blackout_running = False
        self.sniffer_running = False
        self.sae_overflow_running = False
        self.handshake_running = False
        self.portal_running = False
        self.evil_twin_running = False
        self.sniffer_packets = 0
        self.sniffer_thread = None
        self.stop_sniffer_event = threading.Event()
        self.portal_thread = None
        self.stop_portal_event = threading.Event()
        self.evil_twin_thread = None
        self.stop_evil_twin_event = threading.Event()
        self.portal_html_files = []
        self.selected_html_index = -1
        self.selected_html_name = ""
        self.portal_ssid = ""
        self.submitted_forms = 0
        self.last_submitted_data = ""
        self.client_count = 0
        self.evil_twin_ssid = ""
        self.evil_twin_captured_data = []
        self.evil_twin_client_count = 0
        self.os_type = detect_os()
        
        if self.os_type == 'unknown':
            print(f"{Colors.RED}Error: Unsupported operating system{Colors.NC}")
            sys.exit(1)
    
    def show_usage(self) -> None:
        """Show usage information."""
        print(f"{Colors.CYAN}JanOS Controller{Colors.NC} - ESP32-C5 Wireless Controller")
        print()
        print("Usage: ./janos_controller.py <device>")
        print()
        print("Arguments:")
        print("  device    Serial device path (e.g., /dev/ttyUSB0, /dev/cu.usbserial-*)")
        print()
        print("Examples:")
        print("  ./janos_controller.py /dev/ttyUSB0        # Linux")
        print("  ./janos_controller.py /dev/cu.usbserial-0001  # macOS")
        print()
    
    def update_sniffer_display(self, data: str) -> None:
        """Update sniffer packet count from received data."""
        # Try to extract packet count from the data
        import re
        match = re.search(r'(\d+)\s+packets?', data, re.IGNORECASE)
        if match:
            self.sniffer_packets = int(match.group(1))
        elif "captured" in data.lower():
            # Another common format
            match = re.search(r'captured:\s*(\d+)', data, re.IGNORECASE)
            if match:
                self.sniffer_packets = int(match.group(1))
    
    def update_portal_display(self, data: str) -> None:
        """Update portal display with real-time data."""
        # Check for client connections
        if "Client connected" in data:
            self.client_count += 1
            print(f"\n{Colors.GREEN}[+] {data}{Colors.NC}")
        
        # Check for client count updates
        elif "Client count" in data:
            match = re.search(r'Client count = (\d+)', data)
            if match:
                self.client_count = int(match.group(1))
                print(f"{Colors.BLUE}[*] Connected clients: {self.client_count}{Colors.NC}")
        
        # Check for password submissions
        elif "Password:" in data:
            self.submitted_forms += 1
            # Extract password from the line
            password_match = re.search(r'Password:\s*(.+)$', data)
            if password_match:
                password = password_match.group(1)
                self.last_submitted_data = f"Password: {password}"
                print(f"\n{Colors.GREEN}[+] Form submitted!{Colors.NC}")
                print(f"{Colors.GREEN}[+] Password captured: {password}{Colors.NC}")
        
        # Check for form data with other fields
        elif "Form data:" in data or "username:" in data.lower() or "email:" in data.lower():
            self.submitted_forms += 1
            self.last_submitted_data = data
            print(f"\n{Colors.GREEN}[+] Form submitted!{Colors.NC}")
            print(f"{Colors.GREEN}[+] {data}{Colors.NC}")
        
        # Check for data saved to file
        elif "Portal data saved" in data:
            print(f"{Colors.BLUE}[*] {data}{Colors.NC}")
        
        # Check for portal errors or status
        elif "error" in data.lower() or "failed" in data.lower():
            print(f"{Colors.RED}[!] {data}{Colors.NC}")
        elif "started successfully" in data or "enabled" in data:
            print(f"{Colors.GREEN}[+] {data}{Colors.NC}")
    
    def update_evil_twin_display(self, data: str) -> None:
        """Update evil twin display with real-time data."""
        # Check for client connections
        if "Client connected" in data:
            self.evil_twin_client_count += 1
            print(f"\n{Colors.GREEN}[+] {data}{Colors.NC}")
        
        # Check for client trying to connect to evil twin
        elif "trying to connect" in data.lower() or "association" in data.lower():
            print(f"{Colors.MAGENTA}[*] {data}{Colors.NC}")
        
        # Check for password submissions or handshake captures
        elif "Password:" in data or "Handshake captured" in data:
            self.evil_twin_captured_data.append(data)
            print(f"\n{Colors.MAGENTA}[+] {data}{Colors.NC}")
        
        # Check for handshake files
        elif ".pcap" in data or ".cap" in data or "handshake saved" in data.lower():
            print(f"{Colors.GREEN}[+] {data}{Colors.NC}")
        
        # Check for evil twin errors or status
        elif "error" in data.lower() or "failed" in data.lower():
            print(f"{Colors.RED}[!] {data}{Colors.NC}")
        elif "started successfully" in data or "broadcasting" in data:
            print(f"{Colors.GREEN}[+] {data}{Colors.NC}")
    
    def do_scan(self) -> None:
        """Perform network scan."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.YELLOW}[*] Initiating network scan...{Colors.NC}")
        print(f"{Colors.GRAY}    This may take up to {SCAN_TIMEOUT} seconds{Colors.NC}")
        print()
        
        # Clear previous networks
        self.network_mgr.clear_networks()
        
        # Send scan command
        self.serial_mgr.send_command("scan_networks")
        
        # Read response with progress display
        start_time = time.time()
        print(f"{Colors.MAGENTA}[DEBUG] Starting scan...{Colors.NC}")
        print()
        
        # Read lines from serial
        try:
            while time.time() - start_time < SCAN_TIMEOUT:
                elapsed = int(time.time() - start_time)
                print(f"\r    Elapsed: {elapsed}s / {SCAN_TIMEOUT}s  ", end="", flush=True)
                
                lines = self.serial_mgr.read_response(timeout=1)
                for line in lines:
                    print(f"\n[SERIAL] {line}")
                    
                    # Parse network lines
                    if line.startswith('"'):
                        self.network_mgr.add_network(line)
                    
                    # Check if scan is complete
                    if "Scan results printed" in line:
                        print(f"\n{Colors.GREEN}[+] Scan complete!{Colors.NC}")
                        self.network_mgr.scan_done = True
                        print()
                        input("Press Enter to continue...")
                        return
                
                if self.network_mgr.scan_done:
                    break
                
                time.sleep(0.1)
            
            if not self.network_mgr.scan_done:
                print(f"\n{Colors.YELLOW}[!] Timeout reached{Colors.NC}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.NC}")
        
        print()
        
        if self.network_mgr.network_count > 0:
            print(f"{Colors.GREEN}[+] Found {self.network_mgr.network_count} networks!{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[!] No networks found{Colors.NC}")
        
        print()
        input("Press Enter to continue...")
    
    def select_networks_menu(self) -> None:
        """Network selection menu."""
        if self.network_mgr.network_count == 0:
            print(f"{Colors.YELLOW}[!] No networks scanned yet. Run a scan first.{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        
        # Display networks briefly
        print(f"{Colors.CYAN}Available networks:{Colors.NC}")
        print()
        for network in self.network_mgr.networks:
            idx = network.get('index', '?')
            ssid = network.get('ssid', '?')
            rssi = network.get('rssi', '?')
            print(f"  {Colors.GREEN}[{idx}]{Colors.NC} {ssid} {Colors.GRAY}(RSSI: {rssi}){Colors.NC}")
        
        print()
        print(f"{Colors.WHITE}Enter network numbers separated by spaces (e.g., 1 3 5){Colors.NC}")
        print(f"{Colors.GRAY}Or enter 'all' to select all networks{Colors.NC}")
        print()
        
        try:
            selection = input("Selection: ").strip()
        except EOFError:
            return
        
        if not selection:
            print(f"{Colors.YELLOW}[!] No selection made{Colors.NC}")
            time.sleep(1)
            return
        
        # Handle 'all' selection
        if selection.lower() == 'all':
            selection = ' '.join(str(i+1) for i in range(self.network_mgr.network_count))
        
        # Validate selection (basic check for numbers and spaces)
        if not re.match(r'^[\d\s]+$', selection):
            print(f"{Colors.RED}[!] Invalid selection. Use numbers separated by spaces.{Colors.NC}")
            time.sleep(2)
            return
        
        self.network_mgr.set_selected_networks(selection)
        
        print()
        print(f"{Colors.YELLOW}[*] Sending selection to device...{Colors.NC}")
        self.serial_mgr.send_command(f"select_networks {selection}")
        time.sleep(1)
        
        print(f"{Colors.GREEN}[+] Networks selected: {Colors.WHITE}{selection}{Colors.NC}")
        time.sleep(1)
    
    def start_sniffer(self) -> None:
        """Start sniffer with dynamic packet counter."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                      {Colors.WHITE}{Colors.BOLD}📡  SNIFFER MODE  📡{Colors.NC}                                  {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.YELLOW}Starting WiFi packet sniffer...{Colors.NC}                                             {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GRAY}The sniffer will capture all WiFi packets in range.{Colors.NC}                            {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GRAY}Press ANY key to stop sniffing.{Colors.NC}                                             {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Check if we have scanned networks
        if self.network_mgr.network_count > 0:
            print(f"{Colors.YELLOW}[*] Networks already scanned. Starting sniffer without scanning...{Colors.NC}")
            self.serial_mgr.send_command("start_sniffer_noscan")
        else:
            print(f"{Colors.YELLOW}[*] No networks scanned yet. Sniffer will scan networks first...{Colors.NC}")
            self.serial_mgr.send_command("start_sniffer")
        
        # Reset packet counter
        self.sniffer_packets = 0
        self.sniffer_running = True
        
        # Start background thread for reading sniffer data
        self.stop_sniffer_event.clear()
        self.sniffer_thread = threading.Thread(
            target=self.serial_mgr.read_sniffer_data,
            args=(self.update_sniffer_display, self.stop_sniffer_event)
        )
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
        print(f"{Colors.CYAN}[+] Sniffer started!{Colors.NC}")
        print(f"{Colors.CYAN}[📡] Capturing packets...{Colors.NC}")
        print()
        print(f"{Colors.WHITE}Press ANY key to stop sniffing{Colors.NC}")
        print()
        
        # Dynamic packet counter display
        last_packet_count = -1
        start_time = time.time()
        
        try:
            # Wait for any key press
            print(f"{Colors.GRAY}Waiting for key press to stop...{Colors.NC}")
            import sys
            import termios
            import tty
            
            # Save terminal settings
            old_settings = termios.tcgetattr(sys.stdin)
            try:
                # Set terminal to raw mode
                tty.setraw(sys.stdin.fileno())
                
                while True:
                    # Check for any key press
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        key = sys.stdin.read(1)
                        if key:  # Any key pressed
                            break
                    
                    # Update display if packet count changed
                    if self.sniffer_packets != last_packet_count:
                        elapsed = int(time.time() - start_time)
                        print(f"\r{Colors.CYAN}[📡] Packets captured: {Colors.WHITE}{self.sniffer_packets}{Colors.CYAN} | Time: {elapsed}s{Colors.NC}", end="", flush=True)
                        last_packet_count = self.sniffer_packets
                    
                    time.sleep(SNIFFER_UPDATE_INTERVAL)
            
            finally:
                # Restore terminal settings
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        
        except KeyboardInterrupt:
            pass
        
        finally:
            # Stop sniffer
            print(f"\n{Colors.YELLOW}[*] Stopping sniffer...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.sniffer_running = False
            self.stop_sniffer_event.set()
            
            if self.sniffer_thread:
                self.sniffer_thread.join(timeout=2)
            
            print(f"{Colors.GREEN}[+] Sniffer stopped{Colors.NC}")
            print(f"{Colors.GREEN}[+] Total packets captured: {self.sniffer_packets}{Colors.NC}")
            print()
            input("Press Enter to continue...")
    
    def show_sniffer_results(self) -> None:
        """Show sniffer results with proper parsing."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                   {Colors.WHITE}{Colors.BOLD}📡  SNIFFER RESULTS  📡{Colors.NC}                                 {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        
        if self.sniffer_running:
            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.YELLOW}Sniffer is currently running. Stopping to show results...{Colors.NC}                     {Colors.CYAN}║{Colors.NC}")
            print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        
        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.YELLOW}Total packets captured: {Colors.WHITE}{self.sniffer_packets}{Colors.NC}{' ' * (40 - len(str(self.sniffer_packets)))}{Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Stop sniffer if it's running to get results
        if self.sniffer_running:
            print(f"{Colors.YELLOW}[*] Stopping sniffer to show results...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.sniffer_running = False
            self.stop_sniffer_event.set()
            time.sleep(1)
        
        # Request results from ESP32
        print(f"{Colors.CYAN}[*] Requesting sniffer results from device...{Colors.NC}")
        self.serial_mgr.send_command("show_sniffer_results")
        
        # Read and display results
        print(f"{Colors.CYAN}[*] Reading results...{Colors.NC}")
        print()
        
        lines = self.serial_mgr.read_response(timeout=5)
        
        if lines:
            # Parse and display results in a table
            print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.WHITE}Type{Colors.NC}       {Colors.WHITE}Source MAC{Colors.NC}         {Colors.WHITE}Destination MAC{Colors.NC}    {Colors.WHITE}Size{Colors.NC}  {Colors.WHITE}Info{Colors.NC}      {Colors.CYAN}║{Colors.NC}")
            print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
            
            packet_count = 0
            for line in lines:
                if line and not line.startswith("Sniffer") and not line.startswith("Total"):  # Filter header lines
                    # Try to parse different packet formats
                    parts = line.split()
                    if len(parts) >= 5:
                        # Common WiFi packet format
                        pkt_type = parts[0]
                        src_mac = parts[1] if len(parts) > 1 else "N/A"
                        dst_mac = parts[2] if len(parts) > 2 else "N/A"
                        size = parts[3] if len(parts) > 3 else "N/A"
                        info = " ".join(parts[4:]) if len(parts) > 4 else ""
                        
                        # Color code packet types
                        if "BEACON" in pkt_type.upper():
                            pkt_color = Colors.GREEN
                        elif "PROBE" in pkt_type.upper():
                            pkt_color = Colors.YELLOW
                        elif "DATA" in pkt_type.upper():
                            pkt_color = Colors.CYAN
                        elif "AUTH" in pkt_type.upper() or "DEAUTH" in pkt_type.upper():
                            pkt_color = Colors.RED
                        else:
                            pkt_color = Colors.GRAY
                        
                        # Truncate if too long
                        if len(info) > 15:
                            info = info[:12] + "..."
                        
                        print(f"{Colors.CYAN}║{Colors.NC}  {pkt_color}{pkt_type:<10}{Colors.NC} {src_mac:<17} {dst_mac:<17} {size:<5} {info:<15}{Colors.CYAN}║{Colors.NC}")
                        packet_count += 1
                    elif line.strip():  # Show any non-empty line
                        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GRAY}{line:<70}{Colors.NC}  {Colors.CYAN}║{Colors.NC}")
            
            print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
            print()
            print(f"{Colors.GREEN}[+] Displayed {packet_count} packets{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[!] No results received from device{Colors.NC}")
            print(f"{Colors.YELLOW}[*] Try starting the sniffer first to capture packets{Colors.NC}")
        
        print()
        input("Press Enter to continue...")
    
    def show_sniffer_probes(self) -> None:
        """Show probe requests from sniffer with proper parsing."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                    {Colors.WHITE}{Colors.BOLD}📡  PROBE REQUESTS  📡{Colors.NC}                                 {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        
        if self.sniffer_running:
            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.YELLOW}Sniffer is currently running. Stopping to show probe requests...{Colors.NC}              {Colors.CYAN}║{Colors.NC}")
            print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        
        print(f"{Colors.CYAN}║{Colors.NC}  {Colors.YELLOW}Total packets captured: {Colors.WHITE}{self.sniffer_packets}{Colors.NC}{' ' * (40 - len(str(self.sniffer_packets)))}{Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}║{Colors.NC}                                                                              {Colors.CYAN}║{Colors.NC}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Stop sniffer if it's running to get results
        if self.sniffer_running:
            print(f"{Colors.YELLOW}[*] Stopping sniffer to show probe requests...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.sniffer_running = False
            self.stop_sniffer_event.set()
            time.sleep(1)
        
        # Request probe results from ESP32
        print(f"{Colors.CYAN}[*] Requesting probe requests from device...{Colors.NC}")
        self.serial_mgr.send_command("show_probes")
        
        # Read and display results
        print(f"{Colors.CYAN}[*] Reading probe requests...{Colors.NC}")
        print()
        
        lines = self.serial_mgr.read_response(timeout=5)
        
        if lines:
            # Parse and display probe requests in a table
            print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.WHITE}#{Colors.NC}  {Colors.WHITE}Client MAC{Colors.NC}             {Colors.WHITE}SSID{Colors.NC}                           {Colors.WHITE}RSSI{Colors.NC}   {Colors.WHITE}Time{Colors.NC}    {Colors.CYAN}║{Colors.NC}")
            print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
            
            probe_count = 0
            for line in lines:
                if line and not line.startswith("Probe") and not line.startswith("Total"):  # Filter header lines
                    probe_count += 1
                    
                    # Try different parsing formats for probe requests
                    # Format 1: "Client: AA:BB:CC:DD:EE:FF, SSID: MyNetwork, RSSI: -45"
                    # Format 2: "AA:BB:CC:DD:EE:FF -> MyNetwork (-55dBm)"
                    # Format 3: "Probe: AA:BB:CC:DD:EE:FF looking for SSID"
                    
                    client_mac = "N/A"
                    ssid = "<hidden>"
                    rssi = "N/A"
                    timestamp = ""
                    
                    # Parse MAC address (look for XX:XX:XX:XX:XX:XX pattern)
                    mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                    mac_match = re.search(mac_pattern, line)
                    if mac_match:
                        client_mac = mac_match.group(0)
                    
                    # Parse SSID (look for text after "SSID:", "->", or "looking for")
                    if "SSID:" in line:
                        ssid_part = line.split("SSID:")[1].split(",")[0].strip()
                        if ssid_part and ssid_part not in ["N/A", "unknown"]:
                            ssid = ssid_part
                    elif "->" in line:
                        ssid_part = line.split("->")[1].split("(")[0].strip()
                        if ssid_part and ssid_part not in ["N/A", "unknown"]:
                            ssid = ssid_part
                    elif "looking for" in line:
                        ssid_part = line.split("looking for")[1].strip()
                        if ssid_part and ssid_part not in ["N/A", "unknown"]:
                            ssid = ssid_part
                    
                    # Parse RSSI (look for numbers with minus sign or "dBm")
                    rssi_pattern = r'(-?\d+)\s*dBm?'
                    rssi_match = re.search(rssi_pattern, line, re.IGNORECASE)
                    if rssi_match:
                        rssi = rssi_match.group(1) + "dBm"
                    
                    # Parse timestamp if present
                    time_pattern = r'\[(\d+:\d+:\d+)\]'
                    time_match = re.search(time_pattern, line)
                    if time_match:
                        timestamp = time_match.group(1)
                    
                    # Truncate SSID if too long
                    if len(ssid) > 30:
                        ssid = ssid[:27] + "..."
                    
                    # Color code RSSI
                    if rssi != "N/A" and "dBm" in rssi:
                        try:
                            rssi_val = int(rssi.replace("dBm", "").strip())
                            if rssi_val >= -50:
                                rssi_color = Colors.GREEN
                            elif rssi_val >= -70:
                                rssi_color = Colors.YELLOW
                            else:
                                rssi_color = Colors.RED
                        except:
                            rssi_color = Colors.GRAY
                    else:
                        rssi_color = Colors.GRAY
                    
                    print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GREEN}{probe_count:<2}{Colors.NC} {Colors.GRAY}{client_mac:<17}{Colors.NC} {ssid:<30} {rssi_color}{rssi:<6}{Colors.NC} {timestamp:<8}  {Colors.CYAN}║{Colors.NC}")
            
            print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
            print()
            print(f"{Colors.GREEN}[+] Found {probe_count} probe requests{Colors.NC}")
            
            # Show summary
            if probe_count > 0:
                print(f"{Colors.CYAN}[*] Probe request summary:{Colors.NC}")
                print(f"{Colors.CYAN}    - Shows devices searching for WiFi networks{Colors.NC}")
                print(f"{Colors.CYAN}    - Useful for discovering hidden networks and client behavior{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[!] No probe requests received from device{Colors.NC}")
            print(f"{Colors.YELLOW}[*] Try starting the sniffer first to capture probe requests{Colors.NC}")
        
        print()
        input("Press Enter to continue...")
    
    def start_deauth_attack(self) -> None:
        """Start deauth attack."""
        if not self.network_mgr.selected_networks:
            print(f"{Colors.YELLOW}[!] No networks selected. Select networks first.{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.RED}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                      {Colors.WHITE}{Colors.BOLD}⚠  DEAUTH ATTACK  ⚠{Colors.NC}                                  {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                                                                              {Colors.RED}║{Colors.NC}")
        
        # Calculate padding for selected networks display
        selected_len = len(self.network_mgr.selected_networks)
        padding = max(0, 45 - selected_len)
        
        print(f"{Colors.RED}║{Colors.NC}  {Colors.YELLOW}Target networks: {Colors.WHITE}{self.network_mgr.selected_networks}{Colors.NC}{' ' * padding}{Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                                                                              {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}  {Colors.GRAY}This attack will send deauthentication frames to disconnect{Colors.NC}              {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}  {Colors.GRAY}clients from the selected access points.{Colors.NC}                                  {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                                                                              {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        try:
            confirm = input("Start attack? [y/N]: ").strip().lower()
        except EOFError:
            return
        
        if confirm not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[!] Attack cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        print()
        print(f"{Colors.RED}[*] Starting deauth attack...{Colors.NC}")
        self.serial_mgr.send_command("start_deauth")
        self.attack_running = True
        
        print(f"{Colors.RED}[+] Attack is running!{Colors.NC}")
        print()
        print(f"{Colors.WHITE}Press Enter to return to menu (attack continues in background){Colors.NC}")
        input()
    
    def start_blackout_attack(self) -> None:
        """Start blackout attack."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.RED}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                     {Colors.WHITE}{Colors.BOLD}⚠  BLACKOUT ATTACK  ⚠{Colors.NC}                                 {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                                                                              {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}  {Colors.YELLOW}Blackout Attack will jam all WiFi networks in range{Colors.NC}                          {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}  {Colors.YELLOW}creating complete wireless blackout.{Colors.NC}                                           {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                                                                              {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}  {Colors.RED}⚠  WARNING: This affects ALL networks in range!{Colors.NC}                                 {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}║{Colors.NC}                                                                              {Colors.RED}║{Colors.NC}")
        print(f"{Colors.RED}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        try:
            confirm = input("Start Blackout attack? [y/N]: ").strip().lower()
        except EOFError:
            return
        
        if confirm not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[!] Attack cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        print()
        print(f"{Colors.RED}[*] Starting blackout attack...{Colors.NC}")
        self.serial_mgr.send_command("start_blackout")
        self.blackout_running = True
        
        print(f"{Colors.RED}[+] Blackout attack is running!{Colors.NC}")
        print()
        print(f"{Colors.WHITE}Press Enter to return to menu (attack continues in background){Colors.NC}")
        input()
    
    def start_sae_overflow_attack(self) -> None:
        """Start WPA3 SAE Overflow attack."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                   {Colors.WHITE}{Colors.BOLD}⚠  WPA3 SAE OVERFLOW  ⚠{Colors.NC}                                 {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.YELLOW}WPA3 SAE Overflow attack targets WPA3 networks{Colors.NC}                                 {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.YELLOW}using Simultaneous Authentication of Equals (SAE).{Colors.NC}                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.RED}⚠  WARNING: This attack is for educational purposes only!{Colors.NC}                       {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        try:
            confirm = input("Start WPA3 SAE Overflow attack? [y/N]: ").strip().lower()
        except EOFError:
            return
        
        if confirm not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[!] Attack cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        print()
        print(f"{Colors.MAGENTA}[*] Starting WPA3 SAE Overflow attack...{Colors.NC}")
        self.serial_mgr.send_command("sae_overflow")
        self.sae_overflow_running = True
        
        print(f"{Colors.MAGENTA}[+] WPA3 SAE Overflow attack is running!{Colors.NC}")
        print()
        print(f"{Colors.WHITE}Press Enter to return to menu (attack continues in background){Colors.NC}")
        input()
    
    def start_handshake_attack(self) -> None:
        """Start WPA Handshake Capture attack."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.YELLOW}║{Colors.NC}                 {Colors.WHITE}{Colors.BOLD}⚠  WPA HANDSHAKE CAPTURE  ⚠{Colors.NC}                               {Colors.YELLOW}║{Colors.NC}")
        print(f"{Colors.YELLOW}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.YELLOW}║{Colors.NC}                                                                              {Colors.YELLOW}║{Colors.NC}")
        
        if self.network_mgr.selected_networks:
            selected_len = len(self.network_mgr.selected_networks)
            padding = max(0, 45 - selected_len)
            print(f"{Colors.YELLOW}║{Colors.NC}  {Colors.GREEN}Target networks: {Colors.WHITE}{self.network_mgr.selected_networks}{Colors.NC}{' ' * padding}{Colors.YELLOW}║{Colors.NC}")
            print(f"{Colors.YELLOW}║{Colors.NC}  {Colors.GRAY}Attack will target ONLY selected networks{Colors.NC}                                       {Colors.YELLOW}║{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}║{Colors.NC}  {Colors.YELLOW}No networks selected{Colors.NC}                                                         {Colors.YELLOW}║{Colors.NC}")
            print(f"{Colors.YELLOW}║{Colors.NC}  {Colors.GRAY}Attack will scan every 5 minutes and target ALL networks{Colors.NC}                       {Colors.YELLOW}║{Colors.NC}")
        
        print(f"{Colors.YELLOW}║{Colors.NC}                                                                              {Colors.YELLOW}║{Colors.NC}")
        print(f"{Colors.YELLOW}║{Colors.NC}  {Colors.YELLOW}This attack captures WPA/WPA2 handshakes for password cracking.{Colors.NC}                   {Colors.YELLOW}║{Colors.NC}")
        print(f"{Colors.YELLOW}║{Colors.NC}  {Colors.GRAY}Captured handshakes can be used with tools like hashcat or aircrack-ng.{Colors.NC}            {Colors.YELLOW}║{Colors.NC}")
        print(f"{Colors.YELLOW}║{Colors.NC}                                                                              {Colors.YELLOW}║{Colors.NC}")
        print(f"{Colors.YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        try:
            confirm = input("Start Handshake Capture attack? [y/N]: ").strip().lower()
        except EOFError:
            return
        
        if confirm not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[!] Attack cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        print()
        print(f"{Colors.YELLOW}[*] Starting Handshake Capture attack...{Colors.NC}")
        self.serial_mgr.send_command("start_handshake")
        self.handshake_running = True
        
        print(f"{Colors.YELLOW}[+] Handshake Capture attack is running!{Colors.NC}")
        
        if self.network_mgr.selected_networks:
            print(f"{Colors.YELLOW}[*] Targeting selected networks: {self.network_mgr.selected_networks}{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[*] Scanning all networks every 5 minutes{Colors.NC}")
        
        print()
        print(f"{Colors.WHITE}Press Enter to return to menu (attack continues in background){Colors.NC}")
        input()
    
    def get_html_files_from_sd(self) -> bool:
        """Get HTML files from SD card and parse them."""
        print(f"{Colors.BLUE}[*] Requesting list of HTML files from SD card...{Colors.NC}")
        self.serial_mgr.send_command("list_sd")
        
        # Wait a moment for the command to be processed
        time.sleep(1)
        
        # Read response
        lines = self.serial_mgr.read_response(timeout=3)
        
        self.portal_html_files = []
        file_count = 0
        
        if lines:
            print(f"{Colors.BLUE}[*] Parsing HTML files...{Colors.NC}")
            for line in lines:
                # Look for file entries (lines with numbers and .html extension)
                if re.search(r'^\s*\d+\s+\S+\.html\s*$', line):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        file_num = parts[0]
                        file_name = parts[1]
                        self.portal_html_files.append({
                            'number': file_num,
                            'name': file_name,
                            'display': line.strip()
                        })
                        file_count += 1
                elif "HTML files found on SD card:" in line:
                    print(f"{Colors.GREEN}[+] {line}{Colors.NC}")
        
        if file_count > 0:
            print(f"{Colors.GREEN}[+] Found {file_count} HTML files on SD card{Colors.NC}")
            return True
        else:
            print(f"{Colors.YELLOW}[!] No HTML files found on SD card{Colors.NC}")
            print(f"{Colors.YELLOW}[*] Make sure SD card is inserted and contains HTML files{Colors.NC}")
            return False
    
    def select_html_file_menu(self) -> bool:
        """Display HTML file selection menu and get user choice."""
        if not self.portal_html_files:
            print(f"{Colors.YELLOW}[!] No HTML files available. Run list_sd first.{Colors.NC}")
            return False
        
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                    {Colors.WHITE}{Colors.BOLD}📄  SELECT HTML FILE  📄{Colors.NC}                                 {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        
        # Show available files
        print(f"{Colors.BLUE}║{Colors.NC}  {Colors.YELLOW}Available HTML files:{Colors.NC}                                                        {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        
        for i, file_info in enumerate(self.portal_html_files, 1):
            if i <= 15:  # Show first 15 files
                display_text = file_info['display']
                if len(display_text) > 60:
                    display_text = display_text[:57] + "..."
                print(f"{Colors.BLUE}║{Colors.NC}  {Colors.GREEN}{file_info['number']:>2}){Colors.NC} {display_text:<58}  {Colors.BLUE}║{Colors.NC}")
        
        if len(self.portal_html_files) > 15:
            print(f"{Colors.BLUE}║{Colors.NC}  {Colors.GRAY}... and {len(self.portal_html_files) - 15} more files{Colors.NC}                                         {Colors.BLUE}║{Colors.NC}")
        
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        try:
            selection = input("Enter file number to select (0 to cancel): ").strip()
        except EOFError:
            return False
        
        if not selection or selection == '0':
            print(f"{Colors.YELLOW}[!] Selection cancelled{Colors.NC}")
            time.sleep(1)
            return False
        
        try:
            index = int(selection)
            # Find the file with this number
            for file_info in self.portal_html_files:
                if file_info['number'] == selection:
                    self.selected_html_index = index
                    self.selected_html_name = file_info['name']
                    
                    print(f"{Colors.BLUE}[*] Selecting file: {file_info['name']}{Colors.NC}")
                    self.serial_mgr.send_command(f"select_html {index}")
                    
                    # Wait for response
                    time.sleep(1)
                    lines = self.serial_mgr.read_response(timeout=2)
                    for line in lines:
                        if "Loaded HTML file" in line or "Portal will now use" in line:
                            print(f"{Colors.GREEN}[+] {line}{Colors.NC}")
                    
                    print(f"{Colors.GREEN}[+] File selected: {file_info['name']}{Colors.NC}")
                    print(f"{Colors.GREEN}[+] Use 'Start Captive Portal' to launch with this HTML{Colors.NC}")
                    return True
            
            print(f"{Colors.RED}[!] File number {selection} not found{Colors.NC}")
            time.sleep(1)
            return False
        except ValueError:
            print(f"{Colors.RED}[!] Please enter a valid number{Colors.NC}")
            time.sleep(1)
            return False
    
    def select_target_network_menu(self) -> Optional[Dict[str, str]]:
        """Display network selection menu for Evil Twin target."""
        if self.network_mgr.network_count == 0:
            print(f"{Colors.YELLOW}[!] No networks scanned yet. Run a scan first.{Colors.NC}")
            return None
        
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                  {Colors.WHITE}{Colors.BOLD}👥  SELECT TARGET NETWORK  👥{Colors.NC}                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.YELLOW}Select a target network for Evil Twin attack:{Colors.NC}                                    {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        
        # Display networks
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.WHITE}#{Colors.NC}   {Colors.WHITE}SSID{Colors.NC}                        {Colors.WHITE}CH{Colors.NC}  {Colors.WHITE}RSSI{Colors.NC}  {Colors.WHITE}Auth{Colors.NC}                    {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        
        for network in self.network_mgr.networks:
            idx = network.get('index', '?')
            ssid = network.get('ssid', '?')
            channel = network.get('channel', '?')
            auth = network.get('auth', '?')
            rssi = network.get('rssi', '?')
            
            # Truncate SSID if too long
            if len(ssid) > 24:
                ssid = ssid[:21] + "..."
            
            # Truncate auth if too long
            if len(auth) > 12:
                auth = auth[:10] + ".."
            
            rssi_color = self.network_mgr.get_rssi_color(rssi)
            
            print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.GREEN}{idx:<3}{Colors.NC} {ssid:<26} {channel:<3} {rssi_color}{rssi:<5}{Colors.NC} {auth:<12}              {Colors.MAGENTA}║{Colors.NC}")
        
        print(f"{Colors.MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        try:
            selection = input("Enter network number to target (0 to cancel): ").strip()
        except EOFError:
            return None
        
        if not selection or selection == '0':
            print(f"{Colors.YELLOW}[!] Selection cancelled{Colors.NC}")
            time.sleep(1)
            return None
        
        try:
            index = int(selection)
            # Find the network with this index
            for network in self.network_mgr.networks:
                if network.get('index') == selection:
                    print(f"{Colors.GREEN}[+] Selected network: {network.get('ssid')} (Channel: {network.get('channel')}){Colors.NC}")
                    return network
            
            print(f"{Colors.RED}[!] Network number {selection} not found{Colors.NC}")
            time.sleep(1)
            return None
        except ValueError:
            print(f"{Colors.RED}[!] Please enter a valid number{Colors.NC}")
            time.sleep(1)
            return None
    
    def setup_and_start_portal(self) -> None:
        """Full portal setup and start workflow."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                 {Colors.WHITE}{Colors.BOLD}🌐  CAPTIVE PORTAL SETUP  🌐{Colors.NC}                               {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}  {Colors.YELLOW}Step 1: Enter SSID name for the captive portal{Colors.NC}                                    {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Step 1: Get SSID name
        try:
            ssid_name = input("SSID Name (e.g., 'Free WiFi'): ").strip()
        except EOFError:
            print(f"{Colors.YELLOW}[!] Portal setup cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        if not ssid_name:
            print(f"{Colors.YELLOW}[!] No SSID name entered. Using default: 'Free WiFi'{Colors.NC}")
            ssid_name = "Free WiFi"
            time.sleep(1)
        
        self.portal_ssid = ssid_name
        print(f"{Colors.GREEN}[+] SSID set to: {ssid_name}{Colors.NC}")
        print()
        
        # Step 2: Get HTML files from SD card
        print(f"{Colors.BLUE}[*] Step 2: Loading HTML files from SD card...{Colors.NC}")
        if not self.get_html_files_from_sd():
            print(f"{Colors.YELLOW}[!] Cannot proceed without HTML files{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        # Step 3: Select HTML file
        print(f"{Colors.BLUE}[*] Step 3: Select HTML file for the portal{Colors.NC}")
        if not self.select_html_file_menu():
            print(f"{Colors.YELLOW}[!] No HTML file selected{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        # Step 4: Confirm and start portal
        print()
        print(f"{Colors.BLUE}[*] Step 4: Starting captive portal...{Colors.NC}")
        print(f"{Colors.BLUE}[*] SSID: {self.portal_ssid}{Colors.NC}")
        print(f"{Colors.BLUE}[*] HTML file: {self.selected_html_name}{Colors.NC}")
        print()
        
        try:
            confirm = input("Start Captive Portal? [y/N]: ").strip().lower()
        except EOFError:
            print(f"{Colors.YELLOW}[!] Portal start cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        if confirm not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[!] Portal start cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        # Start the portal
        self.start_portal_monitoring()
    
    def start_portal_monitoring(self) -> None:
        """Start portal and monitor its activity."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                 {Colors.WHITE}{Colors.BOLD}🌐  CAPTIVE PORTAL RUNNING  🌐{Colors.NC}                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}  {Colors.GREEN}SSID: {self.portal_ssid}{Colors.NC}{' ' * (70 - len(self.portal_ssid))}{Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}  {Colors.GREEN}HTML file: {self.selected_html_name}{Colors.NC}{' ' * (65 - len(self.selected_html_name))}{Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}  {Colors.YELLOW}Starting captive portal...{Colors.NC}                                                     {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Send start portal command
        print(f"{Colors.BLUE}[*] Sending: start_portal {self.portal_ssid}{Colors.NC}")
        self.serial_mgr.send_command(f"start_portal {self.portal_ssid}")
        
        # Wait for portal to start
        print(f"{Colors.BLUE}[*] Waiting for portal to initialize...{Colors.NC}")
        time.sleep(2)
        
        # Read initial response
        lines = self.serial_mgr.read_response(timeout=3)
        for line in lines:
            if "error" in line.lower() or "failed" in line.lower():
                print(f"{Colors.RED}[!] {line}{Colors.NC}")
                self.portal_running = False
                print()
                input("Press Enter to continue...")
                return
            elif "started successfully" in line.lower():
                print(f"{Colors.GREEN}[+] {line}{Colors.NC}")
                self.portal_running = True
            else:
                print(f"{Colors.BLUE}[*] {line}{Colors.NC}")
        
        if not self.portal_running:
            print(f"{Colors.YELLOW}[!] Portal may not have started correctly{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        # Reset counters
        self.submitted_forms = 0
        self.last_submitted_data = ""
        self.client_count = 0
        
        # Start background thread for reading portal data
        self.stop_portal_event.clear()
        self.portal_thread = threading.Thread(
            target=self.serial_mgr.read_portal_data,
            args=(self.update_portal_display, self.stop_portal_event)
        )
        self.portal_thread.daemon = True
        self.portal_thread.start()
        
        print(f"{Colors.GREEN}[+] Captive portal started successfully!{Colors.NC}")
        print(f"{Colors.GREEN}[+] SSID: {self.portal_ssid}{Colors.NC}")
        print(f"{Colors.GREEN}[+] Clients can connect and will see the HTML form{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}[*] Monitoring portal activity...{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Press Enter to stop the portal{Colors.NC}")
        print()
        
        # Display status
        start_time = time.time()
        
        try:
            # Monitor portal activity
            while True:
                elapsed = int(time.time() - start_time)
                
                # Clear lines and update display
                print("\033[2A", end="")  # Move up 2 lines
                print("\033[2K", end="")  # Clear line
                print(f"{Colors.BLUE}[*] Portal running for: {elapsed}s{Colors.NC}")
                print("\033[2K", end="")  # Clear line
                print(f"{Colors.BLUE}[*] Submitted forms: {self.submitted_forms} | Connected clients: {self.client_count}{Colors.NC}")
                
                if self.last_submitted_data:
                    # Truncate if too long
                    display_data = self.last_submitted_data
                    if len(display_data) > 60:
                        display_data = display_data[:57] + "..."
                    print("\033[2K", end="")  # Clear line
                    print(f"{Colors.GREEN}[*] Last data: {display_data}{Colors.NC}")
                
                print()
                print(f"{Colors.YELLOW}[*] Press Enter to stop the portal{Colors.NC}")
                
                # Check for Enter key press (non-blocking)
                import sys
                import select
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    key = sys.stdin.readline()
                    if key:  # Enter pressed
                        break
                
                time.sleep(PORTAL_UPDATE_INTERVAL)
        
        except KeyboardInterrupt:
            pass
        
        finally:
            # Stop portal
            print(f"\n{Colors.YELLOW}[*] Stopping portal...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.portal_running = False
            self.stop_portal_event.set()
            
            if self.portal_thread:
                self.portal_thread.join(timeout=2)
            
            print(f"{Colors.GREEN}[+] Portal stopped{Colors.NC}")
            print(f"{Colors.GREEN}[+] Total forms submitted: {self.submitted_forms}{Colors.NC}")
            print()
            input("Press Enter to continue...")
    
    def setup_and_start_evil_twin(self) -> None:
        """Full Evil Twin setup and start workflow."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                {Colors.WHITE}{Colors.BOLD}👥  EVIL TWIN ATTACK SETUP  👥{Colors.NC}                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.YELLOW}Step 1: Select target network for Evil Twin attack{Colors.NC}                                {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Step 1: Select target network
        target_network = self.select_target_network_menu()
        if not target_network:
            print(f"{Colors.YELLOW}[!] Evil Twin setup cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        target_ssid = target_network.get('ssid', 'Unknown')
        target_channel = target_network.get('channel', '1')
        
        print(f"{Colors.GREEN}[+] Target network selected: {target_ssid} (Channel: {target_channel}){Colors.NC}")
        print()
        
        # Step 2: Get HTML files from SD card
        print(f"{Colors.MAGENTA}[*] Step 2: Loading HTML files from SD card...{Colors.NC}")
        if not self.get_html_files_from_sd():
            print(f"{Colors.YELLOW}[!] Cannot proceed without HTML files{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        # Step 3: Select HTML file
        print(f"{Colors.MAGENTA}[*] Step 3: Select HTML file for Evil Twin portal{Colors.NC}")
        if not self.select_html_file_menu():
            print(f"{Colors.YELLOW}[!] No HTML file selected{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        # Step 4: Confirm and start Evil Twin
        print()
        print(f"{Colors.MAGENTA}[*] Step 4: Starting Evil Twin attack...{Colors.NC}")
        print(f"{Colors.MAGENTA}[*] Target SSID: {target_ssid}{Colors.NC}")
        print(f"{Colors.MAGENTA}[*] Target Channel: {target_channel}{Colors.NC}")
        print(f"{Colors.MAGENTA}[*] HTML file: {self.selected_html_name}{Colors.NC}")
        print()
        
        try:
            confirm = input("Start Evil Twin Attack? [y/N]: ").strip().lower()
        except EOFError:
            print(f"{Colors.YELLOW}[!] Evil Twin start cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        if confirm not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[!] Evil Twin start cancelled{Colors.NC}")
            time.sleep(1)
            return
        
        # Start the Evil Twin
        self.start_evil_twin_monitoring(target_ssid)
    
    def start_evil_twin_monitoring(self, target_ssid: str) -> None:
        """Start Evil Twin and monitor its activity."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                {Colors.WHITE}{Colors.BOLD}👥  EVIL TWIN ATTACK RUNNING  👥{Colors.NC}                             {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.GREEN}Target SSID: {target_ssid}{Colors.NC}{' ' * (65 - len(target_ssid))}{Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.GREEN}HTML file: {self.selected_html_name}{Colors.NC}{' ' * (65 - len(self.selected_html_name))}{Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.YELLOW}Starting Evil Twin attack...{Colors.NC}                                                   {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Send start evil twin command
        print(f"{Colors.MAGENTA}[*] Sending: start_evil_twin{Colors.NC}")
        self.serial_mgr.send_command("start_evil_twin")
        
        # Wait for Evil Twin to start
        print(f"{Colors.MAGENTA}[*] Waiting for Evil Twin to initialize...{Colors.NC}")
        time.sleep(2)
        
        # Read initial response
        lines = self.serial_mgr.read_response(timeout=3)
        for line in lines:
            if "error" in line.lower() or "failed" in line.lower():
                print(f"{Colors.RED}[!] {line}{Colors.NC}")
                self.evil_twin_running = False
                print()
                input("Press Enter to continue...")
                return
            elif "started successfully" in line.lower() or "broadcasting" in line.lower():
                print(f"{Colors.GREEN}[+] {line}{Colors.NC}")
                self.evil_twin_running = True
            else:
                print(f"{Colors.MAGENTA}[*] {line}{Colors.NC}")
        
        if not self.evil_twin_running:
            print(f"{Colors.YELLOW}[!] Evil Twin may not have started correctly{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        # Reset counters
        self.evil_twin_captured_data = []
        self.evil_twin_client_count = 0
        self.evil_twin_ssid = target_ssid
        
        # Start background thread for reading evil twin data
        self.stop_evil_twin_event.clear()
        self.evil_twin_thread = threading.Thread(
            target=self.serial_mgr.read_evil_twin_data,
            args=(self.update_evil_twin_display, self.stop_evil_twin_event)
        )
        self.evil_twin_thread.daemon = True
        self.evil_twin_thread.start()
        
        print(f"{Colors.GREEN}[+] Evil Twin attack started successfully!{Colors.NC}")
        print(f"{Colors.GREEN}[+] Target SSID: {target_ssid}{Colors.NC}")
        print(f"{Colors.GREEN}[+] Clients will connect to fake access point{Colors.NC}")
        print(f"{Colors.GREEN}[+] Handshakes and passwords will be captured{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}[*] Monitoring Evil Twin activity...{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Press Enter to stop the attack{Colors.NC}")
        print()
        
        # Display status
        start_time = time.time()
        
        try:
            # Monitor Evil Twin activity
            while True:
                elapsed = int(time.time() - start_time)
                
                # Clear lines and update display
                print("\033[2A", end="")  # Move up 2 lines
                print("\033[2K", end="")  # Clear line
                print(f"{Colors.MAGENTA}[*] Evil Twin running for: {elapsed}s{Colors.NC}")
                print("\033[2K", end="")  # Clear line
                print(f"{Colors.MAGENTA}[*] Captured data: {len(self.evil_twin_captured_data)} | Connected clients: {self.evil_twin_client_count}{Colors.NC}")
                
                if self.evil_twin_captured_data:
                    # Show last captured data
                    last_data = self.evil_twin_captured_data[-1]
                    # Truncate if too long
                    if len(last_data) > 60:
                        last_data = last_data[:57] + "..."
                    print("\033[2K", end="")  # Clear line
                    print(f"{Colors.GREEN}[*] Last captured: {last_data}{Colors.NC}")
                
                print()
                print(f"{Colors.YELLOW}[*] Press Enter to stop the attack{Colors.NC}")
                
                # Check for Enter key press (non-blocking)
                import sys
                import select
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    key = sys.stdin.readline()
                    if key:  # Enter pressed
                        break
                
                time.sleep(EVIL_TWIN_UPDATE_INTERVAL)
        
        except KeyboardInterrupt:
            pass
        
        finally:
            # Stop Evil Twin
            print(f"\n{Colors.YELLOW}[*] Stopping Evil Twin attack...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.evil_twin_running = False
            self.stop_evil_twin_event.set()
            
            if self.evil_twin_thread:
                self.evil_twin_thread.join(timeout=2)
            
            print(f"{Colors.GREEN}[+] Evil Twin attack stopped{Colors.NC}")
            print(f"{Colors.GREEN}[+] Total data captured: {len(self.evil_twin_captured_data)}{Colors.NC}")
            print()
            input("Press Enter to continue...")
    
    def show_portal_captured_data(self) -> None:
        """Show captured data from portal."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                   {Colors.WHITE}{Colors.BOLD}🔐  CAPTURED PORTAL DATA  🔐{Colors.NC}                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        
        if self.submitted_forms == 0:
            print(f"{Colors.BLUE}║{Colors.NC}  {Colors.YELLOW}No forms submitted yet.{Colors.NC}                                                     {Colors.BLUE}║{Colors.NC}")
        else:
            print(f"{Colors.BLUE}║{Colors.NC}  {Colors.GREEN}Total forms submitted: {self.submitted_forms}{Colors.NC}{' ' * (45 - len(str(self.submitted_forms)))}{Colors.BLUE}║{Colors.NC}")
            print(f"{Colors.BLUE}║{Colors.NC}  {Colors.GREEN}Connected clients: {self.client_count}{Colors.NC}{' ' * (48 - len(str(self.client_count)))}{Colors.BLUE}║{Colors.NC}")
            
            if self.last_submitted_data:
                print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
                print(f"{Colors.BLUE}║{Colors.NC}  {Colors.YELLOW}Last submitted data:{Colors.NC}                                                       {Colors.BLUE}║{Colors.NC}")
                print(f"{Colors.BLUE}║{Colors.NC}  {Colors.WHITE}{self.last_submitted_data}{Colors.NC}{' ' * (70 - len(self.last_submitted_data))}{Colors.BLUE}║{Colors.NC}")
        
        print(f"{Colors.BLUE}║{Colors.NC}                                                                              {Colors.BLUE}║{Colors.NC}")
        print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        # Request password log from device
        if self.portal_running:
            print(f"{Colors.YELLOW}[*] Portal is running. Data is being captured in real-time.{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[*] Requesting password log from device...{Colors.NC}")
            self.serial_mgr.send_command("show_pass")
            
            lines = self.serial_mgr.read_response(timeout=3)
            if lines:
                print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
                print(f"{Colors.CYAN}║{Colors.NC}  {Colors.WHITE}Time{Colors.NC}           {Colors.WHITE}SSID{Colors.NC}                        {Colors.WHITE}Password/Data{Colors.NC}         {Colors.CYAN}║{Colors.NC}")
                print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
                
                for line in lines:
                    if line and not line.startswith("Password") and not line.startswith("Log"):
                        # Parse log entry
                        parts = line.split()
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            ssid = parts[1]
                            data = " ".join(parts[2:])
                            
                            # Truncate if too long
                            if len(ssid) > 20:
                                ssid = ssid[:17] + "..."
                            if len(data) > 25:
                                data = data[:22] + "..."
                            
                            print(f"{Colors.CYAN}║{Colors.NC}  {timestamp:<12} {ssid:<20} {data:<25} {Colors.CYAN}║{Colors.NC}")
                        else:
                            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GRAY}{line:<70}{Colors.NC}  {Colors.CYAN}║{Colors.NC}")
                
                print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
            else:
                print(f"{Colors.YELLOW}[!] No password log entries found{Colors.NC}")
        
        print()
        input("Press Enter to continue...")
    
    def show_evil_twin_captured_data(self) -> None:
        """Show captured data from Evil Twin attack."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        print(f"{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                 {Colors.WHITE}{Colors.BOLD}👥  EVIL TWIN CAPTURED DATA  👥{Colors.NC}                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        
        if len(self.evil_twin_captured_data) == 0:
            print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.YELLOW}No data captured yet.{Colors.NC}                                                       {Colors.MAGENTA}║{Colors.NC}")
        else:
            print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.GREEN}Total data captured: {len(self.evil_twin_captured_data)}{Colors.NC}{' ' * (43 - len(str(len(self.evil_twin_captured_data))))}{Colors.MAGENTA}║{Colors.NC}")
            print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.GREEN}Connected clients: {self.evil_twin_client_count}{Colors.NC}{' ' * (48 - len(str(self.evil_twin_client_count)))}{Colors.MAGENTA}║{Colors.NC}")
            
            if self.evil_twin_ssid:
                print(f"{Colors.MAGENTA}║{Colors.NC}  {Colors.GREEN}Target SSID: {self.evil_twin_ssid}{Colors.NC}{' ' * (55 - len(self.evil_twin_ssid))}{Colors.MAGENTA}║{Colors.NC}")
        
        print(f"{Colors.MAGENTA}║{Colors.NC}                                                                              {Colors.MAGENTA}║{Colors.NC}")
        print(f"{Colors.MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        if self.evil_twin_captured_data:
            print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.NC}")
            print(f"{Colors.CYAN}║{Colors.NC}  {Colors.WHITE}#{Colors.NC}  {Colors.WHITE}Captured Data{Colors.NC}                                                      {Colors.CYAN}║{Colors.NC}")
            print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣{Colors.NC}")
            
            for i, data in enumerate(self.evil_twin_captured_data[-10:], 1):  # Show last 10 entries
                display_data = data
                if len(display_data) > 70:
                    display_data = display_data[:67] + "..."
                print(f"{Colors.CYAN}║{Colors.NC}  {Colors.GREEN}{i:2}){Colors.NC} {display_data:<70}{Colors.CYAN}║{Colors.NC}")
            
            print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
            print()
        
        if self.evil_twin_running:
            print(f"{Colors.YELLOW}[*] Evil Twin is running. Data is being captured in real-time.{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}[*] Evil Twin is not running. Start the attack to capture data.{Colors.NC}")
        
        print()
        input("Press Enter to continue...")
    
    def stop_all_attacks(self) -> None:
        """Stop all running attacks."""
        clear_screen()
        UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                       self.sniffer_running, self.sae_overflow_running,
                       self.handshake_running, self.portal_running,
                       self.evil_twin_running)
        print()
        
        if not self.attack_running and not self.blackout_running and not self.sniffer_running and not self.sae_overflow_running and not self.handshake_running and not self.portal_running and not self.evil_twin_running:
            print(f"{Colors.YELLOW}[!] No attacks are currently running{Colors.NC}")
            print()
            input("Press Enter to continue...")
            return
        
        print(f"{Colors.YELLOW}[*] Sending stop command to all attacks...{Colors.NC}")
        
        if self.attack_running:
            print(f"{Colors.YELLOW}    Stopping deauth attack...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.attack_running = False
        
        if self.blackout_running:
            print(f"{Colors.YELLOW}    Stopping blackout attack...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.blackout_running = False
        
        if self.sniffer_running:
            print(f"{Colors.YELLOW}    Stopping sniffer...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.sniffer_running = False
            self.stop_sniffer_event.set()
            if self.sniffer_thread:
                self.sniffer_thread.join(timeout=2)
        
        if self.sae_overflow_running:
            print(f"{Colors.YELLOW}    Stopping WPA3 SAE Overflow attack...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.sae_overflow_running = False
        
        if self.handshake_running:
            print(f"{Colors.YELLOW}    Stopping Handshake Capture attack...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.handshake_running = False
        
        if self.portal_running:
            print(f"{Colors.YELLOW}    Stopping Captive Portal...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.portal_running = False
            self.stop_portal_event.set()
            if self.portal_thread:
                self.portal_thread.join(timeout=2)
        
        if self.evil_twin_running:
            print(f"{Colors.YELLOW}    Stopping Evil Twin attack...{Colors.NC}")
            self.serial_mgr.send_command("stop")
            self.evil_twin_running = False
            self.stop_evil_twin_event.set()
            if self.evil_twin_thread:
                self.evil_twin_thread.join(timeout=2)
        
        print(f"{Colors.GREEN}[+] All attacks stopped{Colors.NC}")
        print()
        input("Press Enter to continue...")
    
    def portal_menu(self) -> None:
        """Portal setup menu."""
        while True:
            try:
                clear_screen()
                UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                              self.sniffer_running, self.sae_overflow_running,
                              self.handshake_running, self.portal_running,
                              self.evil_twin_running)
                UI.print_portal_menu()
                
                # Status line
                if self.portal_running:
                    print(f"{Colors.BLUE}[!] Captive Portal is RUNNING{Colors.NC}")
                    print(f"{Colors.BLUE}[+] SSID: {self.portal_ssid}{Colors.NC}")
                    print(f"{Colors.BLUE}[+] HTML: {self.selected_html_name}{Colors.NC}")
                    print(f"{Colors.BLUE}[+] Forms submitted: {self.submitted_forms}{Colors.NC}")
                    print(f"{Colors.BLUE}[+] Connected clients: {self.client_count}{Colors.NC}")
                else:
                    print(f"{Colors.GRAY}[-] Portal not running{Colors.NC}")
                
                print()
                
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    self.setup_and_start_portal()
                elif choice == '2':
                    self.show_portal_captured_data()
                elif choice == '0':
                    return  # Back to attacks menu
                else:
                    print(f"{Colors.RED}Invalid option{Colors.NC}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Returning to attacks menu{Colors.NC}")
                time.sleep(1)
                break
            except EOFError:
                print(f"\n{Colors.YELLOW}[*] Returning to attacks menu{Colors.NC}")
                time.sleep(1)
                break
    
    def evil_twin_menu(self) -> None:
        """Evil Twin setup menu."""
        while True:
            try:
                clear_screen()
                UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                              self.sniffer_running, self.sae_overflow_running,
                              self.handshake_running, self.portal_running,
                              self.evil_twin_running)
                UI.print_evil_twin_menu()
                
                # Status line
                if self.evil_twin_running:
                    print(f"{Colors.MAGENTA}[!] Evil Twin Attack is RUNNING{Colors.NC}")
                    if self.evil_twin_ssid:
                        print(f"{Colors.MAGENTA}[+] Target SSID: {self.evil_twin_ssid}{Colors.NC}")
                    print(f"{Colors.MAGENTA}[+] HTML: {self.selected_html_name}{Colors.NC}")
                    print(f"{Colors.MAGENTA}[+] Data captured: {len(self.evil_twin_captured_data)}{Colors.NC}")
                    print(f"{Colors.MAGENTA}[+] Connected clients: {self.evil_twin_client_count}{Colors.NC}")
                else:
                    print(f"{Colors.GRAY}[-] Evil Twin not running{Colors.NC}")
                
                print()
                
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    self.setup_and_start_evil_twin()
                elif choice == '2':
                    self.show_evil_twin_captured_data()
                elif choice == '0':
                    return  # Back to attacks menu
                else:
                    print(f"{Colors.RED}Invalid option{Colors.NC}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Returning to attacks menu{Colors.NC}")
                time.sleep(1)
                break
            except EOFError:
                print(f"\n{Colors.YELLOW}[*] Returning to attacks menu{Colors.NC}")
                time.sleep(1)
                break
    
    def scan_menu(self) -> None:
        """Scan submenu."""
        while True:
            try:
                clear_screen()
                UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                              self.sniffer_running, self.sae_overflow_running,
                              self.handshake_running, self.portal_running,
                              self.evil_twin_running)
                UI.print_scan_menu(self.network_mgr.network_count, 
                                 self.network_mgr.selected_networks)
                
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    self.do_scan()
                elif choice == '2':
                    self.network_mgr.display_networks()
                elif choice == '3':
                    self.select_networks_menu()
                elif choice == '0':
                    return  # Back to main menu
                else:
                    print(f"{Colors.RED}Invalid option{Colors.NC}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Returning to main menu{Colors.NC}")
                time.sleep(1)
                break
            except EOFError:
                print(f"\n{Colors.YELLOW}[*] Returning to main menu{Colors.NC}")
                time.sleep(1)
                break
    
    def sniffer_menu(self) -> None:
        """Sniffer submenu."""
        while True:
            try:
                clear_screen()
                UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                              self.sniffer_running, self.sae_overflow_running,
                              self.handshake_running, self.portal_running,
                              self.evil_twin_running)
                UI.print_sniffer_menu(self.sniffer_running, self.sniffer_packets)
                
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    self.start_sniffer()
                elif choice == '2':
                    self.show_sniffer_results()
                elif choice == '3':
                    self.show_sniffer_probes()
                elif choice == '0':
                    return  # Back to main menu
                else:
                    print(f"{Colors.RED}Invalid option{Colors.NC}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Returning to main menu{Colors.NC}")
                time.sleep(1)
                break
            except EOFError:
                print(f"\n{Colors.YELLOW}[*] Returning to main menu{Colors.NC}")
                time.sleep(1)
                break
    
    def attacks_menu(self) -> None:
        """Attacks submenu."""
        while True:
            try:
                clear_screen()
                UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                              self.sniffer_running, self.sae_overflow_running,
                              self.handshake_running, self.portal_running,
                              self.evil_twin_running)
                UI.print_attacks_menu(self.network_mgr.selected_networks, 
                                     self.attack_running, self.blackout_running, 
                                     self.sae_overflow_running, self.handshake_running,
                                     self.portal_running, self.evil_twin_running)
                
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    self.start_deauth_attack()
                elif choice == '2':
                    self.start_blackout_attack()
                elif choice == '3':
                    self.start_sae_overflow_attack()
                elif choice == '4':
                    self.start_handshake_attack()
                elif choice == '5':
                    self.portal_menu()
                elif choice == '6':
                    self.evil_twin_menu()
                elif choice == '9':
                    self.stop_all_attacks()
                elif choice == '0':
                    return  # Back to main menu
                else:
                    print(f"{Colors.RED}Invalid option{Colors.NC}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Returning to main menu{Colors.NC}")
                time.sleep(1)
                break
            except EOFError:
                print(f"\n{Colors.YELLOW}[*] Returning to main menu{Colors.NC}")
                time.sleep(1)
                break
    
    def main_menu(self) -> None:
        """Main menu loop."""
        while True:
            try:
                clear_screen()
                UI.print_banner(self.device, self.attack_running, self.blackout_running, 
                              self.sniffer_running, self.sae_overflow_running,
                              self.handshake_running, self.portal_running,
                              self.evil_twin_running)
                UI.print_main_menu()
                
                # Status display
                if self.network_mgr.network_count > 0:
                    print(f"{Colors.GREEN}[+] Networks found: {self.network_mgr.network_count}{Colors.NC}")
                else:
                    print(f"{Colors.GRAY}[-] No networks scanned{Colors.NC}")
                
                if self.network_mgr.selected_networks:
                    print(f"{Colors.GREEN}[+] Selected: {self.network_mgr.selected_networks}{Colors.NC}")
                
                if self.attack_running:
                    print(f"{Colors.RED}[!] Deauth Attack is RUNNING{Colors.NC}")
                if self.blackout_running:
                    print(f"{Colors.RED}[!] Blackout Attack is RUNNING{Colors.NC}")
                if self.sniffer_running:
                    print(f"{Colors.CYAN}[📡] Sniffer is RUNNING{Colors.NC}")
                    print(f"{Colors.CYAN}[+] Packets captured: {self.sniffer_packets}{Colors.NC}")
                if self.sae_overflow_running:
                    print(f"{Colors.MAGENTA}[!] WPA3 SAE Overflow is RUNNING{Colors.NC}")
                if self.handshake_running:
                    print(f"{Colors.YELLOW}[!] Handshake Capture is RUNNING{Colors.NC}")
                if self.portal_running:
                    print(f"{Colors.BLUE}[!] Captive Portal is RUNNING{Colors.NC}")
                    print(f"{Colors.BLUE}[+] SSID: {self.portal_ssid}{Colors.NC}")
                    print(f"{Colors.BLUE}[+] Forms: {self.submitted_forms}{Colors.NC}")
                if self.evil_twin_running:
                    print(f"{Colors.MAGENTA}[!] Evil Twin Attack is RUNNING{Colors.NC}")
                    if self.evil_twin_ssid:
                        print(f"{Colors.MAGENTA}[+] Target: {self.evil_twin_ssid}{Colors.NC}")
                    print(f"{Colors.MAGENTA}[+] Captured: {len(self.evil_twin_captured_data)}{Colors.NC}")
                if not self.attack_running and not self.blackout_running and not self.sniffer_running and not self.sae_overflow_running and not self.handshake_running and not self.portal_running and not self.evil_twin_running:
                    print(f"{Colors.GRAY}[-] No attacks running{Colors.NC}")
                
                print()
                
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    self.scan_menu()
                elif choice == '2':
                    self.sniffer_menu()
                elif choice == '3':
                    self.attacks_menu()
                elif choice in ['0', 'q', 'Q']:
                    if self.attack_running or self.blackout_running or self.sniffer_running or self.sae_overflow_running or self.handshake_running or self.portal_running or self.evil_twin_running:
                        print()
                        try:
                            stop_confirm = input("Attacks/Sniffer/Portal are running. Stop before exit? [Y/n]: ").strip().lower()
                        except EOFError:
                            stop_confirm = 'y'
                        
                        if stop_confirm not in ['n', 'no']:
                            self.serial_mgr.send_command("stop")
                            if self.sniffer_running:
                                self.stop_sniffer_event.set()
                                if self.sniffer_thread:
                                    self.sniffer_thread.join(timeout=2)
                            if self.portal_running:
                                self.stop_portal_event.set()
                                if self.portal_thread:
                                    self.portal_thread.join(timeout=2)
                            if self.evil_twin_running:
                                self.stop_evil_twin_event.set()
                                if self.evil_twin_thread:
                                    self.evil_twin_thread.join(timeout=2)
                            print(f"{Colors.GREEN}[+] All activities stopped{Colors.NC}")
                            time.sleep(1)
                    return
                else:
                    print(f"{Colors.RED}Invalid option{Colors.NC}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.NC}")
                if self.attack_running or self.blackout_running or self.sniffer_running or self.sae_overflow_running or self.handshake_running or self.portal_running or self.evil_twin_running:
                    self.serial_mgr.send_command("stop")
                    if self.sniffer_running:
                        self.stop_sniffer_event.set()
                    if self.portal_running:
                        self.stop_portal_event.set()
                    if self.evil_twin_running:
                        self.stop_evil_twin_event.set()
                break
            except EOFError:
                print(f"\n{Colors.YELLOW}[*] Exiting{Colors.NC}")
                if self.attack_running or self.blackout_running or self.sniffer_running or self.sae_overflow_running or self.handshake_running or self.portal_running or self.evil_twin_running:
                    self.serial_mgr.send_command("stop")
                    if self.sniffer_running:
                        self.stop_sniffer_event.set()
                    if self.portal_running:
                        self.stop_portal_event.set()
                    if self.evil_twin_running:
                        self.stop_evil_twin_event.set()
                break
    
    def run(self) -> None:
        """Run the application."""
        print(f"{Colors.YELLOW}[*] JanOS Controller starting...{Colors.NC}")
        print(f"{Colors.GREEN}[+] Connected to {self.device}{Colors.NC}")
        time.sleep(1)
        
        try:
            self.main_menu()
        finally:
            self.cleanup()
    
    def cleanup(self) -> None:
        """Cleanup resources."""
        print()
        print(f"{Colors.YELLOW}[*] Cleaning up...{Colors.NC}")
        if self.attack_running or self.blackout_running or self.sniffer_running or self.sae_overflow_running or self.handshake_running or self.portal_running or self.evil_twin_running:
            self.serial_mgr.send_command("stop")
            if self.sniffer_running:
                self.stop_sniffer_event.set()
                if self.sniffer_thread:
                    self.sniffer_thread.join(timeout=2)
            if self.portal_running:
                self.stop_portal_event.set()
                if self.portal_thread:
                    self.portal_thread.join(timeout=2)
            if self.evil_twin_running:
                self.stop_evil_twin_event.set()
                if self.evil_twin_thread:
                    self.evil_twin_thread.join(timeout=2)
        self.serial_mgr.close()
        print(f"{Colors.GREEN}Goodbye!{Colors.NC}")

# ============================================================================
# Main Entry Point
# ============================================================================
def main():
    # Check for device argument
    if len(sys.argv) < 2:
        app = JanOS("")
        app.show_usage()
        sys.exit(1)
    
    device = sys.argv[1]
    
    # Create and run application
    app = JanOS(device)
    
    # Setup signal handlers
    import signal
    def signal_handler(sig, frame):
        print(f"\n{Colors.YELLOW}[*] Received interrupt signal{Colors.NC}")
        if app.attack_running or app.blackout_running or app.sniffer_running or app.sae_overflow_running or app.handshake_running or app.portal_running or app.evil_twin_running:
            app.serial_mgr.send_command("stop")
            if app.sniffer_running:
                app.stop_sniffer_event.set()
            if app.portal_running:
                app.stop_portal_event.set()
            if app.evil_twin_running:
                app.stop_evil_twin_event.set()
        app.serial_mgr.close()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    app.run()

if __name__ == "__main__":
    main()