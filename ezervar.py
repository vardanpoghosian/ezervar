#!/usr/bin/env python3
import cmd
import os
import time
import random
import hashlib
import subprocess
import json
import socket
import threading
import base64
import ssl
import re
import csv
from datetime import datetime
from pathlib import Path
from pyfiglet import figlet_format
from termcolor import colored
# Optional imports with error handling
try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import nmap
except ImportError:
    nmap = None

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization
except ImportError:
    Fernet = None
    hashes = None
    PBKDF2HMAC = None
    rsa = None
    padding = None
    serialization = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import pandas as pd
except ImportError:
    pd = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import schedule
except ImportError:
    schedule = None

try:
    import qrcode
except ImportError:
    qrcode = None

try:
    import whois
except ImportError:
    whois = None

try:
    from scapy.all import *
except ImportError:
    scapy = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = None

# Configuration and utilities
class Config:
    def __init__(self):
        self.config_file = "ezervar_config.json"
        self.load_config()
    
    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.data = json.load(f)
            else:
                self.data = {
                    "theme": "dark",
                    "auto_save": True,
                    "scan_timeout": 30,
                    "max_threads": 10
                }
                self.save_config()
        except:
            self.data = {"theme": "dark", "auto_save": True, "scan_timeout": 30, "max_threads": 10}
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.data, f, indent=2)

# File monitoring system
if FileSystemEventHandler is not None:
    class FileMonitor(FileSystemEventHandler):
        def __init__(self, callback):
            self.callback = callback
        
        def on_modified(self, event):
            if not event.is_directory:
                self.callback(event.src_path)
        
        def on_created(self, event):
            if not event.is_directory:
                self.callback(f"Created: {event.src_path}")
        
        def on_deleted(self, event):
            if not event.is_directory:
                self.callback(f"Deleted: {event.src_path}")
        
        def on_moved(self, event):
            if not event.is_directory:
                self.callback(f"Moved: {event.src_path} -> {event.dest_path}")
else:
    # Fallback class when watchdog is not available
    class FileMonitor:
        def __init__(self, callback):
            self.callback = callback
            print(colored("[!] File monitoring disabled - watchdog not installed", "yellow"))
        
        def on_modified(self, event):
            pass
        
        def on_created(self, event):
            pass
        
        def on_deleted(self, event):
            pass
        
        def on_moved(self, event):
            pass

# Password generator
def generate_password(length=12, include_symbols=True, include_numbers=True):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if include_numbers:
        chars += "0123456789"
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(random.choice(chars) for _ in range(length))

# Steganography functions
def hide_text_in_image(image_path, text, output_path):
    if Image is None or np is None:
        print(colored("[x] PIL and numpy are required for steganography", "red"))
        return False
    
    try:
        img = Image.open(image_path)
        img_array = np.array(img)
        text_binary = ''.join(format(ord(char), '08b') for char in text)
        text_binary += '1111111111111110'  # End marker
        
        height, width, channels = img_array.shape
        data_index = 0
        
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    if data_index < len(text_binary):
                        img_array[i][j][k] = img_array[i][j][k] & ~1 | int(text_binary[data_index])
                        data_index += 1
                    else:
                        break
                if data_index >= len(text_binary):
                    break
            if data_index >= len(text_binary):
                break
        
        result_img = Image.fromarray(img_array)
        result_img.save(output_path)
        return True
    except Exception as e:
        print(colored(f"[x] Steganography error: {e}", "red"))
        return False

def extract_text_from_image(image_path):
    if Image is None or np is None:
        print(colored("[x] PIL and numpy are required for steganography", "red"))
        return ""
    
    try:
        img = Image.open(image_path)
        img_array = np.array(img)
        height, width, channels = img_array.shape
        
        binary_data = ""
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    binary_data += str(img_array[i][j][k] & 1)
        
        # Find end marker
        end_marker = "1111111111111110"
        if end_marker in binary_data:
            binary_data = binary_data[:binary_data.index(end_marker)]
        
        # Convert binary to text
        text = ""
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                text += chr(int(byte, 2))
        
        return text
    except Exception as e:
        print(colored(f"[x] Steganography extraction error: {e}", "red"))
        return ""

# Boot Animation
def animate_banner():
    quotes = [
        "[*] Connecting to the void...",
        "[*] Injecting protocol...",
        "[*] Cloaking identity...",
        "[*] Glitching reality...",
        "[*] Hashing the unknown...",
        "[*] Entering Ezervar CLI..."
    ]
    fonts = ["slant", "standard", "block", "bubble"]
    dark_variants = [
        "EZ3RV4R", "ΣZΣRV∆R", "ΞZΞRV∆R", "3Z3RV∆R", "EZ∑RV∆R", "EZΞRVΛR", "EX3RV4R", "EZ3R\\/4R", "EZ3RVAЯ"
    ]

    for i in range(5):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = figlet_format("EZERVAR", font=random.choice(fonts))
        print(colored(banner, "cyan"))
        print(colored(random.choice(quotes), "magenta"))
        time.sleep(0.4)

    os.system('cls' if os.name == 'nt' else 'clear')
    final_text = random.choice(dark_variants)
    final = figlet_format(final_text, font="slant")
    print(colored(final, "green"))
    print(colored("[+] Ezervar CLI Initialized — Type help to begin.\n", "yellow"))

# CLI Core
class EzervarShell(cmd.Cmd):
    intro = colored("[*] Welcome to Ezervar CLI — the darkness begins...\n[*] Root mode is ENABLED by default - all commands use 'sudo'\n[*] Type help or ? to list commands.\n", "cyan")
    prompt = colored("ezervar > ", "green")
    wifi_networks = {}
    
    def __init__(self):
        super().__init__()
        self.config = Config()
        self.file_observer = None
        self.monitoring_paths = []
        self.scheduled_tasks = []
        self.command_history = []
        self.encryption_key = None
        self.root_mode = True

    def _build_command(self, cmd_list):
        """Build command with sudo prefix if root mode is enabled"""
        if self.root_mode:
            return ["sudo"] + cmd_list
        return cmd_list

    def do_help(self, arg):
        print(colored("\n[ Ezervar CLI Command Guide ]", "yellow"))
        print(colored("=" * 50, "yellow"))

        # Aesthetics
        print(colored("\nAesthetics", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("menu            .......... Return to main menu screen", "green"))
        print(colored("back            .......... Go back one step (menu)", "green"))

        # Root Mode
        print(colored("\nRoot Mode", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("root            .......... Enable root mode (sudo prefix)", "green"))
        print(colored("unroot          .......... Disable root mode", "green"))
        print(colored("Note: Root mode is ENABLED by default", "yellow"))

        # Security Tools
        print(colored("\nSecurity Tools", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("portscan <ip>   .......... Advanced port scanner", "green"))
        print(colored("vulnscan <ip>   .......... Vulnerability scanner", "green"))
        print(colored("anomaly         .......... Detect system anomalies", "green"))
        print(colored("audit           .......... Security audit", "green"))
        print(colored("sqlrecon        .......... SQL injection reconnaissance", "green"))
        print(colored("ezeforce        .......... Advanced analytical tools", "green"))
        print(colored("ezewifi         .......... Wi-Fi network analysis", "green"))

        # Cryptography
        print(colored("\nCryptography", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("encrypt <text>  .......... Encrypt text with AES", "green"))
        print(colored("decrypt <text>  .......... Decrypt text", "green"))
        print(colored("genkey          .......... Generate encryption key", "green"))
        print(colored("rsa <bits>      .......... Generate RSA key pair", "green"))
        print(colored("stego <img> <text> ........ Hide text in image", "green"))
        print(colored("unstego <img>   .......... Extract text from image", "green"))

        # Network Analysis
        print(colored("\nNetwork Analysis", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("traceroute <host> ........ Trace network route", "green"))
        print(colored("whois <domain>  .......... Get domain information", "green"))
        print(colored("dns <domain>    .......... DNS lookup", "green"))
        print(colored("ssl <host>      .......... SSL certificate analysis", "green"))
        print(colored("arp             .......... ARP table scan", "green"))

        # Data Processing
        print(colored("\nData Processing", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("logparse <file>  .......... Parse log files", "green"))
        print(colored("pattern <text>  .......... Find patterns in text", "green"))
        print(colored("metadata <file> ........ Show file metadata", "green"))
        print(colored("analyze <file>  .......... Analyze file type", "green"))

        # Automation & Monitoring
        print(colored("\nAutomation & Monitoring", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("monitor <path>  .......... Monitor directory changes", "green"))
        print(colored("schedule <cmd>  .......... Schedule command", "green"))
        print(colored("tasks           .......... List scheduled tasks", "green"))
        print(colored("system          .......... System information", "green"))

        # Utilities
        print(colored("\nUtilities", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("password <len>  .......... Generate password", "green"))
        print(colored("qr <text>      .......... Generate QR code", "green"))
        print(colored("hash <text>    .......... Calculate SHA256 hash", "green"))
        print(colored("config         .......... Show configuration", "green"))
        print(colored("history        .......... Show command history", "green"))

        # Network Tools
        print(colored("\nNetwork Tools", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("scan <subnet>   .......... Scan subnet using nmap", "green"))
        print(colored("scanweb <url>   .......... Scan website for vulnerabilities", "green"))
        print(colored("ping <host>     .......... Ping an IP or domain", "green"))

        # Wi-Fi Tools
        print(colored("\nWi-Fi Tools", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("wifi            .......... List nearby Wi-Fi networks", "green"))
        print(colored("wifiinfo <n>    .......... Show details of Wi-Fi #n", "green"))

        # Exit
        print(colored("\nExit", "magenta"))
        print(colored("-" * 50, "yellow"))
        print(colored("exit            .......... Exit the CLI", "green"))
        print()


    def do_menu(self, arg):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = figlet_format("EZERVAR", font="slant")
        print(colored(banner, "cyan"))
        print(colored("[*] Welcome back to Ezervar CLI", "green"))
        print(colored("[+] Type help to list available commands\n", "yellow"))

    def do_back(self, arg):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = figlet_format("EZERVAR", font="slant")
        print(colored(banner, "cyan"))
        print(colored("[*] Returned to previous screen", "green"))
        print(colored("[+] Type help to list available commands\n", "yellow"))

    def do_hash(self, arg):
        result = hashlib.sha256(arg.encode()).hexdigest()
        print(colored(f"[+] Hash: {result}", "cyan"))

    def do_scan(self, arg):
        print(colored(f"[>] Scanning subnet {arg} ...", "blue"))
        try:
            cmd = self._build_command(["nmap", "-sn", arg])
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(colored(result.stdout, "cyan"))
        except Exception as e:
            print(colored(f"[x] Scan error: {e}", "red"))

    def do_scanweb(self, arg):
        if not arg:
            print(colored("[x] Please specify a URL.", "red"))
            return
        print(colored(f"[>] Scanning website {arg} with Nikto...", "blue"))
        try:
            cmd = self._build_command(["nikto", "-host", arg])
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(colored(result.stdout, "cyan"))
        except Exception as e:
            print(colored(f"[x] Web scan error: {e}", "red"))

    def do_ping(self, arg):
        if not arg:
            print(colored("[x] Please specify an IP or domain.", "red"))
            return
        print(colored(f"[>] Pinging {arg} ...", "blue"))
        try:
            cmd = self._build_command(["ping", "-c", "4", arg])
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(colored(result.stdout, "cyan"))
        except Exception as e:
            print(colored(f"[x] Ping error: {e}", "red"))

    def do_wifi(self, arg):
        print(colored("[>] Scanning nearby Wi-Fi networks...", "blue"))
        self.wifi_networks = {}
        try:
            cmd = self._build_command(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,BSSID,FREQ", "dev", "wifi"])
            result = subprocess.run(cmd, capture_output=True, text=True)
            networks = result.stdout.strip().split('\n')
            count = 1
            for net in networks:
                parts = net.split(":")
                if len(parts) >= 5 and parts[0]:
                    ssid, signal, security, bssid, freq = parts[:5]
                    self.wifi_networks[str(count)] = {
                        "SSID": ssid,
                        "Signal": signal,
                        "Security": security,
                        "BSSID": bssid,
                        "Frequency": freq
                    }
                    print(colored(f"[{count}] {ssid} — Signal: {signal}%", "cyan"))
                    count += 1
        except Exception as e:
            print(colored(f"[x] Wi-Fi scan error: {e}", "red"))

    def do_wifiinfo(self, arg):
        if arg not in self.wifi_networks:
            print(colored("[x] Invalid selection. Run 'wifi' first and choose a valid number.", "red"))
            return
        info = self.wifi_networks[arg]
        print(colored(f"\n[+] Wi-Fi Network #{arg}", "yellow"))
        for key, value in info.items():
            print(colored(f"{key:<10}: {value}", "green"))
        print()

    # Security Tools
    def do_portscan(self, arg):
        if not arg:
            print(colored("[x] Please specify an IP address.", "red"))
            return
        if nmap is None:
            print(colored("[x] python-nmap library is required. Install with: pip install python-nmap", "red"))
            return
        print(colored(f"[>] Advanced port scanning {arg}...", "blue"))
        try:
            nm = nmap.PortScanner()
            result = nm.scan(arg, '1-1000', '-sS -sV -O')
            for host in nm.all_hosts():
                print(colored(f"\n[+] Host: {host}", "green"))
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        print(colored(f"  Port {port}: {state} - {service}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Port scan error: {e}", "red"))

    def do_vulnscan(self, arg):
        if not arg:
            print(colored("[x] Please specify an IP address.", "red"))
            return
        if nmap is None:
            print(colored("[x] python-nmap library is required. Install with: pip install python-nmap", "red"))
            return
        print(colored(f"[>] Vulnerability scanning {arg}...", "blue"))
        try:
            nm = nmap.PortScanner()
            result = nm.scan(arg, arguments='--script vuln')
            for host in nm.all_hosts():
                print(colored(f"\n[+] Vulnerabilities for {host}:", "green"))
                for script in nm[host]['tcp']:
                    if 'script' in nm[host]['tcp'][script]:
                        print(colored(f"  {script}: {nm[host]['tcp'][script]['script']}", "yellow"))
        except Exception as e:
            print(colored(f"[x] Vulnerability scan error: {e}", "red"))

    def do_anomaly(self, arg):
        if psutil is None:
            print(colored("[x] psutil library is required. Install with: pip install psutil", "red"))
            return
        print(colored("[>] Detecting system anomalies...", "blue"))
        try:
            # Check for unusual processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] > 50 or proc_info['memory_percent'] > 20:
                        processes.append(proc_info)
                except:
                    pass
            
            if processes:
                print(colored("[!] Anomalous processes detected:", "red"))
                for proc in processes:
                    print(colored(f"  PID {proc['pid']}: {proc['name']} - CPU: {proc['cpu_percent']}%, RAM: {proc['memory_percent']}%", "yellow"))
            else:
                print(colored("[+] No anomalies detected", "green"))
        except Exception as e:
            print(colored(f"[x] Anomaly detection error: {e}", "red"))

    def do_audit(self, arg):
        if psutil is None:
            print(colored("[x] psutil library is required. Install with: pip install psutil", "red"))
            return
        print(colored("[>] Performing security audit...", "blue"))
        try:
            # Check file permissions
            critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            for file_path in critical_files:
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    mode = oct(stat.st_mode)[-3:]
                    print(colored(f"  {file_path}: {mode}", "cyan"))
            
            # Check running services
            print(colored("\n[+] Running services:", "green"))
            for proc in psutil.process_iter(['name', 'username']):
                try:
                    if proc.info['username'] == 'root':
                        print(colored(f"  {proc.info['name']} (root)", "yellow"))
                except:
                    pass
        except Exception as e:
            print(colored(f"[x] Audit error: {e}", "red"))

    # Cryptography
    def do_encrypt(self, arg):
        if not arg:
            print(colored("[x] Please provide text to encrypt.", "red"))
            return
        if Fernet is None:
            print(colored("[x] cryptography library is required. Install with: pip install cryptography", "red"))
            return
        if not self.encryption_key:
            print(colored("[x] No encryption key found. Run 'genkey' first.", "red"))
            return
        try:
            f = Fernet(self.encryption_key)
            encrypted = f.encrypt(arg.encode())
            print(colored(f"[+] Encrypted: {base64.b64encode(encrypted).decode()}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Encryption error: {e}", "red"))

    def do_decrypt(self, arg):
        if not arg:
            print(colored("[x] Please provide encrypted text to decrypt.", "red"))
            return
        if Fernet is None:
            print(colored("[x] cryptography library is required. Install with: pip install cryptography", "red"))
            return
        if not self.encryption_key:
            print(colored("[x] No encryption key found. Run 'genkey' first.", "red"))
            return
        try:
            f = Fernet(self.encryption_key)
            encrypted_data = base64.b64decode(arg.encode())
            decrypted = f.decrypt(encrypted_data)
            print(colored(f"[+] Decrypted: {decrypted.decode()}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Decryption error: {e}", "red"))

    def do_genkey(self, arg):
        if Fernet is None:
            print(colored("[x] cryptography library is required. Install with: pip install cryptography", "red"))
            return
        try:
            self.encryption_key = Fernet.generate_key()
            print(colored(f"[+] Encryption key generated: {base64.b64encode(self.encryption_key).decode()}", "green"))
        except Exception as e:
            print(colored(f"[x] Key generation error: {e}", "red"))

    def do_rsa(self, arg):
        if rsa is None or serialization is None:
            print(colored("[x] cryptography library is required. Install with: pip install cryptography", "red"))
            return
        try:
            bits = int(arg) if arg else 2048
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=bits
            )
            public_key = private_key.public_key()
            print(colored(f"[+] RSA {bits}-bit key pair generated", "green"))
            print(colored(f"Private key: {private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()}", "cyan"))
        except Exception as e:
            print(colored(f"[x] RSA key generation error: {e}", "red"))

    def do_stego(self, arg):
        args = arg.split()
        if len(args) < 2:
            print(colored("[x] Usage: stego <image_path> <text>", "red"))
            return
        try:
            image_path, text = args[0], ' '.join(args[1:])
            output_path = f"stego_{os.path.basename(image_path)}"
            hide_text_in_image(image_path, text, output_path)
            print(colored(f"[+] Text hidden in {output_path}", "green"))
        except Exception as e:
            print(colored(f"[x] Steganography error: {e}", "red"))

    def do_unstego(self, arg):
        if not arg:
            print(colored("[x] Please specify image path.", "red"))
            return
        try:
            text = extract_text_from_image(arg)
            print(colored(f"[+] Extracted text: {text}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Steganography extraction error: {e}", "red"))

    # Network Analysis
    def do_traceroute(self, arg):
        if not arg:
            print(colored("[x] Please specify a host.", "red"))
            return
        print(colored(f"[>] Tracing route to {arg}...", "blue"))
        try:
            cmd = self._build_command(["traceroute", arg])
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(colored(result.stdout, "cyan"))
        except Exception as e:
            print(colored(f"[x] Traceroute error: {e}", "red"))

    def do_whois(self, arg):
        if not arg:
            print(colored("[x] Please specify a domain.", "red"))
            return
        if whois is None:
            print(colored("[x] python-whois library is required. Install with: pip install python-whois", "red"))
            return
        print(colored(f"[>] Getting WHOIS information for {arg}...", "blue"))
        try:
            domain_info = whois.whois(arg)
            for key, value in domain_info.items():
                print(colored(f"{key}: {value}", "cyan"))
        except Exception as e:
            print(colored(f"[x] WHOIS error: {e}", "red"))

    def do_dns(self, arg):
        if not arg:
            print(colored("[x] Please specify a domain.", "red"))
            return
        if dns is None:
            print(colored("[x] dnspython library is required. Install with: pip install dnspython", "red"))
            return
        print(colored(f"[>] DNS lookup for {arg}...", "blue"))
        try:
            # A record
            a_records = dns.resolver.resolve(arg, 'A')
            print(colored("A Records:", "green"))
            for record in a_records:
                print(colored(f"  {record}", "cyan"))
            
            # MX record
            try:
                mx_records = dns.resolver.resolve(arg, 'MX')
                print(colored("\nMX Records:", "green"))
                for record in mx_records:
                    print(colored(f"  {record}", "cyan"))
            except:
                pass
        except Exception as e:
            print(colored(f"[x] DNS lookup error: {e}", "red"))

    def do_ssl(self, arg):
        if not arg:
            print(colored("[x] Please specify a host.", "red"))
            return
        print(colored(f"[>] Analyzing SSL certificate for {arg}...", "blue"))
        try:
            context = ssl.create_default_context()
            with socket.create_connection((arg, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=arg) as ssock:
                    cert = ssock.getpeercert()
                    print(colored("Certificate Details:", "green"))
                    for key, value in cert.items():
                        print(colored(f"  {key}: {value}", "cyan"))
        except Exception as e:
            print(colored(f"[x] SSL analysis error: {e}", "red"))

    def do_arp(self, arg):
        print(colored("[>] Scanning ARP table...", "blue"))
        try:
            cmd = self._build_command(["arp", "-a"])
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(colored(result.stdout, "cyan"))
        except Exception as e:
            print(colored(f"[x] ARP scan error: {e}", "red"))

    # Data Processing
    def do_logparse(self, arg):
        if not arg:
            print(colored("[x] Please specify a log file.", "red"))
            return
        print(colored(f"[>] Parsing log file {arg}...", "blue"))
        try:
            with open(arg, 'r') as f:
                lines = f.readlines()
            
            # Count different log levels
            levels = {}
            for line in lines:
                if 'ERROR' in line:
                    levels['ERROR'] = levels.get('ERROR', 0) + 1
                elif 'WARNING' in line:
                    levels['WARNING'] = levels.get('WARNING', 0) + 1
                elif 'INFO' in line:
                    levels['INFO'] = levels.get('INFO', 0) + 1
            
            print(colored("Log Analysis:", "green"))
            for level, count in levels.items():
                print(colored(f"  {level}: {count}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Log parsing error: {e}", "red"))

    def do_pattern(self, arg):
        if not arg:
            print(colored("[x] Please provide text to analyze.", "red"))
            return
        print(colored("[>] Analyzing patterns...", "blue"))
        try:
            # Find IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, arg)
            if ips:
                print(colored(f"IP Addresses found: {ips}", "cyan"))
            
            # Find email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, arg)
            if emails:
                print(colored(f"Email addresses found: {emails}", "cyan"))
            
            # Find URLs
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, arg)
            if urls:
                print(colored(f"URLs found: {urls}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Pattern analysis error: {e}", "red"))

    def do_metadata(self, arg):
        if not arg:
            print(colored("[x] Please specify a file.", "red"))
            return
        print(colored(f"[>] Analyzing metadata for {arg}...", "blue"))
        try:
            stat = os.stat(arg)
            print(colored("File Metadata:", "green"))
            print(colored(f"  Size: {stat.st_size} bytes", "cyan"))
            print(colored(f"  Modified: {datetime.fromtimestamp(stat.st_mtime)}", "cyan"))
            print(colored(f"  Permissions: {oct(stat.st_mode)[-3:]}", "cyan"))
        except Exception as e:
            print(colored(f"[x] Metadata analysis error: {e}", "red"))

    def do_analyze(self, arg):
        if not arg:
            print(colored("[x] Please specify a file.", "red"))
            return
        print(colored(f"[>] Analyzing file type for {arg}...", "blue"))
        try:
            cmd = self._build_command(["file", arg])
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(colored(result.stdout, "cyan"))
        except Exception as e:
            print(colored(f"[x] File analysis error: {e}", "red"))

    # Automation & Monitoring
    def do_monitor(self, arg):
        if not arg:
            print(colored("[x] Please specify a directory path.", "red"))
            return
        if Observer is None:
            print(colored("[x] watchdog library is required. Install with: pip install watchdog", "red"))
            return
        print(colored(f"[>] Starting monitoring for {arg}...", "blue"))
        try:
            if self.file_observer:
                self.file_observer.stop()
            
            def file_changed(path):
                print(colored(f"[!] File changed: {path}", "yellow"))
            
            self.file_observer = Observer()
            self.file_observer.schedule(FileMonitor(file_changed), arg, recursive=True)
            self.file_observer.start()
            self.monitoring_paths.append(arg)
            print(colored(f"[+] Monitoring started for {arg}", "green"))
        except Exception as e:
            print(colored(f"[x] Monitoring error: {e}", "red"))

    def do_schedule(self, arg):
        if not arg:
            print(colored("[x] Please specify a command to schedule.", "red"))
            return
        print(colored(f"[>] Scheduling command: {arg}", "blue"))
        try:
            # Simple scheduling - in real implementation, you'd use a proper scheduler
            self.scheduled_tasks.append(arg)
            print(colored(f"[+] Command scheduled: {arg}", "green"))
        except Exception as e:
            print(colored(f"[x] Scheduling error: {e}", "red"))

    def do_tasks(self, arg):
        print(colored("[>] Scheduled tasks:", "blue"))
        if self.scheduled_tasks:
            for i, task in enumerate(self.scheduled_tasks, 1):
                print(colored(f"  {i}. {task}", "cyan"))
        else:
            print(colored("  No scheduled tasks", "yellow"))

    def do_system(self, arg):
        if psutil is None:
            print(colored("[x] psutil library is required. Install with: pip install psutil", "red"))
            return
        print(colored("[>] System information:", "blue"))
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            print(colored(f"CPU Usage: {cpu_percent}%", "cyan"))
            
            # Memory usage
            memory = psutil.virtual_memory()
            print(colored(f"Memory Usage: {memory.percent}%", "cyan"))
            
            # Disk usage
            disk = psutil.disk_usage('/')
            print(colored(f"Disk Usage: {disk.percent}%", "cyan"))
            
            # Network interfaces
            print(colored("\nNetwork Interfaces:", "green"))
            for interface, addrs in psutil.net_if_addrs().items():
                print(colored(f"  {interface}:", "cyan"))
                for addr in addrs:
                    print(colored(f"    {addr.address}", "yellow"))
        except Exception as e:
            print(colored(f"[x] System info error: {e}", "red"))

    # Utilities
    def do_password(self, arg):
        try:
            length = int(arg) if arg else 12
            password = generate_password(length)
            print(colored(f"[+] Generated password: {password}", "green"))
        except Exception as e:
            print(colored(f"[x] Password generation error: {e}", "red"))

    def do_qr(self, arg):
        if not arg:
            print(colored("[x] Please provide text for QR code.", "red"))
            return
        if qrcode is None:
            print(colored("[x] qrcode library is required. Install with: pip install qrcode", "red"))
            return
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(arg)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            filename = f"qr_{int(time.time())}.png"
            img.save(filename)
            print(colored(f"[+] QR code saved as {filename}", "green"))
        except Exception as e:
            print(colored(f"[x] QR code generation error: {e}", "red"))

    def do_config(self, arg):
        print(colored("Current Configuration:", "green"))
        for key, value in self.config.data.items():
            print(colored(f"  {key}: {value}", "cyan"))

    def do_history(self, arg):
        print(colored("Command History:", "green"))
        for i, cmd in enumerate(self.command_history[-10:], 1):
            print(colored(f"  {i}. {cmd}", "cyan"))

    def do_sqlrecon(self, arg):
        """SQL Recon Protocol - Advanced SQL injection reconnaissance"""
        print(colored("╔══════════════════════════════════════╗", "red"))
        print(colored("║     SQL RECON PROTOCOL ENGAGED       ║", "red"))
        print(colored("╚══════════════════════════════════════╝", "red"))
        print()
        
        if not arg:
            print(colored("[*] SQL Recon Protocol Commands:", "yellow"))
            print(colored("=" * 50, "yellow"))
            print()
            print(colored("Basic Reconnaissance:", "green"))
            print(colored("  sqlrecon basic <target_url>", "cyan"))
            print(colored("    └─ Basic SQL injection test", "white"))
            print()
            print(colored("Database Discovery:", "green"))
            print(colored("  sqlrecon dbs <target_url>", "cyan"))
            print(colored("    └─ Enumerate available databases", "white"))
            print()
            print(colored("Table Discovery:", "green"))
            print(colored("  sqlrecon tables <target_url> <database>", "cyan"))
            print(colored("    └─ List tables in specified database", "white"))
            print()
            print(colored("Column Discovery:", "green"))
            print(colored("  sqlrecon columns <target_url> <database> <table>", "cyan"))
            print(colored("    └─ List columns in specified table", "white"))
            print()
            print(colored("Data Extraction:", "green"))
            print(colored("  sqlrecon dump <target_url> <database> <table> <columns>", "cyan"))
            print(colored("    └─ Extract data from specified columns", "white"))
            print()
            print(colored("POST Data Testing:", "green"))
            print(colored("  sqlrecon post <target_url> <data>", "cyan"))
            print(colored("    └─ Test POST-based SQL injection", "white"))
            print()
            print(colored("Cookie-based Testing:", "green"))
            print(colored("  sqlrecon cookie <target_url> <cookie>", "cyan"))
            print(colored("    └─ Test cookie-based SQL injection", "white"))
            print()
            print(colored("Tor Stealth Mode:", "green"))
            print(colored("  sqlrecon tor <target_url>", "cyan"))
            print(colored("    └─ Execute through Tor network", "white"))
            print()
            print(colored("Tags: [sqlmap, injection, database, recon, stealth]", "magenta"))
            return
        
        args = arg.split()
        if len(args) < 2:
            print(colored("[x] Invalid syntax. Use 'sqlrecon' for help.", "red"))
            return
        
        command = args[0].lower()
        target_url = args[1]
        
        try:
            if command == "basic":
                print(colored(f"[>] Initiating basic SQL injection test on {target_url}", "blue"))
                print(colored("Command: sqlmap -u " + target_url, "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "dbs":
                print(colored(f"[>] Enumerating databases on {target_url}", "blue"))
                print(colored("Command: sqlmap -u " + target_url + " --dbs", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "tables":
                if len(args) < 3:
                    print(colored("[x] Please specify database name.", "red"))
                    return
                database = args[2]
                print(colored(f"[>] Enumerating tables in database '{database}' on {target_url}", "blue"))
                print(colored(f"Command: sqlmap -u {target_url} -D {database} --tables", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "columns":
                if len(args) < 4:
                    print(colored("[x] Please specify database and table names.", "red"))
                    return
                database, table = args[2], args[3]
                print(colored(f"[>] Enumerating columns in table '{table}' of database '{database}'", "blue"))
                print(colored(f"Command: sqlmap -u {target_url} -D {database} -T {table} --columns", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "dump":
                if len(args) < 5:
                    print(colored("[x] Please specify database, table, and columns.", "red"))
                    return
                database, table, columns = args[2], args[3], args[4]
                print(colored(f"[>] Extracting data from columns '{columns}' in table '{table}'", "blue"))
                print(colored(f"Command: sqlmap -u {target_url} -D {database} -T {table} -C {columns} --dump", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "post":
                if len(args) < 3:
                    print(colored("[x] Please specify POST data.", "red"))
                    return
                data = args[2]
                print(colored(f"[>] Testing POST-based SQL injection with data: {data}", "blue"))
                print(colored(f"Command: sqlmap -u {target_url} --data=\"{data}\" --method=POST", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "cookie":
                if len(args) < 3:
                    print(colored("[x] Please specify cookie data.", "red"))
                    return
                cookie = args[2]
                print(colored(f"[>] Testing cookie-based SQL injection with: {cookie}", "blue"))
                print(colored(f"Command: sqlmap -u {target_url} --cookie=\"{cookie}\" --random-agent", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                
            elif command == "tor":
                print(colored(f"[>] Initiating Tor-based stealth reconnaissance on {target_url}", "blue"))
                print(colored("Command: sqlmap -u " + target_url + " --tor --tor-type=SOCKS5 --check-tor", "cyan"))
                print(colored("[*] Execute this command in your terminal for actual testing", "yellow"))
                print(colored("[!] Ensure Tor is running and accessible", "red"))
                
            else:
                print(colored("[x] Unknown command. Use 'sqlrecon' for help.", "red"))
                return
                
        except Exception as e:
            print(colored(f"[x] SQL Recon Protocol error: {e}", "red"))

    def do_ezeforce(self, arg):
        """EZEFORCE Analysis Unit - Advanced analytical tools for security research"""
        print(colored("╔══════════════════════════════════════╗", "red"))
        print(colored("║     EZEFORCE ANALYSIS UNIT         ║", "red"))
        print(colored("╚══════════════════════════════════════╝", "red"))
        print()
        
        if not arg:
            print(colored("[*] EZEFORCE Analysis Unit Commands:", "yellow"))
            print(colored("=" * 50, "yellow"))
            print()
            print(colored("Hash Analysis:", "green"))
            print(colored("  ezeforce hash <hash> <wordlist>", "cyan"))
            print(colored("    └─ Analyze hash using dictionary attack", "white"))
            print()
            print(colored("SSH Analysis:", "green"))
            print(colored("  ezeforce ssh <ip> <username> <wordlist>", "cyan"))
            print(colored("    └─ Test SSH login possibility with dictionary", "white"))
            print()
            print(colored("ZIP Analysis:", "green"))
            print(colored("  ezeforce zip <file.zip> <wordlist>", "cyan"))
            print(colored("    └─ Attempt ZIP file decryption with dictionary", "white"))
            print()
            print(colored("HTTP Analysis:", "green"))
            print(colored("  ezeforce http <url> <username> <wordlist>", "cyan"))
            print(colored("    └─ Analyze HTTP login form with dictionary", "white"))
            print()
            print(colored("Tags: [ezeforce, bruteforce, analysis, hash, ssh, zip, http, recon]", "magenta"))
            print(colored("\n[!] ANALYTICAL USE ONLY - Educational and research purposes", "yellow"))
            return
        
        args = arg.split()
        if len(args) < 3:
            print(colored("[x] Invalid syntax. Use 'ezeforce' for help.", "red"))
            return
        
        command = args[0].lower()
        
        try:
            if command == "hash":
                if len(args) < 3:
                    print(colored("[x] Please specify hash and wordlist.", "red"))
                    return
                hash_value = args[1]
                wordlist = args[2]
                print(colored(f"[>] Initiating hash analysis for: {hash_value[:20]}...", "blue"))
                print(colored(f"[>] Using wordlist: {wordlist}", "blue"))
                print(colored("Command: hashcat -m 0 " + hash_value + " " + wordlist, "cyan"))
                print(colored("Alternative: john --wordlist=" + wordlist + " " + hash_value, "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual analysis", "yellow"))
                print(colored("[!] Ensure you have proper authorization for hash analysis", "red"))
                
            elif command == "ssh":
                if len(args) < 4:
                    print(colored("[x] Please specify IP, username, and wordlist.", "red"))
                    return
                ip, username, wordlist = args[1], args[2], args[3]
                print(colored(f"[>] Analyzing SSH access possibility to {ip} as {username}", "blue"))
                print(colored(f"[>] Using wordlist: {wordlist}", "blue"))
                print(colored("Command: hydra -l " + username + " -P " + wordlist + " ssh://" + ip, "cyan"))
                print(colored("Alternative: medusa -h " + ip + " -u " + username + " -P " + wordlist + " -M ssh", "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual analysis", "yellow"))
                print(colored("[!] Ensure you have proper authorization for SSH testing", "red"))
                
            elif command == "zip":
                if len(args) < 3:
                    print(colored("[x] Please specify ZIP file and wordlist.", "red"))
                    return
                zip_file, wordlist = args[1], args[2]
                print(colored(f"[>] Analyzing ZIP file: {zip_file}", "blue"))
                print(colored(f"[>] Using wordlist: {wordlist}", "blue"))
                print(colored("Command: fcrackzip -D -p " + wordlist + " " + zip_file, "cyan"))
                print(colored("Alternative: john --wordlist=" + wordlist + " " + zip_file, "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual analysis", "yellow"))
                print(colored("[!] Ensure you have proper authorization for ZIP analysis", "red"))
                
            elif command == "http":
                if len(args) < 4:
                    print(colored("[x] Please specify URL, username, and wordlist.", "red"))
                    return
                url, username, wordlist = args[1], args[2], args[3]
                print(colored(f"[>] Analyzing HTTP login form at: {url}", "blue"))
                print(colored(f"[>] Testing username: {username}", "blue"))
                print(colored(f"[>] Using wordlist: {wordlist}", "blue"))
                print(colored("Command: hydra -l " + username + " -P " + wordlist + " " + url + " http-post-form", "cyan"))
                print(colored("Alternative: medusa -h " + url + " -u " + username + " -P " + wordlist + " -M http", "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual analysis", "yellow"))
                print(colored("[!] Ensure you have proper authorization for HTTP analysis", "red"))
                
            else:
                print(colored("[x] Unknown command. Use 'ezeforce' for help.", "red"))
                return
                
        except Exception as e:
            print(colored(f"[x] EZEFORCE Analysis Unit error: {e}", "red"))

    def do_ezewifi(self, arg):
        """EZEWIFI Analysis Unit - Advanced Wi-Fi network analysis and monitoring"""
        print(colored("╔══════════════════════════════════════╗", "red"))
        print(colored("║         EZEWIFI ANALYSIS UNIT       ║", "red"))
        print(colored("╚══════════════════════════════════════╝", "red"))
        print()
        
        if not arg:
            print(colored("[*] EZEWIFI Analysis Unit Commands:", "yellow"))
            print(colored("=" * 50, "yellow"))
            print()
            print(colored("Network Discovery:", "green"))
            print(colored("  ezewifi scan", "cyan"))
            print(colored("    └─ Scan for available Wi-Fi networks", "white"))
            print()
            print(colored("Network Information:", "green"))
            print(colored("  ezewifi info <bssid>", "cyan"))
            print(colored("    └─ Get detailed information about selected network", "white"))
            print()
            print(colored("Client Analysis:", "green"))
            print(colored("  ezewifi clients <bssid>", "cyan"))
            print(colored("    └─ Display connected clients to the network", "white"))
            print()
            print(colored("Interface Monitoring:", "green"))
            print(colored("  ezewifi monitor <interface>", "cyan"))
            print(colored("    └─ Enable monitoring mode on network interface", "white"))
            print()
            print(colored("Traffic Analysis:", "green"))
            print(colored("  ezewifi sniff <interface>", "cyan"))
            print(colored("    └─ Capture packets for traffic analysis", "white"))
            print()
            print(colored("Tags: [ezewifi, wifi, network, monitoring, analysis, sniffing, recon]", "magenta"))
            print(colored("\n[!] ANALYTICAL USE ONLY - Educational and research purposes", "yellow"))
            print(colored("[!] Ensure proper authorization for network analysis", "red"))
            return
        
        args = arg.split()
        if len(args) < 1:
            print(colored("[x] Invalid syntax. Use 'ezewifi' for help.", "red"))
            return
        
        command = args[0].lower()
        
        try:
            if command == "scan":
                print(colored("[>] Initiating Wi-Fi network scan...", "blue"))
                print(colored("Command: iwlist scan", "cyan"))
                print(colored("Alternative: nmcli dev wifi list", "cyan"))
                print(colored("Advanced: airodump-ng <interface>", "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual scanning", "yellow"))
                print(colored("[!] Ensure you have proper authorization for network scanning", "red"))
                
            elif command == "info":
                if len(args) < 2:
                    print(colored("[x] Please specify BSSID.", "red"))
                    return
                bssid = args[1]
                print(colored(f"[>] Analyzing network information for BSSID: {bssid}", "blue"))
                print(colored("Command: iwlist scan | grep -A 20 " + bssid, "cyan"))
                print(colored("Alternative: nmcli dev wifi show " + bssid, "cyan"))
                print(colored("Advanced: airodump-ng --bssid " + bssid + " <interface>", "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual analysis", "yellow"))
                print(colored("[!] Ensure you have proper authorization for network analysis", "red"))
                
            elif command == "clients":
                if len(args) < 2:
                    print(colored("[x] Please specify BSSID.", "red"))
                    return
                bssid = args[1]
                print(colored(f"[>] Analyzing connected clients for BSSID: {bssid}", "blue"))
                print(colored("Command: airodump-ng --bssid " + bssid + " <interface>", "cyan"))
                print(colored("Alternative: nmap -sn <network_range>", "cyan"))
                print(colored("Advanced: aireplay-ng --deauth 0 -a " + bssid + " <interface>", "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual analysis", "yellow"))
                print(colored("[!] Ensure you have proper authorization for client analysis", "red"))
                
            elif command == "monitor":
                if len(args) < 2:
                    print(colored("[x] Please specify network interface.", "red"))
                    return
                interface = args[1]
                print(colored(f"[>] Enabling monitoring mode on interface: {interface}", "blue"))
                print(colored("Command: airmon-ng start " + interface, "cyan"))
                print(colored("Alternative: iw dev " + interface + " set type monitor", "cyan"))
                print(colored("Manual: ifconfig " + interface + " down && iwconfig " + interface + " mode monitor && ifconfig " + interface + " up", "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual monitoring", "yellow"))
                print(colored("[!] Ensure you have proper authorization for interface monitoring", "red"))
                
            elif command == "sniff":
                if len(args) < 2:
                    print(colored("[x] Please specify network interface.", "red"))
                    return
                interface = args[1]
                print(colored(f"[>] Initiating packet capture on interface: {interface}", "blue"))
                print(colored("Command: tcpdump -i " + interface + " -w capture.pcap", "cyan"))
                print(colored("Alternative: airodump-ng " + interface, "cyan"))
                print(colored("Advanced: wireshark -i " + interface, "cyan"))
                print(colored("[*] Execute these commands in your terminal for actual packet capture", "yellow"))
                print(colored("[!] Ensure you have proper authorization for packet sniffing", "red"))
                
            else:
                print(colored("[x] Unknown command. Use 'ezewifi' for help.", "red"))
                return
                
        except Exception as e:
            print(colored(f"[x] EZEWIFI Analysis Unit error: {e}", "red"))

    def do_root(self, arg):
        """Enable root mode - commands will be prefixed with sudo"""
        self.root_mode = True
        print(colored("╔════════════════════════════════════╗", "red"))
        print(colored("║        ROOT MODE ENABLED          ║", "red"))
        print(colored("╚════════════════════════════════════╝", "red"))
        print(colored("[*] Root mode enabled - commands will be prefixed with 'sudo'", "yellow"))
        print(colored("[!] Use 'unroot' to disable root mode", "cyan"))

    def do_unroot(self, arg):
        """Disable root mode - commands will run normally"""
        self.root_mode = False
        print(colored("[*] Root mode disabled - commands will run normally", "yellow"))
        print(colored("[*] Use 'root' to enable root mode", "cyan"))
        print(colored("[!] WARNING: Some commands may require elevated privileges", "red"))

    def do_exit(self, arg):
        if self.file_observer:
            self.file_observer.stop()
        print(colored("[*] Leaving the shadows...", "cyan"))
        return True

# Run CLI
if __name__ == '__main__':
    animate_banner()
    EzervarShell().cmdloop()
