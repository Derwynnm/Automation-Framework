import pandas as pd
from netmiko import ConnectHandler
import re
from dotenv import load_dotenv
from pathlib import Path
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")

# Load MACs and IPs from Excel
INPUT_FILE = Path(__file__).resolve().parents[1] / "database" / "SBMAC.xlsx"
mac_df = pd.read_excel(INPUT_FILE)  # Excel sheet with IP and MAC columns
mac_df['MAC Address'] = mac_df['MAC Address'].str.lower()

# Sanitize MAC Column
mac_df['MAC Address'] = mac_df['MAC Address'].astype(str).str.lower()

# Group MAC addresses by switch IP
all_macs = [m for m in mac_df['MAC Address'] if m and m != 'nan']
switch_ips = [str(ip) for ip in mac_df['IP Address'] if pd.notna(ip)]

# --- 3) Pre-compile the regex to parse MAC table lines ---
pattern = re.compile(
    r'^\s*(?:\d+|All)\s+([0-9a-f\.]{4}\.[0-9a-f\.]{4}\.[0-9a-f\.]{4})\s+\S+\s+(\S+)',
    re.IGNORECASE | re.MULTILINE
)

# --- 4) Loop through each switch and every MAC ---
for ip in switch_ips:
    print(f"\nConnecting to switch at {ip}...")
    net_connect = ConnectHandler(
        device_type='cisco_ios',
        ip=ip,
        username=username,
        password=password,
        secret=secret
    )
    net_connect.enable()
    output = net_connect.send_command('show mac address-table')
    matches = pattern.findall(output)

    visited_interfaces = set()
    changes_made = False

    for mac in all_macs:
        for found_mac, interface in matches:
            iface = interface.strip()
            iface_lower = iface.lower()
            
            # Skip CPU entries and port-channels
            if iface_lower == 'cpu' or iface_lower.startswith('po') or iface_lower.startswith('twe'):
                continue
            
            # Match exact MAC and avoid reconfiguring same interface
            if mac == found_mac.lower() and iface not in visited_interfaces:
                print(f" → Found {mac} on {iface}; moving to VLAN 254")
                cmds = [
                    f"interface {iface}",
                    'switchport access vlan 254',
                    'exit'
                ]
                net_connect.send_config_set(cmds)
                visited_interfaces.add(iface)
                changes_made = True

    if changes_made:
        print('Saving configuration…')
        net_connect.send_command('write memory')
    else:
        print('No changes needed on this switch.')

    net_connect.disconnect()
    print(f"Finished switch {ip}\n")
