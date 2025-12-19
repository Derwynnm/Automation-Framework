import pandas as pd
from netmiko import ConnectHandler
from dotenv import load_dotenv
from pathlib import Path
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")


# Load Excel file with IPs and VLANs
INPUT_FILE = Path(__file__).resolve().parents[1] / "database" / "AIK.xlsx"  # Same file you used before
df = pd.read_excel(INPUT_FILE)

for index, row in df.iterrows():
    ip = str(row.get('IP Address')).strip()

    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret if secret else None,
    }

    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Build rollback config
        commands = ['spanning-tree mode pvst']  # revert back to standard STP
        commands.append(f'spanning-tree vlan 1-4094 priority 24576')
        commands.append('end')
        commands.append('wr')  # Save config

        output = connection.send_config_set(commands)
        print(f" Rollback complete on {ip}:\n{output}")
        connection.disconnect()

    except Exception as e:
        print(f" Could not connect to {ip}: {e}")
