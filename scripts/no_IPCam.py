import pandas as pd
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
import logging

from dotenv import load_dotenv
from pathlib import Path
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")

# Configuration

THREADS = 10  # Adjust this to tune parallelism
FILE_PATH = Path(__file__).resolve().parents[1] / "database" / "IPCam.xlsx"  # Excel input
SSH_TIMEOUT = 60  # Seconds before an SSH attempt times out
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "ipcam_log.txt"  # Log file name

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Worker function – runs in its own thread

def configure_port_description(switch_ip: str, ports: list[str], description: str) -> str:
    """Connects to a Cisco IOS device, applies a description to each interface, and returns a short status string."""

    device = {
        "device_type": "cisco_ios",
        "host": switch_ip,
        "username": username,
        "password": password,
        "secret": secret if secret else None,
        "conn_timeout": SSH_TIMEOUT,
        "global_delay_factor": 1,
        "verbose": False,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()

            for port in ports:
                port = port.strip()
                if port.lower().startswith(('po', 'twe')):
                    logging.info(f"Skipped {port} on {switch_ip} (Port-Channel or Twe)")
                    continue
                cmd_set = [
                    f"interface {port}",
                    f"no description {description}",
                ]
                net_connect.send_config_set(cmd_set, cmd_verify=False)
                net_connect.find_prompt()
                sleep(0.5)
            
        result = f"SUCCESS: {switch_ip} ({len(ports)} ports)"
        logging.info(result)
        return result

    except Exception as exc:
        error = f"FAIL:    {switch_ip} → {exc}"
        logging.error(error)
        return error

# Helpers

def read_excel(file_path: str) -> pd.DataFrame:
    """Load Excel sheet containing columns 'IP Address', 'Port', 'Description'."""
    return pd.read_excel(file_path)

# Main execution

def main() -> None:
    df = read_excel(FILE_PATH)

    # Build job list for executor
    jobs = []
    with ThreadPoolExecutor(max_workers=min(THREADS, len(df))) as pool:
        for _, row in df.iterrows():
            ip = row["IP Address"]
            ports = [p.strip() for p in str(row["Port"]).split(",") if p.strip()]
            desc = row["Description"]
            jobs.append(pool.submit(configure_port_description, ip, ports, desc))

        # As jobs finish, print their status lines
        for future in as_completed(jobs):
            print(future.result())

if __name__ == "__main__":
    main()
