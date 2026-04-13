import pandas as pd
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import logging

from dotenv import load_dotenv
from pathlib import Path
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("NET_USERNAME")
password = os.getenv("NET_PASSWORD")
secret = os.getenv("NET_SECRET")

# Configuration

THREADS = 10  # Adjust this to tune parallelism
FILE_PATH = Path(__file__).resolve().parents[1] / "database" / "NRE.xlsx"  # Excel input
SSH_TIMEOUT = 60  # Seconds before an SSH attempt times out
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "port_description_log.txt"  # Log file name

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Worker function – runs in its own thread

def configure_port_description(switch_ip: str, port_desc_pairs: list[tuple[str, str]]) -> str:
    """Connects to a Cisco IOS device, applies descriptions to all interfaces in one session, and returns a short status string."""

    device = {
        "device_type": "cisco_ios",
        "host": switch_ip,
        "username": username,
        "password": password,
        "secret": secret if secret else None,
        "conn_timeout": SSH_TIMEOUT,
        "verbose": False,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()

            cmds = []
            skipped = []
            for port, description in port_desc_pairs:
                if port.lower().startswith(('po', 'twe')):
                    skipped.append(port)
                    logging.info(f"Skipped {port} on {switch_ip} (Port-Channel or Twe)")
                    continue
                if description:
                    cmds.extend([f"interface {port}", f"description {description}"])
                else:
                    cmds.extend([f"interface {port}", "no description"])

            configured = len(port_desc_pairs) - len(skipped)
            if cmds:
                response = net_connect.send_config_set(cmds, cmd_verify=False, read_timeout=120)
                if "% Invalid input" in response or "% Incomplete" in response or "% Ambiguous" in response:
                    logging.warning(f"Potential issue on {switch_ip}: {response.strip()}")
                else:
                    logging.info(f"Configured {configured} port(s) on {switch_ip}")

        result = f"SUCCESS: {switch_ip} ({configured} ports)"
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

    # Group all (port, description) pairs by IP so each device gets exactly one SSH connection
    ip_jobs: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for _, row in df.iterrows():
        ip = str(row["IP Address"]).strip()
        desc = str(row["Description"]).strip()
        for port in str(row["Port"]).split(","):
            port = port.strip()
            if port:
                ip_jobs[ip].append((port, desc))

    with ThreadPoolExecutor(max_workers=min(THREADS, len(ip_jobs))) as pool:
        futures = {pool.submit(configure_port_description, ip, pairs): ip
                   for ip, pairs in ip_jobs.items()}
        for future in as_completed(futures):
            print(future.result())

if __name__ == "__main__":
    main()
