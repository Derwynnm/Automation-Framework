from __future__ import annotations
import csv
import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import pandas as pd
from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

# ─────────── USER CONFIGURABLE ────────────────────────────────────────────────
EXCEL_FILE = Path(r"C:\Users\dmckella\Desktop\Automation\RSTP Project\High.xlsx")
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "rstp_log.txt"
MAX_GLOBAL_THREADS = 200        # never exceed this many simultaneous sessions
MAX_PER_SITE_THREADS = 10       # limit per derived site label
RETRIES = 5                    # SSH connection retries
BACKOFF_SEC = 2                # exponential back‑off seed (seconds)
# -----------------------------------------------------------------------------

from dotenv import load_dotenv
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")

# ─────────── logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("paramiko").setLevel(logging.WARNING)

# ─────────── helpers ─────────────────────────────────────────────────────────

def site_from_ip(ip: str) -> str:
    """Return a site label based on IP per stated rules."""
    try:
        o = ip.split(".")
        if len(o) != 4:
            return "default"
        if o[0] == "10" and o[1] == "199":
            return o[2]  # 10.199.X.Y  -> X
        if o[0] == "10" and o[1] == "0" and o[2] == "0":
            return o[3]  # 10.0.0.Z    -> Z
    except Exception:
        pass
    return "default"


# semaphores for pacing
_global_sema = threading.BoundedSemaphore(MAX_GLOBAL_THREADS)
_site_semas: defaultdict[str, threading.BoundedSemaphore] = defaultdict(
    lambda: threading.BoundedSemaphore(MAX_PER_SITE_THREADS)
)

SummaryRow = Tuple[str, str, str]  # (ip, site, status)
_summary: List[SummaryRow] = []


# ─────────── core push function ─────────────────────────────────────────────

def push_config(ip: str, site: str, vlan_string: str, root_value) -> SummaryRow:
    """SSH to *ip*, apply RSTP config, return (ip, site, status)."""

    with _site_semas[site]:
        with _global_sema:
            device = {
                "device_type": "cisco_ios",
                "host": ip,
                "username": username,
                "password": password,
                "secret": secret if secret else None,
            }

            # Connect with retries
            for attempt in range(RETRIES):
                try:
                    conn = ConnectHandler(**device)
                    if not conn.check_enable_mode():
                        conn.enable()
                    break  # success
                except NetmikoAuthenticationException as e:
                    msg = f"AUTH_FAIL:{e}"[:32]
                    logging.error("%s %s", ip, msg)
                    return ip, site, msg
                except NetmikoTimeoutException:
                    wait = BACKOFF_SEC * 2**attempt
                    logging.warning("%s timeout (%s) – retry in %ss", ip, attempt + 1, wait)
                    time.sleep(wait)
            else:
                logging.error("%s unable to connect after retries", ip)
                return ip, site, "CONN_FAIL"

            cmds = [
                "spanning-tree mode rapid-pvst",
                "no spanning-tree vlan 1-4094 priority 24576",
            ]
            try:
                root_int = int(root_value)
            except (ValueError, TypeError):
                root_int = None

            if root_int in {1, 2} and isinstance(vlan_string, str):
                vlans = [v.strip() for v in vlan_string.split(',') if v.strip()]
                priority = "0" if root_int == 1 else "4096"
                cmds += [f"spanning-tree vlan {v} priority {priority}" for v in vlans]

            cmds += ["end", "wr"]

            try:
                output = conn.send_config_set(cmds)
                status = "OK" if "%" not in output else "CMD_ERR"
                if status == "CMD_ERR":
                    logging.error("%s command error: %s", ip, output)
                else:
                    logging.info("%s configured OK", ip)
            except Exception as e:
                status = f"ERR:{e}"[:32]
                logging.error("%s exception: %s", ip, e)
            finally:
                conn.disconnect()

            return ip, site, status


# ─────────── main ───────────────────────────────────────────────────────────

def main() -> None:
    if not EXCEL_FILE.is_file():
        raise FileNotFoundError(EXCEL_FILE)

    df = pd.read_excel(EXCEL_FILE)
    df.columns = df.columns.str.strip()

    roots, others = [], []
    for _, row in df.dropna(subset=["IP Address"]).iterrows():
        ip = str(row["IP Address"]).strip()
        site = site_from_ip(ip)
        vlan_str = str(row.get("VLANs", ""))
        root_val = row.get("Root")
        dev = (ip, site, vlan_str, root_val)
        if str(root_val).strip() == "1":
            roots.append(dev)
        else:
            others.append(dev)

    # 1️⃣ configure primary roots serially
    for ip, site, vlan, root_val in roots:
        _summary.append(push_config(ip, site, vlan, root_val))
        time.sleep(10)  # let RSTP settle

    # 2️⃣ others threaded
    with ThreadPoolExecutor(max_workers=MAX_GLOBAL_THREADS) as pool:
        fut_map = {
            pool.submit(push_config, ip, site, vlan, root_val): (ip, site)
            for ip, site, vlan, root_val in others
        }
        for fut in as_completed(fut_map):
            ip, site = fut_map[fut]
            try:
                res = fut.result()
            except Exception as e: 
                res = (ip, site, f"EXC:{e}"[:32])
            _summary.append(res)
            print(f"[{res[2]}] {res[0]} (site {res[1]})")

    # write CSV summary
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = Path(f"summary_{ts}.csv")
    with csv_path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["IP", "Site", "Status"])
        writer.writerows(_summary)

    print(f"\nRun complete — summary → {csv_path}")


if __name__ == "__main__":
    main()
