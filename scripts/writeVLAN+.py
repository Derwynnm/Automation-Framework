from __future__ import annotations
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict
from dotenv import load_dotenv
import os

import pandas as pd
from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

# ───────────────── USER CONFIGURABLE ─────────────────────────────────────────
EXCEL_FILE = Path(r"C:\Users\dmckella\Desktop\Automation\District.xlsx")
MAX_THREADS = 200      # upper bound for concurrent SSH sessions
RETRIES = 3           # per‑device connect retries
BACKOFF_SEC = 2       # initial back‑off; doubles each retry
SKIP_VLANS = {"1002", "1003", "1004", "1005"}
# ---------------------------------------------------------------------------

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")


def fetch_vlans(ip: str) -> str:
    """Return a comma‑separated, sorted VLAN string for *ip* (empty on failure)."""

    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "secret": secret if secret else None,
        "conn_timeout": 60,
    }

    for attempt in range(RETRIES):
        try:
            conn = ConnectHandler(**device)
            if not conn.check_enable_mode():
                conn.enable()
            output = conn.send_command("show vlan brief")
            conn.disconnect()
            break
        except NetmikoAuthenticationException:
            print(f"[AUTHFAIL] {ip}")
            return ""
        except NetmikoTimeoutException:
            wait = BACKOFF_SEC * 2**attempt
            print(f"[TIMEOUT] {ip} – retry {attempt+1}/{RETRIES} in {wait}s")
            time.sleep(wait)
    else:
        print(f"[FAIL] {ip} – unable to connect after retries")
        return ""

    # Parse VLAN IDs at line start, ignoring headers
    vlans = re.findall(r"^\s*(\d+)\s", output, re.MULTILINE)
    vlan_list = sorted({v for v in vlans if v not in SKIP_VLANS}, key=int)
    return ", ".join(vlan_list)


def main() -> None:
    if not EXCEL_FILE.is_file():
        raise FileNotFoundError(EXCEL_FILE)

    df = pd.read_excel(EXCEL_FILE)
    if "VLANs" not in df.columns:
        df.insert(len(df.columns), "VLANs", "")  # new column at end

    print(f"Loaded {len(df)} rows – starting VLAN collection with {MAX_THREADS} threads…")

    results: Dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        futures = {
            pool.submit(fetch_vlans, str(row.get("IP Address")).strip()): idx
            for idx, row in df.iterrows()
            if str(row.get("IP Address")).strip() and str(row.get("IP Address")).lower() != "nan"
        }

        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                vlan_str = fut.result()
            except Exception as exc: 
                print(f"[EXC] Row {idx}: {exc}")
                vlan_str = ""
            results[idx] = vlan_str

    # Write results back to DataFrame
    for idx, vlans in results.items():
        df.at[idx, "VLANs"] = vlans

    out_file = EXCEL_FILE.with_stem(EXCEL_FILE.stem + "_updated")
    df.to_excel(out_file, index=False)
    print(f"\nVLAN data written to {out_file}")


if __name__ == "__main__":
    main()
