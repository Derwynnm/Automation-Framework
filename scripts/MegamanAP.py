import os
import sys
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

import pandas as pd
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)

from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")


# Configuration

LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "ap_inventory_log.txt"
OUTPUT_XLSX   = Path(__file__).resolve().parents[1] / "docs" / "ap_inventory.xlsx"
THREAD_MULTI  = 7         # default threads ≈ cores × 7

logging.basicConfig(
    filename=LOG_FILE,
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
)
log = logging.getLogger(__name__)

CDP_SPLIT   = re.compile(r"-{10,}")           # lines of dashes between detail blocks
DEVICE_RE   = re.compile(r"Device ID:\s+(\S+)")
PLATFORM_RE = re.compile(r"Platform:\s+(.+?),")



# Helpers


def _ap_model(block: str) -> str | None:
    """Return the AP model for this CDP‑detail block, or None if it’s not an AP."""
    dev = DEVICE_RE.search(block)
    if not dev:
        return None
    device_id = dev.group(1)
    if "-AP" not in device_id:            # your naming convention
        return None

    plat = PLATFORM_RE.search(block)
    return plat.group(1).strip() if plat else "Unknown‑Model"


def _scan_switch(ip: str) -> list[tuple[str, str, str]]:
    """SSH to one switch and return a list of tuples: (model, device_id, seen_from_ip)"""
    device = {
        "device_type": "cisco_ios",
        "host":        ip,
        "username":    username,
        "password":    password,
        "secret":      secret,
        "conn_timeout": 60,
    }
    found: list[tuple[str, str, str]] = []

    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            conn.send_command("terminal length 0", expect_string=r"#")
            out = conn.send_command("show cdp neighbors detail", expect_string=r"#")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        log.warning("Cannot connect to %s : %s", ip, e)
        return found

    for blk in CDP_SPLIT.split(out):
        model = _ap_model(blk)
        if model:
            dev_id = DEVICE_RE.search(blk).group(1)
            found.append((model, dev_id, ip))

    return found



# Main


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("Usage:  python ap_inventory.py devices.xlsx [thread_count]")

    inventory_path = sys.argv[1]
    max_workers = (
        int(sys.argv[2]) if len(sys.argv) > 2 else (os.cpu_count() or 6) * THREAD_MULTI
    )

    df = pd.read_excel(inventory_path)
    if "IP Address" not in df.columns:
        sys.exit("Excel sheet must have a column named 'IP Address'")

    ips = df["IP Address"].dropna().astype(str).tolist()
    log.info("Scanning %d switches with %d threads", len(ips), max_workers)

    model_counts: defaultdict[str, int] = defaultdict(int)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_switch, ip): ip for ip in ips}

        for fut in as_completed(futures):
            for model, device_id, seen_from in fut.result():
                model_counts[model] += 1
                log.info(
                    "Found AP %-20s  model=%s  seen_from=%s",
                    device_id,
                    model,
                    seen_from,
                )

    # Write summary Excel
    tally_df = (
        pd.DataFrame(sorted(model_counts.items()), columns=["Model", "Count"])
        .sort_values("Model")
        .reset_index(drop=True)
    )
    tally_df.to_excel(OUTPUT_XLSX, index=False)

    print(f"✅  Inventory complete — {len(model_counts)} AP models written to {OUTPUT_XLSX}")
    print(f"📝  Detailed discovery log saved as {LOG_FILE}")


if __name__ == "__main__":
    main()
