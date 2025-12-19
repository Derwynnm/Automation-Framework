from __future__ import annotations
import os
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set
import pandas as pd
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")

# CDP parsing helpers
_CAPS_RE = re.compile(r"Capabilities:\s+(.+)")
_DEVICE_RE = re.compile(r"Device ID:\s+(\S+)")


def _is_switch(block: str) -> bool:
    m = _CAPS_RE.search(block)
    return bool(m and "Switch" in m.group(1))


def _parse_switch_neighbors(output: str) -> List[str]:
    blocks = re.split(r"\n-{10,}\n", output)
    ids: List[str] = []
    for blk in blocks:
        if not _is_switch(blk):
            continue
        m = _DEVICE_RE.search(blk)
        if m:
            ids.append(m.group(1))
    return ids

# Worker

def _scan_device(name: str, ip: str, timeout: int = 10) -> List[str]:
    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": timeout,
    }
    try:
        conn = ConnectHandler(**device)
        if secret:
            conn.enable()
        conn.send_command("terminal length 0", expect_string=r"[#>]", strip_prompt=False, strip_command=False)
        out = conn.send_command("show cdp neighbors detail", expect_string=r"[#>]", read_timeout=30)
        conn.disconnect()
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"[!] {ip} ({name}): {e}")
        return []
    return _parse_switch_neighbors(out)

# Main logic

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python cdp_missing_switches.py <devices.xlsx> [threads]")
        sys.exit(1)

    input_file = sys.argv[1]
    thread_arg = int(sys.argv[2]) if len(sys.argv) >= 3 else None

    df = pd.read_excel(input_file)
    if not {"Device Name", "IP Address"}.issubset(df.columns):
        sys.exit("ERROR: sheet must include 'Device Name' and 'IP Address' columns.")

    known: Set[str] = set(df["Device Name"].astype(str))
    stray_map: Dict[str, Set[str]] = defaultdict(set)

    cores = os.cpu_count() or 4
    max_workers = thread_arg or max(5, min(cores * 7, 100))
    print(f"[*] Launching scans with {max_workers} threads …")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_source = {}
        for _, row in df.iterrows():
            name = str(row["Device Name"]).strip()
            ip = str(row["IP Address"]).strip()
            if ip and ip.lower() != "nan":
                fut = pool.submit(_scan_device, name, ip)
                fut_to_source[fut] = name

        for fut in as_completed(fut_to_source):
            source = fut_to_source[fut]
            for neighbor in fut.result():
                if neighbor not in known:
                    stray_map[neighbor].add(source)

    if stray_map:
        out_rows = [
            {"Undocumented": stray, "Seen Via": ", ".join(sorted(vias))}
            for stray, vias in sorted(stray_map.items())
        ]
        out_df = pd.DataFrame(out_rows)
        outfile = Path("undocumented_switches.xlsx")
        out_df.to_excel(outfile, index=False)
        print(f"[+] FOUND {len(out_df)} undocumented switch(es). Saved to {outfile.resolve()}")
    else:
        print("[+] No stray switches found — inventory is complete ✔️")


if __name__ == "__main__":
    main()
