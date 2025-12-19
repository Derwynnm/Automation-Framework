import os
import re
import sys
import time
from typing import List, Tuple, Optional
import pandas as pd
from netmiko import ConnectHandler
from netmiko import NetMikoTimeoutException, NetMikoAuthenticationException


from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")

# ============================ USER CONFIG ===================================
IP_LIST_PATH = str(Path(__file__).resolve().parents[1] / "database" / "IP.xlsx")         # Excel/CSV containing a column with IPs
OUTPUT_CSV   = str(Path(__file__).resolve().parents[1] / "docs" / "MTE.csv")

# Column name candidates for the IP address in your file (case-insensitive).
IP_COL_CANDIDATES = ["ip", "ip_address", "address", "management_ip", "mgmt_ip", "host"]

# SSH credentials (Cisco IOS/IOS-XE)
DEVICE_TYPE   = "cisco_ios"
USERNAME      = username
PASSWORD      = password
ENABLE_SECRET = secret

# Detection/policy
SEP_PREFIX            = "SEP"   # LLDP neighbor System Name starts with this
DESCRIPTION_PREFIX    = "MTE"   # required beginning of the interface description
CASE_SENSITIVE_PREFIX = False   # if True, exact case; if False, case-insensitive

# Timeouts/retries
CONN_TIMEOUT_SECS      = 20
DELAY_BETWEEN_SWITCHES = 0.0    # seconds to sleep between devices
# ========================== END USER CONFIG =================================


def read_table(path: str) -> pd.DataFrame:
    low = path.lower()
    if low.endswith(".xlsx") or low.endswith(".xls"):
        return pd.read_excel(path)
    return pd.read_csv(path)


def must_get_col(df: pd.DataFrame, candidates, label: str) -> str:
    cols = {str(c).strip().lower(): c for c in df.columns}
    # try exact (case-insensitive)
    for cand in candidates:
        if cand.lower() in cols:
            return cols[cand.lower()]
    # try normalized space/underscore removal
    def norm(s: str) -> str:
        return re.sub(r"[\s_]+", "", s.lower())
    for cand in candidates:
        for lower, orig in cols.items():
            if norm(lower) == norm(cand):
                return orig
    raise ValueError(f"Could not find a '{label}' column. Tried: {candidates}. Available: {list(df.columns)}")


def normalize_ifname(name: str) -> str:
    if not isinstance(name, str):
        return ""
    s = name.strip()
    s = re.sub(r"^gigabitethernet", "gi", s, flags=re.IGNORECASE)
    s = re.sub(r"^tengigabitethernet|^te?ngigabitethernet|^ten(?:gig)?abitethernet", "te", s, flags=re.IGNORECASE)
    s = re.sub(r"^fastethernet", "fa", s, flags=re.IGNORECASE)
    s = re.sub(r"^port-channel", "po", s, flags=re.IGNORECASE)
    s = s.replace(" ", "")
    return s


def parse_lldp_neighbors_detail(output: str) -> List[Tuple[str, str]]:
    """
    Parse "show lldp neighbors detail" output.
    Returns list of tuples: (local_interface, neighbor_system_name)
    Looks for sections containing:
        Local Intf: Gi1/0/1
        System Name: SEPXXXXXXXXXXXX
    """
    if not output:
        return []
    # Split into stanzas using "Local Intf:" as an anchor
    stanzas = re.split(r"\n(?=\s*Local Intf\s*:)", output)
    results: List[Tuple[str, str]] = []
    for stanza in stanzas:
        m_intf = re.search(r"Local\s+Intf\s*:\s*(.+)", stanza, flags=re.IGNORECASE)
        m_sys  = re.search(r"System\s+Name\s*:\s*(.+)", stanza, flags=re.IGNORECASE)
        if m_intf and m_sys:
            local_intf = m_intf.group(1).strip()
            sys_name   = m_sys.group(1).strip()
            results.append((local_intf, sys_name))
    return results


def get_interface_description(conn: ConnectHandler, interface: str) -> str:
    """Try a few approaches to retrieve the interface description for a port."""
    # Per-interface queries first (fast, precise)
    for cmd in (
        f"show interfaces {interface} | include Description",
        f"show interface {interface} | include Description",
    ):
        out = conn.send_command(cmd)
        if out and "Description" in out:
            m = re.search(r"Description\s*:\s*(.*)$", out, flags=re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()

    # Fallback: table scan
    table = conn.send_command("show interfaces description")
    if table:
        intf_norm = normalize_ifname(interface)
        for line in table.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            cand = normalize_ifname(parts[0])
            if cand.lower() == intf_norm.lower():
                # description is usually everything after statuses
                m = re.match(r"^(\S+)\s+\S+\s+\S+\s+(.*)$", line.strip())
                if m:
                    return m.group(2).strip()
                # fallback last-token
                return parts[-1] if len(parts) >= 4 else ""
    return ""


def description_has_required_prefix(desc: str) -> bool:
    if desc is None:
        return False
    if CASE_SENSITIVE_PREFIX:
        return desc.startswith(DESCRIPTION_PREFIX)
    return desc.upper().startswith(DESCRIPTION_PREFIX.upper())


def process_switch(ip: str) -> List[dict]:
    rows: List[dict] = []
    device = {
        "device_type": DEVICE_TYPE,
        "host": ip,
        "username": USERNAME,
        "password": PASSWORD,
        "secret": ENABLE_SECRET or "",
        "timeout": CONN_TIMEOUT_SECS,
        "conn_timeout": CONN_TIMEOUT_SECS,
        "fast_cli": True,
    }

    try:
        conn = ConnectHandler(**device)
        if ENABLE_SECRET:
            try:
                conn.enable()
            except Exception:
                pass
        lldp_out = conn.send_command(
            "show lldp neighbors detail", expect_string=r"[#>]", read_timeout=CONN_TIMEOUT_SECS
        )
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[WARN] {ip}: SSH problem: {e}")
        return rows
    except Exception as e:
        print(f"[WARN] {ip}: Unexpected SSH error: {e}")
        return rows

    pairs = parse_lldp_neighbors_detail(lldp_out)
    if not pairs:
        try:
            conn.disconnect()
        except Exception:
            pass
        return rows

    for local_intf, sys_name in pairs:
        if not sys_name:
            continue
        if not re.match(rf"^\s*{re.escape(SEP_PREFIX)}", sys_name, flags=re.IGNORECASE):
            continue
        desc = get_interface_description(conn, local_intf)
        if not description_has_required_prefix(desc):
            rows.append({
                "switch_ip": ip,
                "interface": local_intf,
                "neighbor_name": sys_name,
                "description": desc.strip() if desc else "",
            })

    try:
        conn.disconnect()
    except Exception:
        pass

    return rows


def main():
    if not os.path.exists(IP_LIST_PATH):
        print(f"ERROR: IP list file not found: {IP_LIST_PATH}")
        sys.exit(1)

    try:
        df_ips = read_table(IP_LIST_PATH)
    except Exception as e:
        print(f"ERROR: Could not read IP list: {e}")
        sys.exit(1)

    # Find the IP column
    try:
        ip_col = must_get_col(df_ips, IP_COL_CANDIDATES, "IP address")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    ips = [str(x).strip() for x in df_ips[ip_col].dropna().tolist() if str(x).strip()]
    if not ips:
        print("No IPs found in the input file.")
        sys.exit(0)

    all_rows: List[dict] = []

    for idx, ip in enumerate(ips, start=1):
        print(f"[{idx}/{len(ips)}] Processing {ip} ...")
        rows = process_switch(ip)
        all_rows.extend(rows)
        if DELAY_BETWEEN_SWITCHES:
            time.sleep(DELAY_BETWEEN_SWITCHES)

    out_df = (
        pd.DataFrame(all_rows, columns=["switch_ip", "interface", "neighbor_name", "description"])
        if all_rows
        else pd.DataFrame(columns=["switch_ip", "interface", "neighbor_name", "description"])
    )

    try:
        out_df.to_csv(OUTPUT_CSV, index=False)
    except Exception as e:
        print(f"ERROR: Could not write output CSV '{OUTPUT_CSV}': {e}")
        sys.exit(1)

    print("\n=== Summary ===")
    print(f"Total switches scanned: {len(ips)}")
    print(f"Rows needing description prefix '{DESCRIPTION_PREFIX}': {len(out_df)}")
    print(f"CSV written: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
