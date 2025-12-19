import re
import csv
import logging
import pandas as pd
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from dotenv import load_dotenv
from pathlib import Path
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret = os.getenv("secret")

# ---------------- Config ----------------
EXCEL_PATH = Path(__file__).resolve().parents[1] / "database" / "MACTest.xlsx"
TARGET_VLAN = 1          # global target VLAN; can be per-row if you add a column
DRY_RUN = True
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "deploy_vlan_changes.log"
REPORT_CSV = Path(__file__).resolve().parents[1] / "docs" / "deploy_vlan_report.csv"

# Feature flags / behavior switches
ALLOW_MULTI_MAC = False              # allow phone+PC edges (default: False)
CONFIRM_MAC_BEFORE_CHANGE = True     # verify MAC still on same iface before change
FORCE_MODE_ACCESS = True             # enforce 'switchport mode access' when changing VLAN
FAST_CLI = False                     # Netmiko fast_cli optimization (test before enabling)
THREADS = 10                          # Max concurrent switch sessions

logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

# -------------- Helpers -----------------
def norm_mac(mac: str) -> str:
    """Normalize to Cisco dotted: aaaa.bbbb.cccc; return '' if invalid."""
    s = re.sub(r'[^0-9a-fA-F]', '', mac or '')
    if len(s) != 12:
        return ''
    s = s.lower()
    return f"{s[0:4]}.{s[4:8]}.{s[8:12]}"

# Dynamic entries only: VLAN  MAC                Type     Port
MAC_DYNAMIC = re.compile(
    r'^\s*(?:\d+|All)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+dynamic\s+(\S+)',
    re.IGNORECASE | re.MULTILINE
)

def parse_dynamic_mac_table(output: str):
    """Yield (mac, iface) pairs for dynamic entries."""
    for mac, iface in MAC_DYNAMIC.findall(output):
        yield mac.lower(), iface

DEF_NON_EDGE_PREFIXES = (
    'po', 'port-channel', 'vlan', 'loopback', 'twe', 'te', 'fo', 'hu'
)

def is_operational_access(conn, iface: str) -> bool:
    out = conn.send_command(f"show interface {iface} switchport")
    if 'Switchport: Enabled' not in out:
        return False
    if 'Operational Mode: trunk' in out or 'Administrative Mode: trunk' in out:
        return False
    # Positive indicators vary by platform; these cover common IOS-XE strings
    return ('Operational Mode: static access' in out) or ('Access Mode VLAN' in out)

def current_access_vlan(conn, iface: str) -> int | None:
    out = conn.send_command(f"show interface {iface} switchport")
    m = re.search(r"Access Mode VLAN:\s*[^\(\n]*\(?([0-9]+)\)?", out)
    return int(m.group(1)) if m else None

def count_dynamic_macs_on_iface(conn, iface: str) -> int:
    out = conn.send_command(f"show mac address-table interface {iface} dynamic")
    return sum(1 for _ in re.finditer(
        r'^[ \t]*\d+[ \t]+[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}[ \t]+DYNAMIC',
        out, re.IGNORECASE | re.MULTILINE
    ))

def ensure_vlan(conn, vlan: int):
    cmds = [f"vlan {vlan}", "exit"]
    if not DRY_RUN:
        conn.send_config_set(cmds, cmd_verify=False)

def set_access_vlan(conn, iface: str, vlan: int):
    cmds = [f"interface {iface}"]
    if FORCE_MODE_ACCESS:
        cmds.append("switchport mode access")
    cmds.extend([f"switchport access vlan {vlan}", "exit"])
    if not DRY_RUN:
        conn.send_config_set(cmds, cmd_verify=False)

def safe_to_change(conn, iface: str) -> bool:
    il = iface.lower()
    if il in ('cpu', 'router', 'drop') or il.startswith(DEF_NON_EDGE_PREFIXES):
        return False
    try:
        if not is_operational_access(conn, iface):
            return False
        if not ALLOW_MULTI_MAC and count_dynamic_macs_on_iface(conn, iface) > 1:
            return False
    except Exception:
        return False
    return True

# -------------- Load Excel --------------
df = pd.read_excel(EXCEL_PATH, dtype=str)

mac_series = df.get('MAC Address', pd.Series(dtype=str)).dropna()
switch_series = df.get('IP Address', pd.Series(dtype=str)).dropna()

# Normalize and dedup
target_macs = {norm_mac(m) for m in mac_series if norm_mac(m)}
switch_ips = sorted({ip.strip() for ip in switch_series if ip and ip.strip()})

if not target_macs:
    raise SystemExit('No valid MAC addresses loaded from Excel.')
if not switch_ips:
    raise SystemExit('No switch IPs loaded from Excel.')

# -------------- Concurrency (per-switch threads) --------------
mac_lock = Lock()

def process_switch(ip: str):
    """Connect to a switch, claim target MACs found there, make safe changes, return report rows."""
    local_rows = []
    print(f"\n[{ip}] connecting…")
    try:
        # Quick check before opening an SSH session
        with mac_lock:
            if not target_macs:
                print(f"[{ip}] nothing left to do; skipping connect")
                return local_rows

        with ConnectHandler(device_type='cisco_ios', ip=ip,
                            username=username, password=password, secret=secret,
                            fast_cli=FAST_CLI) as conn:
            conn.enable()

            # Pull the dynamic MAC table once
            tbl = conn.send_command('show mac address-table dynamic')
            dynamic_map = {mac: iface for mac, iface in parse_dynamic_mac_table(tbl)}

            # Determine hits without claiming yet (another switch may be the true edge)
            with mac_lock:
                hits = target_macs.intersection(dynamic_map.keys())

            if not hits:
                print(f"[{ip}] no targets found on this switch")
                return local_rows

            # Ensure VLAN exists once per switch
            ensure_vlan(conn, TARGET_VLAN)

            visited_ifaces = set()
            for mac in sorted(hits):
                iface = dynamic_map[mac]
                il = iface.lower()
                if il in visited_ifaces:
                    continue

                if not safe_to_change(conn, iface):
                    local_rows.append((ip, iface, mac, '', '', 'skip', 'not safe'))
                    continue

                # Claim now that we know it's safe (edge interface)
                with mac_lock:
                    if mac not in target_macs:
                        visited_ifaces.add(il)
                        continue
                    target_macs.remove(mac)

                old_vlan = current_access_vlan(conn, iface)
                if old_vlan == TARGET_VLAN:
                    local_rows.append((ip, iface, mac, old_vlan, TARGET_VLAN, 'noop', 'already correct'))
                    visited_ifaces.add(il)
                    continue

                print(f"[{ip}] → {mac} @ {iface}: VLAN {old_vlan} → {TARGET_VLAN}")
                logging.info(f"{ip} {iface} {mac}: {old_vlan} -> {TARGET_VLAN}")

                # Confirm MAC still on this interface (race-proofing)
                if CONFIRM_MAC_BEFORE_CHANGE:
                    cur = conn.send_command(f"show mac address-table address {mac}")
                    if iface not in cur:
                        local_rows.append((ip, iface, mac, old_vlan, '', 'skip', 'mac moved'))
                        visited_ifaces.add(il)
                        continue

                # DRY RUN: record planned action and skip push/verify
                if DRY_RUN:
                    local_rows.append((ip, iface, mac, old_vlan, TARGET_VLAN, 'planned', 'dry-run'))
                    visited_ifaces.add(il)
                    continue

                # Apply change
                set_access_vlan(conn, iface, TARGET_VLAN)
                visited_ifaces.add(il)

                # Verify
                new_vlan = current_access_vlan(conn, iface)
                if new_vlan != TARGET_VLAN:
                    import time
                    time.sleep(1)
                    new_vlan = current_access_vlan(conn, iface)
                    if new_vlan != TARGET_VLAN:
                        sp_text = conn.send_command(f"show interface {iface} switchport")
                        for ln in sp_text.splitlines():
                            if "Access Mode VLAN:" in ln:
                                m2 = re.search(r"([0-9]+)", ln)
                                if m2:
                                    new_vlan = int(m2.group(1))
                                break
                ok = (new_vlan == TARGET_VLAN)
                local_rows.append((ip, iface, mac, old_vlan,
                                   new_vlan if new_vlan else '',
                                   'changed' if ok else 'verify-fail',
                                   '' if ok else 'post-check mismatch'))

            # Save if any changes occurred
            if not DRY_RUN and any(r[5] == 'changed' for r in local_rows):
                print(f"[{ip}] saving configuration…")
                conn.send_command('write memory')

    except Exception as e:
        logging.exception(f"Error on {ip}: {e}")
        print(f"ERROR on {ip}: {e}")
        local_rows.append((ip, '', '', '', '', 'error', str(e)))

    return local_rows

# -------------- Main (threaded) --------------
report_rows = [("switch_ip","interface","mac","old_vlan","new_vlan","action","notes")]

max_workers = min(THREADS, len(switch_ips)) or 1
with ThreadPoolExecutor(max_workers=max_workers) as pool:
    futures = [pool.submit(process_switch, ip) for ip in switch_ips]
    for fut in as_completed(futures):
        rows = fut.result()
        if rows:
            report_rows.extend(rows)

# -------------- Report output --------------
with open(REPORT_CSV, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerows(report_rows)

if target_macs:
    print('\nThe following MACs were NOT located on any switch:')
    for m in sorted(target_macs):
        print('  ', m)
else:
    print('\nAll target MACs handled.')

print(f"\nDone. Report: {REPORT_CSV}")
