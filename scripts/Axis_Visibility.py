import pandas as pd
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from dotenv import load_dotenv
from pathlib import Path
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("username")
password = os.getenv("password")
secret =   os.getenv("secret")

# -----



# ── USER VARIABLES ──────────────────────────────────────────────────────────────
INPUT_FILE  = r"C:\Users\dmckella\Desktop\WriteMem.xlsx"
OUTPUT_FILE = r"C:\Users\dmckella\Desktop\Automation\LLDP_Audit_Result.xlsx"
MAX_WORKERS = 100
# ────────────────────────────────────────────────────────────────────────────────

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)

# ── Load IPs ───────────────────────────────────────────────────────────────────
try:
    df = pd.read_excel(INPUT_FILE)
except FileNotFoundError:
    raise SystemExit(f"❌ INPUT_FILE not found → {INPUT_FILE}")

col = "IP Address" if "IP Address" in df.columns else df.columns[0]
if col != "IP Address":
    logging.warning("'IP Address' column not found. Using first column instead.")

ip_list = df[col].dropna().astype(str).str.strip().tolist()
if not ip_list:
    raise SystemExit("❌ No IPs found in the input file. Check the sheet content.")
logging.info(f"Loaded {len(ip_list)} IPs for auditing.")

# ── Interface short‑form mapper ────────────────────────────────────────────────
IFNAME_MAP = {
    "GigabitEthernet": "Gi",
    "TenGigabitEthernet": "Te",
    "TwentyFiveGigE": "Twe",
    "FortyGigabitEthernet": "Fo",
    "HundredGigabitEthernet": "Hu",
    "FastEthernet": "Fa",
    "Ethernet": "Eth",
}

def shorten(ifname: str) -> str:
    for long, short in IFNAME_MAP.items():
        if ifname.startswith(long):
            return ifname.replace(long, short, 1)
    return ifname

# ── Regex helpers ──────────────────────────────────────────────────────────────
AXIS_FIELD_RE = re.compile(
    r"^(System Name|Port Description|System Description|Port id):\s+(axis[^\s]*)",
    re.IGNORECASE | re.MULTILINE,
)
LOCAL_INTF_RE = re.compile(r"^(?:Interface|Local Port|Local Intf):\s+(\S+)", re.MULTILINE)
# Matches only lines whose description column equals 'IPCam' (case-insensitive)
ORPHAN_IPCAM_RE = re.compile(r"^(\S+)\s+\S+\s+\S+\s+IPCam\s*$", re.IGNORECASE | re.MULTILINE)

# ── Worker function ────────────────────────────────────────────────────────────

def audit_switch(ip: str):
    device = {
        "device_type": "cisco_ios",
        "ip": ip,
        "username": username,
        "password": password,
        "secret": secret,
        "conn_timeout": 30,
    }

    rows = []

    try:
        conn = ConnectHandler(**device)
        conn.enable()
        logging.info(f"Connected → {ip}")

        lldp_detail = conn.send_command("show lldp neighbors detail", delay_factor=2)
        int_desc    = conn.send_command("show interface description")
        conn.disconnect()
    except Exception as exc:
        logging.error(f"{ip}: Connection failed → {exc}")
        rows.append({"Switch IP": ip, "Port ID": "—", "Device ID": "—", "Status": f"Connection failed: {exc}"})
        return rows

    # --- Parse LLDP blocks for Axis devices ---
    blocks = re.split(r"-+", lldp_detail)
    axis_ports = set()

    for block in blocks:
        axis_match = AXIS_FIELD_RE.search(block)
        if not axis_match:
            continue
        dev_id = axis_match.group(2).strip()

        local_match = LOCAL_INTF_RE.search(block)
        if not local_match:
            continue
        local_long = local_match.group(1).strip()
        local_short = shorten(local_long)
        axis_ports.update({local_long, local_short})

        # Check description for Axis‑linked port
        desc_match = re.search(
            rf"^(?:{re.escape(local_long)}|{re.escape(local_short)})\s+\S+\s+\S+\s+(.*)$",
            int_desc, re.MULTILINE | re.IGNORECASE
        )
        if desc_match:
            desc_txt = desc_match.group(1).strip()
            status = "✅ Has IPCam" if "ipcam" in desc_txt.lower() else "❌ Missing IPCam"
        else:
            status = "❓ Interface not found in description table"

        rows.append({
            "Switch IP": ip,
            "Port ID": local_long,
            "Device ID": dev_id,
            "Status": status,
        })

    # --- Scan for orphan IPCam descriptions ---
    orphan_hits = 0
    for if_name in ORPHAN_IPCAM_RE.findall(int_desc):
        if if_name not in axis_ports:
            orphan_hits += 1
            rows.append({
                "Switch IP": ip,
                "Port ID": if_name,
                "Device ID": "—",
                "Status": "🟡 IPCam desc (no Axis LLDP)",
            })

    logging.info(f"{ip}: Axis neighbours → {len(axis_ports)//2} | Orphan IPCam ports → {orphan_hits}")

    if not rows:
        rows.append({"Switch IP": ip, "Port ID": "—", "Device ID": "—", "Status": "No data collected"})

    return rows

# ── Thread pool orchestration ─────────────────────────────────────────────────
results = []
login_success = login_fail = 0

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
    futures = {pool.submit(audit_switch, ip): ip for ip in ip_list}
    for fut in as_completed(futures):
        try:
            res = fut.result()
        except Exception as e:
            logging.error(f"Unhandled exception from {futures[fut]} → {e}")
            login_fail += 1
            continue

        if not res:
            login_fail += 1
            continue

        results.extend(res)
        if "Connection failed" in res[0]["Status"]:
            login_fail += 1
        else:
            login_success += 1

# ── Export results ────────────────────────────────────────────────────────────
output_df = pd.DataFrame(results)
output_df.to_excel(OUTPUT_FILE, index=False)
logging.info(f"✅ Audit complete → {OUTPUT_FILE}")
logging.info(f"Summary: {len(ip_list)} attempted | {login_success} connected | {login_fail} failed")
