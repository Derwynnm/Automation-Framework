"""
Fleet-wide audit of IP access-lists and SNMP configuration.

Connects to every switch in inventory/devices.csv (threaded), pulls the
running-config sections for ACLs and SNMP, and reports:
  - lines common to every reachable switch (the baseline)
  - lines that deviate, and exactly which device(s) they're on

SNMP community strings and v3 auth/priv secrets are redacted before they are
compared or written out. Redaction covers the common patterns only (see
redact_snmp_line) -- treat the output workbook as sensitive-adjacent.
"""
import argparse
import csv
import logging
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
from netmiko import ConnectHandler
from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException

from dotenv import load_dotenv
import os

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# ----- Calling .env
username = os.getenv("NET_USERNAME")
password = os.getenv("NET_PASSWORD")
secret = os.getenv("NET_SECRET")

# ============================ USER CONFIG ===================================
DEVICE_LIST = Path(__file__).resolve().parents[1] / "inventory" / "devices.csv"
DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "acl_snmp_audit.log"

THREADS = 30                # max concurrent SSH sessions (read-only commands)
CONN_TIMEOUT_SECS = 20
RETRIES = 2                 # attempts per device on timeout
BACKOFF_SEC = 2

ACL_COMMAND = "show running-config | section ^ip access-list"
SNMP_COMMAND = "show running-config | section ^snmp-server"
# ========================== END USER CONFIG =================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("paramiko").setLevel(logging.WARNING)

ACL_HEADER_RE = re.compile(r"^ip access-list (?:standard|extended)\s+(\S+)", re.IGNORECASE)

# Redact secret tokens out of snmp-server lines before comparison/reporting.
SNMP_REDACT_PATTERNS = [
    (re.compile(r"^(snmp-server community\s+)(\S+)(.*)$", re.IGNORECASE), r"\1<REDACTED>\3"),
    (re.compile(r"(auth\s+(?:md5|sha)\s+)(\S+)", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(priv\s+(?:des|3des|aes\s*\d*)\s+)(\S+)", re.IGNORECASE), r"\1<REDACTED>"),
]


def redact_snmp_line(line: str) -> str:
    for pattern, repl in SNMP_REDACT_PATTERNS:
        line = pattern.sub(repl, line)
    return line


def normalize_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def parse_acl_section(output: str) -> List[Tuple[str, str]]:
    """Return (acl_name, normalized_ace_line) pairs from an ACL running-config section."""
    pairs: List[Tuple[str, str]] = []
    current_acl: Optional[str] = None
    for raw_line in (output or "").splitlines():
        if not raw_line.strip():
            continue
        m = ACL_HEADER_RE.match(raw_line.strip())
        if m:
            current_acl = m.group(1)
            continue
        if current_acl is not None:
            pairs.append((current_acl, normalize_line(raw_line)))
    return pairs


def parse_snmp_section(output: str) -> List[str]:
    """Return normalized, redacted snmp-server lines."""
    lines: List[str] = []
    for raw_line in (output or "").splitlines():
        if not raw_line.strip():
            continue
        lines.append(redact_snmp_line(normalize_line(raw_line)))
    return lines


def load_devices(path: Path) -> List[Dict[str, str]]:
    devices: List[Dict[str, str]] = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            ip = (row.get("IP Address") or "").strip()
            name = (row.get("Device Name") or "").strip()
            if ip:
                devices.append({"ip": ip, "name": name})
    return devices


def audit_device(ip: str, name: str) -> dict:
    """SSH to *ip*, pull ACL + SNMP sections. Returns a result dict; never raises."""
    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "secret": secret if secret else None,
        "conn_timeout": CONN_TIMEOUT_SECS,
        "timeout": CONN_TIMEOUT_SECS,
    }

    last_err = ""
    for attempt in range(RETRIES):
        try:
            conn = ConnectHandler(**device)
            break
        except NetmikoAuthenticationException as e:
            last_err = f"AUTH_FAIL: {e}"
            logging.error("%s %s", ip, last_err)
            return {"ip": ip, "name": name, "status": "error", "error": last_err,
                     "acl_lines": [], "snmp_lines": []}
        except NetmikoTimeoutException as e:
            last_err = f"TIMEOUT: {e}"
            wait = BACKOFF_SEC * 2 ** attempt
            logging.warning("%s timeout (attempt %s) - retry in %ss", ip, attempt + 1, wait)
            time.sleep(wait)
        except Exception as e:
            last_err = f"CONN_ERR: {e}"
            logging.error("%s %s", ip, last_err)
            return {"ip": ip, "name": name, "status": "error", "error": last_err,
                     "acl_lines": [], "snmp_lines": []}
    else:
        return {"ip": ip, "name": name, "status": "error", "error": last_err or "CONN_FAIL",
                 "acl_lines": [], "snmp_lines": []}

    try:
        if secret and not conn.check_enable_mode():
            conn.enable()
        acl_out = conn.send_command(ACL_COMMAND, read_timeout=CONN_TIMEOUT_SECS)
        snmp_out = conn.send_command(SNMP_COMMAND, read_timeout=CONN_TIMEOUT_SECS)
        acl_lines = parse_acl_section(acl_out)
        snmp_lines = parse_snmp_section(snmp_out)
        logging.info("%s OK (%d ACL lines, %d SNMP lines)", ip, len(acl_lines), len(snmp_lines))
        return {"ip": ip, "name": name, "status": "ok", "error": None,
                 "acl_lines": acl_lines, "snmp_lines": snmp_lines}
    except Exception as e:
        err = f"CMD_ERR: {e}"
        logging.error("%s %s", ip, err)
        return {"ip": ip, "name": name, "status": "error", "error": err,
                 "acl_lines": [], "snmp_lines": []}
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def build_baseline_and_deviations(
    ok_results: List[dict], line_key: str
) -> Tuple[List[Tuple[str, str]], List[dict]]:
    """
    line_key: "acl_lines" or "snmp_lines"
    Returns (baseline_rows, deviation_rows).
    baseline_rows: list of (section, line)
    deviation_rows: list of dicts with Section, Line, Type, Device_IP, Device_Name,
                    Present_Count, Total_Count
    """
    total = len(ok_results)
    device_by_ip = {r["ip"]: r["name"] for r in ok_results}

    key_to_devices: Dict[Tuple[str, str], set] = defaultdict(set)
    for r in ok_results:
        if line_key == "acl_lines":
            entries = r["acl_lines"]
        else:
            entries = [("snmp-server", line) for line in r["snmp_lines"]]
        for section, line in entries:
            key_to_devices[(section, line)].add(r["ip"])

    baseline_rows: List[Tuple[str, str]] = []
    deviation_rows: List[dict] = []

    for (section, line), present_ips in key_to_devices.items():
        present_count = len(present_ips)
        if total > 0 and present_count == total:
            baseline_rows.append((section, line))
            continue

        if present_count <= total / 2:
            dev_type = "Extra"
            minority_ips = present_ips
        else:
            dev_type = "Missing"
            minority_ips = set(device_by_ip.keys()) - present_ips

        for ip in sorted(minority_ips):
            deviation_rows.append({
                "Section": section,
                "Line": line,
                "Type": dev_type,
                "Device_IP": ip,
                "Device_Name": device_by_ip.get(ip, ""),
                "Present_Count": present_count,
                "Total_Count": total,
            })

    baseline_rows.sort()
    deviation_rows.sort(key=lambda d: (d["Section"], d["Line"], d["Device_IP"]))
    return baseline_rows, deviation_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit ACLs and SNMP config across all switches.")
    parser.add_argument("--limit", type=int, default=None, help="Only audit the first N devices from the inventory.")
    parser.add_argument("--ip", action="append", default=None, help="Audit only this IP (repeatable).")
    args = parser.parse_args()

    if not DEVICE_LIST.exists():
        raise SystemExit(f"ERROR: device list not found: {DEVICE_LIST}")

    devices = load_devices(DEVICE_LIST)
    if args.ip:
        wanted = set(args.ip)
        devices = [d for d in devices if d["ip"] in wanted]
    elif args.limit:
        devices = devices[: args.limit]

    if not devices:
        raise SystemExit("No devices selected to audit.")

    print(f"Auditing {len(devices)} device(s)...")

    results: List[dict] = []
    max_workers = min(THREADS, len(devices)) or 1
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(audit_device, d["ip"], d["name"]): d for d in devices}
        for i, fut in enumerate(as_completed(futures), start=1):
            d = futures[fut]
            res = fut.result()
            results.append(res)
            print(f"[{i}/{len(devices)}] {res['ip']} ({d['name']}) -> {res['status']}")

    ok_results = [r for r in results if r["status"] == "ok"]
    error_results = [r for r in results if r["status"] == "error"]

    acl_baseline, acl_deviations = build_baseline_and_deviations(ok_results, "acl_lines")
    snmp_baseline, snmp_deviations = build_baseline_and_deviations(ok_results, "snmp_lines")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DOCS_DIR / f"acl_snmp_audit_{ts}.xlsx"

    summary_df = pd.DataFrame([{
        "Run Timestamp": ts,
        "Devices In Scope": len(devices),
        "Devices Audited OK": len(ok_results),
        "Devices Errored": len(error_results),
        "ACL Baseline Lines": len(acl_baseline),
        "ACL Deviation Rows": len(acl_deviations),
        "SNMP Baseline Lines": len(snmp_baseline),
        "SNMP Deviation Rows": len(snmp_deviations),
    }])

    acl_baseline_df = pd.DataFrame(acl_baseline, columns=["Section", "Line"])
    acl_deviations_df = pd.DataFrame(
        acl_deviations,
        columns=["Section", "Line", "Type", "Device_IP", "Device_Name", "Present_Count", "Total_Count"],
    )
    snmp_baseline_df = pd.DataFrame([line for _, line in snmp_baseline], columns=["Line"])
    snmp_deviations_df = pd.DataFrame(
        snmp_deviations,
        columns=["Section", "Line", "Type", "Device_IP", "Device_Name", "Present_Count", "Total_Count"],
    )
    errors_df = pd.DataFrame(
        [{"Device_IP": r["ip"], "Device_Name": r["name"], "Error": r["error"]} for r in error_results],
        columns=["Device_IP", "Device_Name", "Error"],
    )

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        acl_baseline_df.to_excel(writer, sheet_name="ACL_Baseline", index=False)
        acl_deviations_df.to_excel(writer, sheet_name="ACL_Deviations", index=False)
        snmp_baseline_df.to_excel(writer, sheet_name="SNMP_Baseline", index=False)
        snmp_deviations_df.to_excel(writer, sheet_name="SNMP_Deviations", index=False)
        errors_df.to_excel(writer, sheet_name="Errors", index=False)

    print("\n=== Summary ===")
    print(f"Devices audited OK: {len(ok_results)} / {len(devices)}")
    print(f"ACL baseline lines: {len(acl_baseline)}  |  ACL deviation rows: {len(acl_deviations)}")
    print(f"SNMP baseline lines: {len(snmp_baseline)}  |  SNMP deviation rows: {len(snmp_deviations)}")
    print(f"Report written: {out_path}")


if __name__ == "__main__":
    main()
