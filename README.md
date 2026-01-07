# Automation-Framework

Operational network work does not fail because the commands are hard—it fails because the *volume* is high and the *inputs* are inconsistent: spreadsheets, stale inventories, hand-audited switchports, and device state that drifts between sites. In enterprise environments, that drift drives avoidable outages, slows incident response, and turns routine change into a risky, manual process.

This repository contains a set of Python utilities (primarily in `scripts/`) that automate common network operations against Cisco IOS/IOS-XE devices using SSH, and (optionally) synchronize discovered state into NetBox.

## What This Solves (Enterprise Pain)

- **Inventory drift**: “What do we actually have deployed?” is often answered with stale spreadsheets or partial CMDB data.
- **Time-consuming audits**: Port descriptions, endpoints (phones/cameras/APs), and VLAN placement are frequently checked by hand.
- **High-risk bulk changes**: STP mode changes, VLAN enforcement, and account updates are error-prone when done device-by-device.
- **Inconsistent documentation**: Even when standards exist (e.g., description prefixes), enforcement at scale is difficult.

## High-Level Capabilities

The scripts in this repo are task-oriented and typically follow this pattern:

1. Load a device list (CSV/Excel) from `inventory/` or `database/`
2. Connect to each device over SSH (Netmiko)
3. Collect state (`show …`) and/or apply changes (`send_config_set`)
4. Write results to `docs/` and logs to `logs/`

## Included Scripts (Quick Guide)

- `scripts/netboxparse.py`: Discovers switch VLANs, switchport data, and L3 interface addressing and pushes/updates Devices, Interfaces, VLANs, and IPs in NetBox (supports `DRY_RUN`).
- `scripts/Discovery+.py`: Finds target MAC addresses on switches and (optionally) moves the associated access interface to a target VLAN with safety checks and a report CSV.
- `scripts/Discovery.py`: Earlier/less-safe MAC-to-VLAN change workflow (moves matching ports to VLAN 254).
- `scripts/writeVLAN+.py`: Collects VLANs from each switch (`show vlan brief`) and writes them back into the source Excel workbook as a `VLANs` column.
- `scripts/rstp+.py`: Pushes Rapid-PVST configuration and optional per-VLAN STP priorities based on an Excel input; writes a run summary CSV.
- `scripts/rstp_rollback.py`: Rolls STP configuration back to PVST and restores default priority settings.
- `scripts/PortDocument.py`: Applies interface descriptions in bulk (Excel-driven) with logging and basic response checks.
- `scripts/no_IPCam.py`: Removes interface descriptions for specified ports (Excel-driven).
- `scripts/Axis_Visibility.py`: Audits Axis camera visibility via LLDP and checks whether the connected port description includes `IPCam`; outputs an Excel report.
- `scripts/Phone_Audit.py`: Audits LLDP neighbors for Cisco phones (`SEP…`) and reports interfaces missing a required description prefix (default `MTE`).
- `scripts/Megaman.py`: Uses CDP neighbor discovery to identify “undocumented” switches not present in the provided inventory sheet.
- `scripts/MegamanAP.py`: Inventories access point models from CDP neighbor details (based on naming conventions) and outputs a model count report.
- `scripts/ConfigPush.py`: Runs a simple command set at scale (default is writing config) across a device list.
- `scripts/pw_update.py`: GUI tool to bulk add/update/delete a local user on IOS/ASA devices and save configuration.
- `scripts/CER Project.py`: Spreadsheet quality checks for CER-related fields (flags mismatches/blank values and writes a results sheet).
- `scripts/PortDesc_Change.py`: Example one-off description refactor driven by `show int desc` parsing (intended as a starting point).

## Technologies Used

- **Python 3**
- **Netmiko** (SSH connectivity and command/config execution)
- **Paramiko** (SSH transport used by Netmiko; directly referenced in `pw_update.py`)
- **pandas + openpyxl** (Excel/CSV inputs and report outputs)
- **python-dotenv** (loads credentials and environment settings from `.env`)
- **pynetbox** (NetBox API client for discovery-to-source-of-truth workflows)
- **concurrent.futures / threading** (controlled parallelism for scale)
- **tkinter** (GUI in `pw_update.py`)

## Repository Layout

- `scripts/`: Task-focused automation scripts
- `inventory/`: Inventory inputs (e.g., `inventory/devices.csv` used by `netboxparse.py`)
- `database/`: Excel workbooks used as job inputs (typically not committed)
- `docs/`: Reports and exported results (typically not committed)
- `logs/`: Execution logs (typically not committed)

## Safe Usage (Recommended Workflow)

These scripts can make production-impacting changes. Treat them as change tools, not just reporting utilities.

1. **Clone and isolate dependencies**
   - Create a virtual environment and install required packages (there is no pinned `requirements.txt` in this repo).
2. **Configure credentials and defaults**
   - Copy `.env.example` to `.env` and populate values.
   - Prefer using a dedicated automation account with appropriate privilege and auditing.
3. **Start in read-only or dry-run mode**
   - Use scripts that only collect state first.
   - Where supported (e.g., `scripts/netboxparse.py`), enable `DRY_RUN` before writing to systems of record.
4. **Limit blast radius**
   - Test against a small subset of devices.
   - Reduce thread counts until you understand device/control-plane impact.
5. **Run during a maintenance window for change scripts**
   - Any script that writes config and saves (`wr` / `write memory`) should follow your change-management process.

## Configuration

Environment variables are loaded from `.env` at the repo root. See `.env.example` for the current set.

Common values:

- `username`, `password`, `secret`: Device credentials (used by most scripts)
- `NETBOX_URL`, `NETBOX_TOKEN`: Required for NetBox synchronization (`scripts/netboxparse.py`)
- `NETMIKO_DEVICE_TYPE`: Netmiko platform driver (default: `cisco_ios`)
- `DISCOVERY_WORKERS`, `NETBOX_WORKERS`: Parallelism tuning for discovery and NetBox writes
- `DRY_RUN`: Enables non-destructive NetBox sync runs where supported

## High-Level Usage Examples

Most scripts are self-contained and use default file paths under `database/`, `inventory/`, `docs/`, and `logs/`.

- NetBox discovery + sync:
  - `python scripts/netboxparse.py`
- VLAN move workflow with safety checks and reporting:
  - `python scripts/Discovery+.py`
- Collect VLAN lists and write back to Excel:
  - `python scripts/writeVLAN+.py`
- RSTP rollout:
  - `python scripts/rstp+.py`
- Undocumented switch detection (inventory file passed on CLI):
  - `python scripts/Megaman.py <devices.xlsx> [threads]`
- AP model inventory (inventory file passed on CLI):
  - `python scripts/MegamanAP.py <devices.xlsx> [thread_count]`
- Bulk user management (GUI):
  - `python scripts/pw_update.py`

## Assumptions and Limitations

- **Platform assumptions**: Most scripts assume Cisco IOS/IOS-XE CLI output (`show vlan brief`, `show interfaces switchport`, `show lldp neighbors detail`, `show cdp neighbors detail`).
- **Input conventions**: Several scripts expect specific Excel column names (commonly `IP Address`, plus task-specific fields like `Port`, `Description`, `MAC Address`, `VLANs`, `Root`).
- **Naming conventions**:
  - `scripts/netboxparse.py` infers NetBox Site using a facility code token in the hostname and the NetBox Site `facility` field.
  - `scripts/Phone_Audit.py` uses LLDP system-name prefix matching (default `SEP`) and enforces a description prefix (default `MTE`).
  - `scripts/MegamanAP.py` uses a naming convention to identify AP neighbors (device IDs containing `-AP`).
- **Change safety varies by script**: Some scripts default to making changes and saving config; others are audit-only. Review each script and test on a small subset before broad execution.
- **No packaging/CLI framework**: Scripts are not provided as a unified CLI, and dependencies are not pinned.


## Disclaimer

These tools execute commands on network devices and can change production state. Review the scripts, validate in a lab, and use enterprise change controls before running broadly.

## Context

This project reflects real-world work done in a production-style environment. The goal was to reduce manual configuration errors, standardize deployments, and support scalable automation.
