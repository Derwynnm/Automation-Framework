"""dnac_netbox_sync.py — Sync switches from Cisco DNA Center / Catalyst Center to NetBox.

Data flow:
    DNAC API  →  Transform  →  NetBox helpers  →  NetBox

Usage:
    python scripts/dnac_netbox_sync.py [options]

Options:
    --dry-run           Override DRY_RUN to true (never writes to NetBox)
    --hostname NAME     Sync only this device hostname (for testing)
    --family FAMILY     DNAC device family filter (default: "Switches and Hubs")
    --skip-topology     Skip cable/topology sync stage
    --workers N         Override DISCOVERY_WORKERS
    --netbox-workers N  Override NETBOX_WORKERS
"""
import sys
import os
import re
import socket
import struct
import queue
import time
import threading
import argparse
import concurrent.futures
from pathlib import Path
import logging

# Must be before local imports so `from lib.xxx import` works regardless of working directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pynetbox.core.query import RequestError
from dotenv import load_dotenv

from lib.netbox_helpers import (
    init as init_nb_helpers,
    NetboxConfig,
    nb_client,
    get_site_tenant_id,
    get_obj_tenant_id,
    set_obj_tenant,
    resolve_site_role,
    resolve_role_mappings,
    is_vlan1_interface,
    dns_label,
    build_site_map,
    extract_facility_id_from_hostname,
    ensure_device_in_netbox,
    get_or_create_vlan_group,
    ensure_vlan_in_netbox,
    ensure_interface,
    is_dry_run,
)
from lib.dnac_client import DNACClient, DNACConfig


# =========================
# RUN SETTINGS
# Change DRY_RUN to False when you're ready to write to NetBox.
# True  → preview mode: logs everything, writes nothing.
# False → live mode:    syncs devices, VLANs, interfaces, IPs, and cables.
# =========================
DRY_RUN = False


# =========================
# ENV / CONFIG
# =========================
env_path = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(env_path)

NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")

DISCOVERY_WORKERS = int(os.getenv("DISCOVERY_WORKERS", "5"))
NETBOX_WORKERS = int(os.getenv("NETBOX_WORKERS", "1"))
# DRY_RUN can also be forced on via .env (DRY_RUN=true) or --dry-run CLI flag
DRY_RUN = DRY_RUN or os.getenv("DRY_RUN", "").strip().lower() in ("1", "true", "yes", "y")

INHERIT_SITE_TENANT = os.getenv("INHERIT_SITE_TENANT", "true").strip().lower() in ("1", "true", "yes", "y")
INHERIT_SITE_ROLE = os.getenv("INHERIT_SITE_ROLE", "true").strip().lower() in ("1", "true", "yes", "y")

FALLBACK_NETBOX_DEVICE_TYPE_SLUG = os.getenv("FALLBACK_NETBOX_DEVICE_TYPE_SLUG", "unknown-catalyst-switch")
FALLBACK_DEVICE_ROLE = os.getenv("FALLBACK_DEVICE_ROLE", "access-switch")

DNAC_BASE_URL = os.getenv("DNAC_BASE_URL", "").rstrip("/")
DNAC_USERNAME = os.getenv("DNAC_USERNAME") or os.getenv("username")
DNAC_PASSWORD = os.getenv("DNAC_PASSWORD") or os.getenv("password")
DNAC_VERIFY_SSL = os.getenv("DNAC_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes", "y")
DNAC_PAGE_SIZE = int(os.getenv("DNAC_PAGE_SIZE", "500"))

LOG_DIR = Path(__file__).resolve().parents[1] / "logs"

# Some sites have switches prefixed with a building number instead of (or in addition to)
# the facility letter code.  Map the numeric prefix → the facility code used in NetBox.
# e.g. "400-SomeSwitch" → facility_id "ADM" → site_map["ADM"]
_HOSTNAME_PREFIX_ALIASES: dict[str, str] = {
    "400": "ADM",
    "410": "ABC",
    "420": "ANN",
}

if not NETBOX_URL or not NETBOX_TOKEN:
    raise ValueError("NETBOX_URL and NETBOX_TOKEN must be set in .env")
if not DNAC_BASE_URL or not DNAC_USERNAME or not DNAC_PASSWORD:
    raise ValueError("DNAC_BASE_URL, DNAC_USERNAME, and DNAC_PASSWORD must be set in .env")


# =========================
# LOGGING
# =========================
def setup_logging(dry_run: bool):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_mode = "dryrun" if dry_run else "run"
    log_path = LOG_DIR / f"dnac_sync_{run_mode}_{timestamp}.log"

    logger = logging.getLogger("dnac_sync")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logger.info("Logging to %s (dry_run=%s)", log_path, dry_run)
    return logger


# =========================
# TRANSFORMATION LAYER
# =========================

def _mask_to_bits(mask: str) -> int:
    """Convert dotted-decimal subnet mask to prefix length."""
    try:
        return bin(struct.unpack("!I", socket.inet_aton(mask))[0]).count("1")
    except Exception:
        return 32


_INTERNAL_VLAN_RE = re.compile(r'^VLAN\d+$')


def _is_internal_vlan(vlan_number: int, vlan_name: str) -> bool:
    """
    Filter IOS-XE internal VLANs that DNAC exposes but `show vlan brief` naturally omits.
    Rules:
      - vlanNumber < 1  → invalid
      - 1002-1005       → FDDI/Token Ring defaults
      - vlanNumber > 1005 AND name matches ^VLAN\\d+$ → IOS-XE auto-generated internal VLAN
    This avoids dropping legitimate VLANs with real names like VLAN-STAFF.
    """
    if vlan_number < 1:
        return True
    if 1002 <= vlan_number <= 1005:
        return True
    if vlan_number > 1005 and _INTERNAL_VLAN_RE.match(vlan_name or ""):
        return True
    return False


def _transform_device(dnac_device: dict) -> dict:
    """Map a DNAC device record to a netbox_helpers-compatible dev dict."""
    serials_raw = (dnac_device.get("serialNumber") or "").strip()
    serials = [s.strip() for s in serials_raw.split(",") if s.strip()]
    primary_serial = serials[0] if serials else ""
    stack_serials_str = serials_raw if len(serials) > 1 else None

    return {
        "name": dnac_device.get("hostname", ""),
        "host": dnac_device.get("managementIpAddress", ""),
        "netbox_device_type": dnac_device.get("platformId", ""),
        "_dnac_type": dnac_device.get("type") or "",  # human-readable type, used as fallback for device type resolution
        "device_role": "distribution-switch" if (dnac_device.get("platformId") or "").upper().startswith(("C9300", "C9500")) else "access-switch",
        # DNAC-specific extras passed as kwargs to ensure_device_in_netbox
        "_serial": primary_serial,
        "_software_version": dnac_device.get("softwareVersion") or None,
        "_dnac_device_id": dnac_device.get("id") or None,
        "_stack_serials": stack_serials_str,
    }


def _transform_vlans(dnac_vlans: list) -> list:
    """Map DNAC VLAN records to {id, name} dicts, filtering internal VLANs."""
    result = []
    for v in dnac_vlans:
        num = v.get("vlanNumber")
        name = (v.get("vlanName") or "").strip()
        if num is None:
            continue
        try:
            num = int(num)
        except (TypeError, ValueError):
            continue
        if _is_internal_vlan(num, name):
            continue
        result.append({"id": num, "name": name or f"VLAN{num}"})
    return result


# Cisco IOS abbreviations that SSH (netboxparse.py) stores in NetBox via show interfaces switchport.
# DNAC returns full names; normalize to match what's already in NetBox.
# TwentyFiveGigE, Port-channel, Vlan, Loopback, Tunnel, Bluetooth keep their DNAC names — they already match.
_DNAC_IF_NORM = [
    ("GigabitEthernet", "Gi"),
    ("TenGigabitEthernet", "Te"),
    ("FortyGigabitEthernet", "Fo"),
    ("FastEthernet", "Fa"),
    ("HundredGigE", "Hu"),
    ("AppGigabitEthernet", "Ap"),
]


def _normalize_if_name(name: str) -> str:
    """Convert DNAC full interface names to Cisco abbreviated form (matching NetBox from SSH)."""
    for full, abbrev in _DNAC_IF_NORM:
        if name.startswith(full):
            return abbrev + name[len(full):]
    return name


def _is_primary_interface(dev: dict, if_name: str) -> bool:
    """Return True if this interface's IP should be set as the device's primary IPv4.
    C9300* platforms use Loopback0 as management; everything else uses Vlan1."""
    platform = (dev.get("netbox_device_type") or "").upper()
    if platform.startswith("C9300"):
        return if_name.lower() == "loopback0"
    return is_vlan1_interface(if_name)


# Prefixes whose interfaces should be skipped entirely (not physical switchports)
_SKIP_PREFIXES = ("loopback", "vlan", "tunnel")
# Prefixes that cannot be access ports (port-channels: include in swp_info with mode=None)
_NO_ACCESS_PREFIXES = ("port-channel",)


def _transform_interfaces(dnac_interfaces: list) -> dict:
    """
    Build swp_info dict from DNAC interfaces.

    Access ports: physical switchport with a valid vlanId → mode="access".
    Trunk/unknown: included with mode=None so they still get created in NetBox
    but skip VLAN assignment.  Omitting them entirely would mean they never get
    created — worse than empty shells.
    """
    swp_info = {}
    for iface in dnac_interfaces:
        name = _normalize_if_name((iface.get("portName") or "").strip())
        if not name:
            continue
        lname = name.lower()

        # Skip virtual/non-switchport interface types
        if any(lname.startswith(p) for p in _SKIP_PREFIXES):
            continue

        vlan_id_raw = iface.get("vlanId") or ""
        vlan_id = None
        if str(vlan_id_raw).isdigit() and int(vlan_id_raw) > 0:
            vlan_id = int(vlan_id_raw)

        if vlan_id and not any(lname.startswith(p) for p in _NO_ACCESS_PREFIXES):
            swp_info[name] = {
                "mode": "access",
                "access_vlan": vlan_id,
                "native_vlan": None,
                "allowed_vlans": [],
            }
        else:
            swp_info[name] = {
                "mode": None,
                "access_vlan": None,
                "native_vlan": None,
                "allowed_vlans": [],
            }
    return swp_info


def _transform_ips(dnac_interfaces: list) -> list:
    """Extract IP addresses from DNAC interface list, converted to CIDR notation."""
    results = []
    for iface in dnac_interfaces:
        ip = (iface.get("ipv4Address") or "").strip()
        mask = (iface.get("ipv4Mask") or "").strip()
        name = _normalize_if_name((iface.get("portName") or "").strip())
        if ip and mask and name:
            bits = _mask_to_bits(mask)
            results.append({"name": name, "cidr": f"{ip}/{bits}"})
    return results


# =========================
# PER-DEVICE COLLECTION
# =========================

def collect_device_data(dnac: DNACClient, dnac_device: dict) -> dict:
    """Fetch per-device interfaces and VLANs from DNAC, transform, and return a queue item."""
    device_id = dnac_device["id"]

    interfaces = dnac.get_device_interfaces(device_id)
    vlans_raw = dnac.get_device_vlans(device_id)

    dev = _transform_device(dnac_device)
    vlans = _transform_vlans(vlans_raw)
    swp_info = _transform_interfaces(interfaces)
    ip_info = _transform_ips(interfaces)

    return {
        "dev": dev,
        "vlans": vlans,
        "swp_info": swp_info,
        "ip_info": ip_info,
    }


# =========================
# NETBOX PUSH (DNAC source)
# =========================

def push_device_to_netbox_from_dnac(item: dict, site, facility_id: str, logger):
    """
    Sync one device's data (pre-transformed from DNAC) into NetBox.
    Mirrors push_device_to_netbox() from netboxparse.py but accepts structured data
    instead of raw CLI output.
    """
    dev = item["dev"]
    vlans = item["vlans"]
    swp_info = item["swp_info"]
    ip_info = item["ip_info"]

    logger.info(
        "=== Processing %s (%s) facility=%s site=%s ===",
        dev["name"],
        dev["host"],
        facility_id,
        site.name if site else "None",
    )

    tenant_id = get_site_tenant_id(site) if INHERIT_SITE_TENANT else None
    site_role = resolve_site_role(site) if INHERIT_SITE_ROLE else None
    site_device_role, site_vlan_role, site_ip_role = (
        resolve_role_mappings(site_role) if site_role else (None, None, None)
    )

    if INHERIT_SITE_ROLE and site_role and not site_device_role:
        logger.info("  [ROLE MAP] No matching device role for site role '%s'", site_role.name)
    if INHERIT_SITE_ROLE and site_role and not site_vlan_role:
        logger.info("  [ROLE MAP] No matching VLAN role for site role '%s'", site_role.name)
    if INHERIT_SITE_ROLE and site_role and not site_ip_role:
        logger.info("  [ROLE MAP] No matching IP role for site role '%s'", site_role.name)

    nb_device = ensure_device_in_netbox(
        dev, site,
        tenant_id=tenant_id,
        site_device_role=site_device_role,
        serial=dev.get("_serial") or None,
        software_version=dev.get("_software_version"),
        dnac_device_id=dev.get("_dnac_device_id"),
        stack_serials=dev.get("_stack_serials"),
    )

    # Bulk-fetch all interfaces for this device in one call instead of one call per interface.
    # Reduces ~226 individual API calls per device to a single paginated request.
    if nb_device:
        iface_cache = {i.name: i for i in nb_client().dcim.interfaces.filter(device_id=nb_device.id)}
    else:
        iface_cache = {}

    logger.info(
        "  Found %s VLANs, %s switchports, %s L3 interfaces",
        len(vlans), len(swp_info), len(ip_info),
    )

    group_name = facility_id or "UNKNOWN"
    group = get_or_create_vlan_group(site, group_name)

    vlan_map = {}
    for v in vlans:
        nb_vlan = ensure_vlan_in_netbox(
            v, group,
            tenant_id=tenant_id,
            vlan_role_id=site_vlan_role.id if site_vlan_role else None,
        )
        if nb_vlan:
            vlan_map[v["id"]] = nb_vlan

    for if_name, info in swp_info.items():
        nb_iface = ensure_interface(nb_device, if_name, tenant_id=tenant_id, iface_cache=iface_cache)
        if not nb_iface and DRY_RUN:
            continue

        # mode=None means trunk or unknown — interface is created but no VLAN assignment
        desired_mode = None
        desired_untagged_vlan_id = None
        desired_tagged_vlan_ids = []

        if info["mode"] == "access":
            desired_mode = "access"
            if info["access_vlan"] and info["access_vlan"] in vlan_map:
                desired_untagged_vlan_id = vlan_map[info["access_vlan"]].id

        elif info["mode"] == "trunk":
            desired_mode = "tagged"
            if info["native_vlan"] and info["native_vlan"] in vlan_map:
                desired_untagged_vlan_id = vlan_map[info["native_vlan"]].id
            for v in info["allowed_vlans"]:
                if v in vlan_map:
                    desired_tagged_vlan_ids.append(vlan_map[v].id)

        # mode=None: desired_mode stays None → no mode/VLAN update, interface exists as shell
        changed = False

        if desired_mode and nb_iface and nb_iface.mode != desired_mode:
            nb_iface.mode = desired_mode
            changed = True

        if nb_iface:
            current_untagged_id = nb_iface.untagged_vlan.id if nb_iface.untagged_vlan else None
            if desired_untagged_vlan_id is not None and current_untagged_id != desired_untagged_vlan_id:
                nb_iface.untagged_vlan = desired_untagged_vlan_id
                changed = True

            if desired_tagged_vlan_ids:
                current_tagged_ids = sorted([v.id for v in (nb_iface.tagged_vlans or [])])
                if sorted(desired_tagged_vlan_ids) != current_tagged_ids:
                    nb_iface.tagged_vlans = desired_tagged_vlan_ids
                    changed = True

        if changed:
            if DRY_RUN:
                logger.info(
                    "  [DRY RUN] Would update %s: mode=%s, untagged=%s, tagged=%s",
                    if_name, desired_mode, desired_untagged_vlan_id, desired_tagged_vlan_ids,
                )
            else:
                try:
                    nb_iface.save()
                    logger.info(
                        "  [IF] Updated %s: mode=%s, untagged=%s, tagged=%s",
                        if_name, desired_mode, desired_untagged_vlan_id, desired_tagged_vlan_ids,
                    )
                except RequestError as e:
                    logger.error("  [IF] NetBox rejected %s: %s", if_name, getattr(e, "error", e))

    for entry in ip_info:
        if_name = entry["name"]
        cidr = entry["cidr"]

        nb_iface = ensure_interface(nb_device, if_name, tenant_id=tenant_id, iface_cache=iface_cache)
        if not nb_iface and DRY_RUN:
            continue

        ip_results = list(nb_client().ipam.ip_addresses.filter(address=cidr))
        existing = ip_results[0] if ip_results else None
        if existing:
            changed = False
            if existing.assigned_object_type != "dcim.interface" or existing.assigned_object_id != nb_iface.id:
                if DRY_RUN:
                    logger.info("  [DRY RUN] Would re-attach %s to %s", cidr, if_name)
                else:
                    existing.assigned_object_type = "dcim.interface"
                    existing.assigned_object_id = nb_iface.id
                    changed = True
            if tenant_id is not None:
                current_tenant_id = get_obj_tenant_id(existing)
                if current_tenant_id != tenant_id:
                    if DRY_RUN:
                        logger.info("  [DRY RUN] Would update tenant for %s", cidr)
                    else:
                        if set_obj_tenant(existing, tenant_id, f"ip {cidr}"):
                            changed = True
            if site_ip_role:
                current_role_id = existing.role.id if existing.role else None
                if current_role_id != site_ip_role.id:
                    if DRY_RUN:
                        logger.info("  [DRY RUN] Would update role for %s", cidr)
                    else:
                        existing.role = site_ip_role.id
                        changed = True
            want_dns = dns_label(dev.get("name")) if is_vlan1_interface(if_name) and ":" not in cidr else None
            if want_dns is not None and (existing.dns_name or "") != want_dns:
                if DRY_RUN:
                    logger.info("  [DRY RUN] Would set dns_name for %s to %s", cidr, want_dns)
                else:
                    existing.dns_name = want_dns
                    changed = True
            if changed and not DRY_RUN:
                try:
                    existing.save()
                    logger.info("  [IP] Updated %s on %s", cidr, if_name)
                except Exception as e:
                    logger.warning("  [IP] Could not update %s on %s: %s", cidr, if_name, e)

            if _is_primary_interface(dev, if_name) and ":" not in cidr:
                if DRY_RUN:
                    logger.info("  [DRY RUN] Would set primary IPv4 for %s to %s", dev["name"], cidr)
                else:
                    current_primary = getattr(nb_device, "primary_ip4", None)
                    current_primary_id = current_primary.id if current_primary else None
                    if current_primary_id != existing.id:
                        try:
                            nb_client().dcim.devices.update([{"id": nb_device.id, "primary_ip4": existing.id}])
                            logger.info("  [DEVICE] Set primary IPv4 for %s to %s", dev["name"], cidr)
                        except Exception as e:
                            logger.warning("  [DEVICE] Could not set primary IPv4 for %s to %s: %s", dev["name"], cidr, e)
            continue

        if DRY_RUN:
            logger.info("  [DRY RUN] Would create %s on %s", cidr, if_name)
        else:
            payload = {
                "address": cidr,
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": nb_iface.id,
            }
            if tenant_id is not None:
                payload["tenant"] = tenant_id
            if site_ip_role:
                payload["role"] = site_ip_role.id
            want_dns = dns_label(dev.get("name")) if is_vlan1_interface(if_name) and ":" not in cidr else None
            if want_dns is not None:
                payload["dns_name"] = want_dns
            created = nb_client().ipam.ip_addresses.create(payload)
            logger.info("  [IP] Created %s on %s", cidr, if_name)
            if created and _is_primary_interface(dev, if_name) and ":" not in cidr:
                current_primary = getattr(nb_device, "primary_ip4", None)
                current_primary_id = current_primary.id if current_primary else None
                if current_primary_id != created.id:
                    try:
                        nb_client().dcim.devices.update([{"id": nb_device.id, "primary_ip4": created.id}])
                        logger.info("  [DEVICE] Set primary IPv4 for %s to %s", dev["name"], cidr)
                    except Exception as e:
                        logger.warning("  [DEVICE] Could not set primary IPv4 for %s to %s: %s", dev["name"], cidr, e)


# =========================
# TOPOLOGY / CABLE SYNC
# =========================

def sync_topology(dnac: DNACClient, logger):
    """
    Fetch CDP/LLDP physical topology from DNAC and create cables in NetBox.

    Skip behavior:
      - Either endpoint device not in NetBox → warn + skip
      - Either endpoint interface not in NetBox → warn + skip
      - Either interface already has a cable attached → skip (count as 'already cabled')
    Bidirectional topology deduplication: after the first link creates a cable,
    the reverse link's interfaces will have cable set and be skipped automatically.
    """
    logger.info(">>> Starting topology/cable sync...")
    topology = dnac.get_physical_topology()
    nodes = topology.get("nodes", [])
    links = topology.get("links", [])

    # Build DNAC node-id → hostname lookup
    id_to_hostname = {}
    for node in nodes:
        node_id = node.get("id", "")
        label = node.get("label", "")
        if node_id and label:
            id_to_hostname[node_id] = label

    nb = nb_client()
    created = 0
    skipped_cabled = 0
    skipped_missing = 0

    for link in links:
        src_id = link.get("source") or link.get("sourceNodeId") or ""
        tgt_id = link.get("target") or link.get("targetNodeId") or ""
        src_port = _normalize_if_name((link.get("startPortName") or "").strip())
        tgt_port = _normalize_if_name((link.get("endPortName") or "").strip())

        if not all([src_id, tgt_id, src_port, tgt_port]):
            continue

        src_hostname = id_to_hostname.get(src_id, "")
        tgt_hostname = id_to_hostname.get(tgt_id, "")

        if not src_hostname or not tgt_hostname:
            logger.warning(
                "  [CABLE SKIP] Cannot resolve hostnames for link %s <-> %s", src_id, tgt_id
            )
            skipped_missing += 1
            continue

        try:
            src_results = list(nb.dcim.devices.filter(name=src_hostname))
            src_device = src_results[0] if src_results else None
            tgt_results = list(nb.dcim.devices.filter(name=tgt_hostname))
            tgt_device = tgt_results[0] if tgt_results else None
        except Exception as e:
            logger.warning(
                "  [CABLE SKIP] NetBox API error looking up %s <-> %s: %s",
                src_hostname, tgt_hostname, e,
            )
            skipped_missing += 1
            continue

        if not src_device or not tgt_device:
            missing = [h for h, d in [(src_hostname, src_device), (tgt_hostname, tgt_device)] if not d]
            logger.warning("  [CABLE SKIP] Device(s) not in NetBox: %s", ", ".join(missing))
            skipped_missing += 1
            continue

        src_iface = nb.dcim.interfaces.get(device_id=src_device.id, name=src_port)
        tgt_iface = nb.dcim.interfaces.get(device_id=tgt_device.id, name=tgt_port)

        if not src_iface or not tgt_iface:
            missing = [
                f"{h}/{p}"
                for h, p, i in [
                    (src_hostname, src_port, src_iface),
                    (tgt_hostname, tgt_port, tgt_iface),
                ]
                if not i
            ]
            logger.warning("  [CABLE SKIP] Interface(s) not in NetBox: %s", ", ".join(missing))
            skipped_missing += 1
            continue

        if src_iface.cable or tgt_iface.cable:
            skipped_cabled += 1
            continue

        if DRY_RUN:
            logger.info(
                "  [DRY RUN] Would create cable %s/%s <-> %s/%s",
                src_hostname, src_port, tgt_hostname, tgt_port,
            )
            created += 1
        else:
            try:
                nb.dcim.cables.create({
                    "a_terminations": [{"object_type": "dcim.interface", "object_id": src_iface.id}],
                    "b_terminations": [{"object_type": "dcim.interface", "object_id": tgt_iface.id}],
                })
                logger.info(
                    "  [CABLE] Created %s/%s <-> %s/%s",
                    src_hostname, src_port, tgt_hostname, tgt_port,
                )
                created += 1
            except Exception as e:
                logger.error(
                    "  [CABLE ERROR] %s/%s <-> %s/%s: %s",
                    src_hostname, src_port, tgt_hostname, tgt_port, e,
                )

    logger.info(
        ">>> Topology sync done: Created %d, skipped %d (already cabled), skipped %d (endpoint not in NetBox)",
        created, skipped_cabled, skipped_missing,
    )


# =========================
# MAIN
# =========================

def main():
    global DRY_RUN

    parser = argparse.ArgumentParser(description="Sync switches from DNAC to NetBox")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Override DRY_RUN to true")
    parser.add_argument("--hostname", default=None, help="Sync only this hostname (for testing)")
    parser.add_argument("--family", default="Switches and Hubs", help="DNAC device family filter")
    parser.add_argument("--skip-topology", action="store_true", default=False, help="Skip cable/topology sync")
    parser.add_argument("--workers", type=int, default=None, help="Override DISCOVERY_WORKERS")
    parser.add_argument("--netbox-workers", type=int, default=None, help="Override NETBOX_WORKERS")
    args = parser.parse_args()

    if args.dry_run:
        DRY_RUN = True

    discovery_workers = args.workers if args.workers is not None else DISCOVERY_WORKERS
    netbox_workers = args.netbox_workers if args.netbox_workers is not None else NETBOX_WORKERS

    logger = setup_logging(DRY_RUN)

    # Init shared NetBox helpers
    config = NetboxConfig(
        netbox_url=NETBOX_URL,
        netbox_token=NETBOX_TOKEN,
        dry_run=DRY_RUN,
        inherit_site_tenant=INHERIT_SITE_TENANT,
        inherit_site_role=INHERIT_SITE_ROLE,
        fallback_device_type_slug=FALLBACK_NETBOX_DEVICE_TYPE_SLUG,
        fallback_device_role=FALLBACK_DEVICE_ROLE,
    )
    init_nb_helpers(config, logger)

    # Init DNAC client and authenticate
    dnac_cfg = DNACConfig(
        base_url=DNAC_BASE_URL,
        username=DNAC_USERNAME,
        password=DNAC_PASSWORD,
        verify_ssl=DNAC_VERIFY_SSL,
        page_size=DNAC_PAGE_SIZE,
    )
    dnac = DNACClient(dnac_cfg)
    logger.info(">>> Authenticating to DNAC at %s ...", DNAC_BASE_URL)
    dnac._ensure_token()
    logger.info(">>> DNAC auth OK")

    # Build site map
    site_map = build_site_map()
    logger.info(">>> Loaded %d sites from NetBox", len(site_map))

    # Fetch all devices from DNAC
    logger.info(">>> Fetching devices from DNAC (family=%r) ...", args.family)
    all_devices = dnac.get_all_devices()

    # Apply filters BEFORE spawning threads — no point hitting per-device APIs for discarded devices
    filtered = []
    for d in all_devices:
        if d.get("family", "") != args.family:
            continue
        if d.get("reachabilityStatus", "") != "Reachable":
            continue
        if args.hostname and d.get("hostname", "") != args.hostname:
            continue
        # Explicitly skip APs and wireless devices regardless of family filter
        _platform = (d.get("platformId") or "").upper()
        _family   = (d.get("family") or "").lower()
        _dtype    = (d.get("type") or "").lower()
        if (
            _family in ("access points", "unified ap", "wireless lan controller")
            or "access point" in _dtype
            or _platform.startswith(("AIR-", "C9100", "C9105", "C9115", "C9120", "C9130", "C9136"))
        ):
            logger.info("  [SKIP AP] %s (family=%r, platform=%r)", d.get("hostname"), d.get("family"), _platform)
            continue
        filtered.append(d)

    logger.info(
        ">>> %d devices total from DNAC; %d match filters (family=%r, hostname=%r, reachable only)",
        len(all_devices), len(filtered), args.family, args.hostname,
    )
    logger.info(
        ">>> discovery_workers=%d; netbox_workers=%d; dry_run=%s",
        discovery_workers, netbox_workers, DRY_RUN,
    )

    results_q = queue.Queue()

    def netbox_worker():
        while True:
            item = results_q.get()
            try:
                if item is None:
                    return

                dev = item["dev"]
                facility_id = extract_facility_id_from_hostname(dev.get("name", ""), site_map)
                if not facility_id:
                    # Try numeric-prefix alias (e.g. "400-Switch" → "ADM")
                    prefix = re.split(r"[^A-Za-z0-9]", dev.get("name", "").upper())[0]
                    facility_id = _HOSTNAME_PREFIX_ALIASES.get(prefix)
                site = site_map.get(facility_id)

                logger.info(
                    "[SITE MAP] %s -> facility_id=%s -> site=%s",
                    dev["name"], facility_id, site.name if site else None,
                )

                push_device_to_netbox_from_dnac(item, site, facility_id, logger)
            except Exception as exc:
                dev_name = "<unknown>"
                if isinstance(item, dict):
                    dev_name = item.get("dev", {}).get("name", "<unknown>")
                logger.error("  [NETBOX ERROR] %s: %s", dev_name, exc)
            finally:
                results_q.task_done()

    nb_threads = []
    for _ in range(max(netbox_workers, 1)):
        t = threading.Thread(target=netbox_worker, daemon=True)
        t.start()
        nb_threads.append(t)

    def collect(dnac_device):
        return collect_device_data(dnac, dnac_device)

    with concurrent.futures.ThreadPoolExecutor(max_workers=discovery_workers) as executor:
        futures = {executor.submit(collect, d): d for d in filtered}
        for future in concurrent.futures.as_completed(futures):
            dnac_device = futures[future]
            try:
                results_q.put(future.result())
            except Exception as exc:
                logger.error(
                    "  [COLLECTION ERROR] %s: %s",
                    dnac_device.get("hostname", "<unknown>"), exc,
                )

    # Signal workers to stop and wait for queue to drain
    for _ in nb_threads:
        results_q.put(None)
    results_q.join()
    for t in nb_threads:
        t.join()

    logger.info(">>> Device sync complete.")

    # Topology / cable sync (runs single-threaded, after all devices are synced)
    if not args.skip_topology:
        sync_topology(dnac, logger)

    logger.info(">>> Done.")


if __name__ == "__main__":
    main()
