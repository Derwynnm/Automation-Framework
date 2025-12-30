import os
import csv
import re
import queue
import time
import random
import threading
import concurrent.futures
from pathlib import Path
import logging

from netmiko import ConnectHandler
import pynetbox
from pynetbox.core.query import RequestError
from dotenv import load_dotenv


# =========================
# ENV / CONFIG
# =========================
env_path = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(env_path)

NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
DEVICE_USERNAME = os.getenv("DEVICE_USERNAME") or os.getenv("username")
DEVICE_PASSWORD = os.getenv("DEVICE_PASSWORD") or os.getenv("password")
DEVICE_SECRET = os.getenv("DEVICE_SECRET") or os.getenv("secret")

# Netmiko platform driver (NOT NetBox model)
NETMIKO_DEVICE_TYPE_DEFAULT = os.getenv("NETMIKO_DEVICE_TYPE", "cisco_ios")

DEVICE_CSV = Path(__file__).resolve().parents[1] / "inventory" / "devices.csv"
DISCOVERY_WORKERS = int(os.getenv("DISCOVERY_WORKERS", "5"))
NETBOX_WORKERS = int(os.getenv("NETBOX_WORKERS", "1"))
DRY_RUN = os.getenv("DRY_RUN", "").strip().lower() in ("1", "true", "yes", "y")

CONNECT_TIMEOUT = int(os.getenv("CONNECT_TIMEOUT", "15"))
COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "25"))
READ_TIMEOUT = int(os.getenv("READ_TIMEOUT", "60"))

# You created this in NetBox — used as model fallback for messy CSV strings like "Catalyst 35xx"
FALLBACK_NETBOX_DEVICE_TYPE_SLUG = os.getenv("FALLBACK_NETBOX_DEVICE_TYPE_SLUG", "unknown-catalyst-switch")

# If role is missing, default to this
FALLBACK_DEVICE_ROLE = os.getenv("FALLBACK_DEVICE_ROLE", "switch")

LOG_DIR = Path(__file__).resolve().parents[1] / "logs"

if not NETBOX_URL or not NETBOX_TOKEN:
    raise ValueError("NETBOX_URL and NETBOX_TOKEN must be set in .env")

nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)

def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_mode = "dryrun" if DRY_RUN else "run"
    log_path = LOG_DIR / f"netboxparse_{run_mode}_{timestamp}.log"

    logger = logging.getLogger("netboxparse")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logger.info("Logging to %s (dry_run=%s)", log_path, DRY_RUN)
    return logger


logger = setup_logging()


# =========================
# UTILS
# =========================
def strip_bom(s: str) -> str:
    return s.lstrip("\ufeff") if isinstance(s, str) else s


def normalize_key(k: str) -> str:
    k = strip_bom(k.strip())
    k = re.sub(r"\s+", " ", k)
    return k


def normalize_value(v):
    if isinstance(v, str):
        return v.strip()
    return v


def infer_device_role_from_type(device_type_name: str):
    """
    Infer a NetBox ROLE (not model, not netmiko platform).
    Adjust to match your NetBox role slugs/names.
    """
    if not device_type_name:
        return None
    lowered = device_type_name.lower()
    if any(x in lowered for x in ("catalyst", "switch", "9200", "9300", "9500", "35xx", "3560", "3750", "3850")):
        return "switch"
    return None


# =========================
# SITE MAP (UPDATED)
# =========================
def build_site_map():
    """
    Build a mapping of Facility Code -> Site object.
    This uses the NetBox Site 'facility' field (ACE, BSE, PHS, FSC, etc).
    """
    site_map = {}
    for site in nb.dcim.sites.all():
        facility = getattr(site, "facility", None)
        if facility and isinstance(facility, str):
            code = facility.strip().upper()
            if code:
                site_map[code] = site
    return site_map


def extract_facility_id_from_hostname(hostname: str, site_map: dict):
    """
    Extract facility code from hostname by looking for a token that matches a known facility code.
    Example tokens come from splitting on '-', '_', '.', etc.
    """
    if not hostname:
        return None

    tokens = re.split(r"[^A-Za-z0-9]+", hostname.upper())

    # Exact token match
    for t in tokens:
        if t in site_map:
            return t

    # Fallback: if the first 3 alnum chars match a code, accept it
    cleaned = re.sub(r"[^A-Za-z0-9]", "", hostname.upper())
    if len(cleaned) >= 3 and cleaned[:3] in site_map:
        return cleaned[:3]

    return None


# =========================
# INVENTORY LOADING
# =========================
def normalize_row(row: dict) -> dict:
    dev = {}
    for k, v in row.items():
        if not k:
            continue
        key = normalize_key(k)
        val = normalize_value(v)
        dev[key] = val

    # Header variants
    if "Device Name" in dev and "name" not in dev:
        dev["name"] = dev.get("Device Name")
    if "IP Address" in dev and "host" not in dev:
        dev["host"] = dev.get("IP Address")
    if "Device Type" in dev and "netbox_device_type" not in dev:
        dev["netbox_device_type"] = dev.get("Device Type")

    # Alternate common fields
    if not dev.get("name") and dev.get("hostname"):
        dev["name"] = dev.get("hostname")
    if not dev.get("host") and dev.get("ip"):
        dev["host"] = dev.get("ip")

    # Netmiko platform always set
    if not dev.get("device_type"):
        dev["device_type"] = NETMIKO_DEVICE_TYPE_DEFAULT

    # Credentials
    if not dev.get("username") and DEVICE_USERNAME:
        dev["username"] = DEVICE_USERNAME
    if not dev.get("password") and DEVICE_PASSWORD:
        dev["password"] = DEVICE_PASSWORD
    if not dev.get("secret") and DEVICE_SECRET:
        dev["secret"] = DEVICE_SECRET

    # Role inference / fallback
    if not dev.get("device_role") and not dev.get("netbox_device_role") and not dev.get("nb_device_role"):
        inferred = infer_device_role_from_type(dev.get("netbox_device_type"))
        if inferred:
            dev["device_role"] = inferred

    return dev


def load_inventory(path=DEVICE_CSV):
    devices = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue

            dev = normalize_row(row)

            if not any(dev.values()):
                continue

            if not dev.get("name") or not dev.get("host"):
                logger.warning("  [INVENTORY SKIP] Missing name/host: %s", dev)
                continue

            missing = [k for k in ("username", "password") if not dev.get(k)]
            if missing:
                raise ValueError(
                    f"Device {dev.get('name', '<unknown>')} missing {missing}. "
                    "Set in devices.csv or .env (DEVICE_USERNAME/DEVICE_PASSWORD)."
                )

            dev["device_type"] = dev.get("device_type") or NETMIKO_DEVICE_TYPE_DEFAULT
            devices.append(dev)

    return devices


# =========================
# NETBOX HELPERS
# =========================
def resolve_device_type(nb_type_name: str):
    """
    Resolve a NetBox DeviceType from CSV-provided string.
    Falls back to placeholder device type (unknown-catalyst-switch) if no match.
    """
    device_type = None
    if nb_type_name:
        device_type = (
            nb.dcim.device_types.get(slug=nb_type_name)
            or nb.dcim.device_types.get(model=nb_type_name)
            or nb.dcim.device_types.get(name=nb_type_name)
        )
        if device_type:
            return device_type

        query = nb_type_name.strip()
        candidates = nb.dcim.device_types.filter(q=query)
        q_lower = query.lower()
        for c in candidates:
            for field in (c.model, c.name, c.slug):
                if field and field.strip().lower() == q_lower:
                    return c

    return nb.dcim.device_types.get(slug=FALLBACK_NETBOX_DEVICE_TYPE_SLUG)


def resolve_device_role(role_name: str):
    role = None
    if role_name:
        role = nb.dcim.device_roles.get(slug=role_name) or nb.dcim.device_roles.get(name=role_name)
        if role:
            return role

    return nb.dcim.device_roles.get(slug=FALLBACK_DEVICE_ROLE) or nb.dcim.device_roles.get(name=FALLBACK_DEVICE_ROLE)


def ensure_device_in_netbox(dev, site):
    nb_device = nb.dcim.devices.get(name=dev["name"])
    if nb_device:
        # update site if needed
        desired_site_id = site.id if site else None
        current_site_id = nb_device.site.id if nb_device.site else None
        if desired_site_id != current_site_id:
            if DRY_RUN:
                logger.info("  [DRY RUN] Would update site for %s to %s", dev["name"], site.name if site else "None")
            else:
                nb_device.site = desired_site_id
                nb_device.save()
                logger.info("  [DEVICE] Updated site for %s to %s", dev["name"], site.name if site else "None")
        return nb_device

    nb_type_name = dev.get("netbox_device_type") or dev.get("nb_device_type")
    nb_role_name = dev.get("netbox_device_role") or dev.get("nb_device_role") or dev.get("device_role") or FALLBACK_DEVICE_ROLE

    device_type = resolve_device_type(nb_type_name)
    if not device_type:
        raise ValueError(
            f"DeviceType resolution failed for {dev['name']}. "
            f"CSV type={nb_type_name!r}, fallback slug={FALLBACK_NETBOX_DEVICE_TYPE_SLUG!r} not found in NetBox."
        )

    device_role = resolve_device_role(nb_role_name)
    if not device_role:
        raise ValueError(
            f"DeviceRole resolution failed for {dev['name']}. "
            f"CSV role={nb_role_name!r}, fallback role={FALLBACK_DEVICE_ROLE!r} not found in NetBox."
        )

    if nb_type_name and device_type.slug == FALLBACK_NETBOX_DEVICE_TYPE_SLUG:
        logger.info("  [DEVICE TYPE FALLBACK] %s: '%s' -> '%s'", dev["name"], nb_type_name, device_type.model)

    if not site:
        # Your NetBox requires site. If mapping fails, you MUST choose a strategy:
        # 1) create a "STAGING" site and use it here, OR
        # 2) skip the device.
        raise ValueError(f"Site mapping failed for {dev['name']} (hostname did not contain a known Facility code).")

    payload = {
    "name": dev["name"],
    "device_type": device_type.id,
    "site": site.id,

    # compatibility across NetBox versions/serializers
    "device_role": device_role.id,
    "role": device_role.id,
    }

    if DRY_RUN:
        logger.info(
            "  [DRY RUN] Would create device %s (type=%s, role=%s, site=%s)",
            dev["name"],
            device_type.model,
            device_role.name,
            site.name,
        )
        return None

    created = nb.dcim.devices.create(payload)
    logger.info(
        "  [NEW DEVICE] Created %s (type=%s, role=%s, site=%s)",
        dev["name"],
        device_type.model,
        device_role.name,
        site.name,
    )
    return created


def get_or_create_vlan_group(site, group_name):
    group = nb.ipam.vlan_groups.get(name=group_name, scope_type="dcim.site", scope_id=site.id) if site else None

    if not group:
        if DRY_RUN:
            logger.info(
                "  [DRY RUN] Would create VLAN group '%s' for site=%s",
                group_name,
                site.name if site else "None",
            )
            return None
        payload = {"name": group_name, "slug": group_name.lower().replace(" ", "-")}
        if site:
            payload["scope_type"] = "dcim.site"
            payload["scope_id"] = site.id
        group = nb.ipam.vlan_groups.create(payload)

    return group


def ensure_vlan_in_netbox(vlan, group):
    if not group:
        return None

    existing = nb.ipam.vlans.get(vid=vlan["id"], group_id=group.id)
    if existing:
        changed = False
        if existing.name != vlan["name"]:
            existing.name = vlan["name"]
            changed = True
        if changed:
            if DRY_RUN:
                logger.info("  [DRY RUN] Would update VLAN %s name", vlan["id"])
            else:
                existing.save()
        return existing

    if DRY_RUN:
        logger.info(
            "  [DRY RUN] Would create VLAN %s (%s) in group %s",
            vlan["id"],
            vlan["name"],
            group.name,
        )
        return None

    return nb.ipam.vlans.create({"vid": vlan["id"], "name": vlan["name"], "group": group.id})


def detect_interface_type(if_name):
    lname = if_name.lower()
    if lname.startswith(("vlan", "loopback")):
        return "virtual"
    if lname.startswith(("gi", "gigabitethernet")):
        return "1000base-t"
    if lname.startswith(("te", "tengigabitethernet")):
        return "10gbase-x-sfpp"
    if lname.startswith(("twe", "twentyfivegige")):
        return "25gbase-x-sfp28"
    if lname.startswith(("fo", "fortygigabitethernet")):
        return "40gbase-x-qsfpp"
    if lname.startswith(("hu", "hundredgige")):
        return "100gbase-x-qsfp28"
    return "other"


def ensure_interface(nb_device, if_name):
    if not nb_device:
        return None
    nb_iface = nb.dcim.interfaces.get(device_id=nb_device.id, name=if_name)
    if nb_iface:
        return nb_iface

    iface_type = detect_interface_type(if_name)
    if DRY_RUN:
        logger.info("  [DRY RUN] Would create interface %s type=%s", if_name, iface_type)
        return None

    return nb.dcim.interfaces.create({"device": nb_device.id, "name": if_name, "type": iface_type})


# =========================
# PARSERS
# =========================
def expand_vlan_list(vlan_str):
    vlans = []
    for chunk in vlan_str.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-")
            if start.isdigit() and end.isdigit():
                vlans.extend(range(int(start), int(end) + 1))
        else:
            if chunk.isdigit():
                vlans.append(int(chunk))
    return vlans


def parse_vlans(vlan_output):
    vlans = []
    for line in vlan_output.splitlines():
        line = line.strip()
        if not line or line.startswith(("VLAN", "-", "----")):
            continue
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        vlan_id = int(parts[0])
        vlan_name = parts[1]
        vlans.append({"id": vlan_id, "name": vlan_name})
    return vlans


def parse_switchport(output):
    result = {}
    current = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        name_match = re.match(r"^Name\s*:\s*(\S+)", line)
        if name_match:
            name = name_match.group(1)
            current = {"mode": None, "access_vlan": None, "native_vlan": None, "allowed_vlans": []}
            result[name] = current
            continue

        if current is None:
            continue

        if line.startswith("Operational Mode:"):
            val = line.split("Operational Mode:")[1].strip().lower()
            if "access" in val:
                current["mode"] = "access"
            elif "trunk" in val:
                current["mode"] = "trunk"

        elif line.startswith("Access Mode VLAN:"):
            parts = line.split(":", 1)[1].strip().split()
            if parts and parts[0].isdigit():
                current["access_vlan"] = int(parts[0])

        elif line.startswith("Trunking Native Mode VLAN:"):
            parts = line.split(":", 1)[1].strip().split()
            if parts and parts[0].isdigit():
                current["native_vlan"] = int(parts[0])

        elif line.startswith("Trunking VLANs Enabled:"):
            vlan_str = line.split(":", 1)[1].strip()
            if vlan_str.lower() != "none":
                current["allowed_vlans"] = expand_vlan_list(vlan_str)

    return result


def parse_ip_interface(output):
    results = []
    current_int = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if " line protocol is " in line:
            current_int = line.split()[0]
            continue

        if "Internet address is" in line and current_int:
            addr = line.split()[-1]
            if "/" in addr and addr.split("/")[1].isdigit():
                cidr = addr
            elif "/" in addr:
                ip, mask = addr.split("/")
                octets = [int(o) for o in mask.split(".")]
                bits = sum(bin(o).count("1") for o in octets)
                cidr = f"{ip}/{bits}"
            else:
                cidr = addr + "/32"

            results.append({"name": current_int, "cidr": cidr})

    return results


# =========================
# DISCOVERY + NETBOX PUSH
# =========================
def collect_switch_data(dev):
    time.sleep(random.uniform(0.2, 1.0))

    conn_params = {
        "device_type": dev.get("device_type") or NETMIKO_DEVICE_TYPE_DEFAULT,
        "host": dev["host"],
        "username": dev["username"],
        "password": dev["password"],
        "timeout": CONNECT_TIMEOUT,
        "conn_timeout": CONNECT_TIMEOUT,
        "banner_timeout": CONNECT_TIMEOUT,
        "auth_timeout": CONNECT_TIMEOUT,
    }
    if dev.get("secret"):
        conn_params["secret"] = dev["secret"]

    conn = ConnectHandler(**conn_params)
    if dev.get("secret"):
        try:
            conn.enable()
        except Exception:
            pass
    try:
        conn.send_command("terminal length 0", read_timeout=READ_TIMEOUT)
    except Exception:
        pass

    vlan_output = conn.send_command("show vlan brief", read_timeout=READ_TIMEOUT)
    swp_output = conn.send_command("show interfaces switchport", read_timeout=READ_TIMEOUT)
    ip_output = conn.send_command("show ip interface", read_timeout=READ_TIMEOUT)

    conn.disconnect()
    return vlan_output, swp_output, ip_output


def push_device_to_netbox(dev, site, facility_id, vlan_output, swp_output, ip_output):
    logger.info(
        "=== Processing %s (%s) facility=%s site=%s ===",
        dev["name"],
        dev["host"],
        facility_id,
        site.name if site else "None",
    )

    nb_device = ensure_device_in_netbox(dev, site)

    vlans = parse_vlans(vlan_output)
    swp_info = parse_switchport(swp_output)
    ip_info = parse_ip_interface(ip_output)

    logger.info(
        "  [OUTPUT] switchport chars=%s lines=%s",
        len(swp_output),
        len(swp_output.splitlines()),
    )
    logger.info(
        "  Found %s VLANs, %s switchports, %s L3 interfaces",
        len(vlans),
        len(swp_info),
        len(ip_info),
    )

    group_name = facility_id or "UNKNOWN"
    group = get_or_create_vlan_group(site, group_name)

    vlan_map = {}
    for v in vlans:
        nb_vlan = ensure_vlan_in_netbox(v, group)
        if nb_vlan:
            vlan_map[v["id"]] = nb_vlan

    for if_name, info in swp_info.items():
        nb_iface = ensure_interface(nb_device, if_name)
        if not nb_iface and DRY_RUN:
            continue

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

        changed = False

        if desired_mode and nb_iface.mode != desired_mode:
            nb_iface.mode = desired_mode
            changed = True

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
                    if_name,
                    desired_mode,
                    desired_untagged_vlan_id,
                    desired_tagged_vlan_ids,
                )
            else:
                try:
                    nb_iface.save()
                    logger.info(
                        "  [IF] Updated %s: mode=%s, untagged=%s, tagged=%s",
                        if_name,
                        desired_mode,
                        desired_untagged_vlan_id,
                        desired_tagged_vlan_ids,
                    )
                except RequestError as e:
                    logger.error("  [IF] NetBox rejected %s: %s", if_name, getattr(e, "error", e))

    for entry in ip_info:
        if_name = entry["name"]
        cidr = entry["cidr"]

        nb_iface = ensure_interface(nb_device, if_name)
        if not nb_iface and DRY_RUN:
            continue

        existing = nb.ipam.ip_addresses.get(address=cidr)
        if existing:
            if existing.assigned_object_type != "dcim.interface" or existing.assigned_object_id != nb_iface.id:
                if DRY_RUN:
                    logger.info("  [DRY RUN] Would re-attach %s to %s", cidr, if_name)
                else:
                    existing.assigned_object_type = "dcim.interface"
                    existing.assigned_object_id = nb_iface.id
                    existing.save()
                    logger.info("  [IP] Re-attached %s to %s", cidr, if_name)
            continue

        if DRY_RUN:
            logger.info("  [DRY RUN] Would create %s on %s", cidr, if_name)
        else:
            nb.ipam.ip_addresses.create(
                {"address": cidr, "assigned_object_type": "dcim.interface", "assigned_object_id": nb_iface.id}
            )
            logger.info("  [IP] Created %s on %s", cidr, if_name)


# =========================
# MAIN
# =========================
def main():
    devices = load_inventory()
    site_map = build_site_map()

    logger.info(
        ">>> Loaded %s devices; discovery_workers=%s; netbox_workers=%s; dry_run=%s",
        len(devices),
        DISCOVERY_WORKERS,
        NETBOX_WORKERS,
        DRY_RUN,
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
                site = site_map.get(facility_id)

                # Debug to confirm mapping works
                logger.info(
                    "[SITE MAP] %s -> facility_id=%s -> site=%s",
                    dev["name"],
                    facility_id,
                    site.name if site else None,
                )

                push_device_to_netbox(
                    dev,
                    site,
                    facility_id,
                    item["vlan_output"],
                    item["swp_output"],
                    item["ip_output"],
                )
            except Exception as exc:
                dev_name = "<unknown>"
                if isinstance(item, dict):
                    dev_name = item.get("dev", {}).get("name", "<unknown>")
                logger.error("  [NETBOX ERROR] %s: %s", dev_name, exc)
            finally:
                results_q.task_done()

    nb_threads = []
    for _ in range(max(NETBOX_WORKERS, 1)):
        t = threading.Thread(target=netbox_worker, daemon=True)
        t.start()
        nb_threads.append(t)

    def discover(dev):
        vlan_output, swp_output, ip_output = collect_switch_data(dev)
        return {"dev": dev, "vlan_output": vlan_output, "swp_output": swp_output, "ip_output": ip_output}

    with concurrent.futures.ThreadPoolExecutor(max_workers=DISCOVERY_WORKERS) as executor:
        futures = {executor.submit(discover, dev): dev for dev in devices}
        for future in concurrent.futures.as_completed(futures):
            dev = futures[future]
            try:
                results_q.put(future.result())
            except Exception as exc:
                logger.error("  [DISCOVERY ERROR] %s: %s", dev.get("name", "<unknown>"), exc)

    for _ in nb_threads:
        results_q.put(None)
    results_q.join()
    for t in nb_threads:
        t.join()

    logger.info(">>> Done.")


if __name__ == "__main__":
    main()
