import os
import yaml
from netmiko import ConnectHandler
import pynetbox
from pynetbox.core.query import RequestError
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parents[1] / ".env"  # go up to repo root
load_dotenv(env_path)

# -------- Calling .env ---------
NETBOX_URL=os.getenv("NETBOX_URL")
NETBOX_TOKEN=os.getenv("NETBOX_TOKEN")
DEVICE_USERNAME = os.getenv("username")
DEVICE_PASSWORD = os.getenv("password")
DEVICE_SECRET = os.getenv("secret")

# ========= CONFIG =========
NETBOX_URL   = NETBOX_URL
NETBOX_TOKEN = NETBOX_TOKEN
NETBOX_SITE_NAME = "Sandbox"
VLAN_GROUP_NAME  = "Sandbox"
DEVICE_YAML      = Path(__file__).resolve().parents[1] / "inventory" / "devices.yml"
# ==========================

nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)


# ---------- Helpers ----------

def load_inventory(path=DEVICE_YAML):
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    devices = data["devices"]
    for dev in devices:
        if "username" not in dev and DEVICE_USERNAME:
            dev["username"] = DEVICE_USERNAME
        if "password" not in dev and DEVICE_PASSWORD:
            dev["password"] = DEVICE_PASSWORD
        if "secret" not in dev and DEVICE_SECRET:
            dev["secret"] = DEVICE_SECRET

        missing = [k for k in ("username", "password") if not dev.get(k)]
        if missing:
            raise ValueError(
                f"Device {dev.get('name', '<unknown>')} missing {missing}. "
                "Set in devices.yml or .env (DEVICE_USERNAME/DEVICE_PASSWORD)."
            )
    return devices


def get_site_from_netbox(name):
    site = nb.dcim.sites.get(name=name)
    if not site:
        raise ValueError(f"Site '{name}' not found in NetBox.")
    return site


def get_or_create_vlan_group(site):
    group = nb.ipam.vlan_groups.get(name=VLAN_GROUP_NAME, scope_id=site.id)
    if not group:
        group = nb.ipam.vlan_groups.create({
            "name": VLAN_GROUP_NAME,
            "slug": VLAN_GROUP_NAME.lower().replace(" ", "-"),
            "scope_type": "dcim.site",
            "scope_id": site.id,
        })
    return group


def ensure_vlan_in_netbox(vlan, site, group):
    """
    vlan = {"id": 10, "name": "STUDENT"}
    """
    existing = nb.ipam.vlans.get(vid=vlan["id"], group_id=group.id)
    if existing:
        changed = False
        if existing.name != vlan["name"]:
            existing.name = vlan["name"]
            changed = True
        # migrate old site-bound VLANs into the group
        if not existing.group:
            existing.group = group.id
            existing.site = None
            changed = True
        if changed:
            existing.save()
        return existing

    return nb.ipam.vlans.create({
        "vid": vlan["id"],
        "name": vlan["name"],
        "group": group.id,
    })


def ensure_interface_in_netbox(nb_device, if_name):
    nb_iface = nb.dcim.interfaces.get(device_id=nb_device.id, name=if_name)
    if not nb_iface:
        nb_iface = nb.dcim.interfaces.create({
            "device": nb_device.id,
            "name": if_name,
            "type": "1000base-t",    # adjust if you want to detect type
        })
    return nb_iface

def detect_interface_type(if_name):
    lname = if_name.lower()

    if lname.startswith("vlan"):
        return "virtual"
    if lname.startswith("loopback"):
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

def ensure_l3_interface(nb_device, if_name):
    """
    Creates an SVI, routed port, or loopback interface if missing.
    """

    nb_iface = nb.dcim.interfaces.get(device_id=nb_device.id, name=if_name)
    if nb_iface:
        return nb_iface

    # Determine interface type
    lname = if_name.lower()

    if lname.startswith("vlan"):
        iface_type = "virtual"
    elif lname.startswith("loopback"):
        iface_type = "virtual"
    else:
        iface_type = detect_interface_type(if_name)

    nb_iface = nb.dcim.interfaces.create({
        "device": nb_device.id,
        "name": if_name,
        "type": iface_type,
    })

    print(f"  [NEW IF] Created L3 interface {if_name}")

    return nb_iface

# ---------- CLI parsers ----------

def expand_vlan_list(vlan_str):
    vlans = []
    for chunk in vlan_str.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-")
            if start.isdigit() and end.isdigit():
                for v in range(int(start), int(end)+1):
                    vlans.append(v)
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
        if not parts[0].isdigit():
            continue
        vlan_id = int(parts[0])
        vlan_name = parts[1]
        vlans.append({"id": vlan_id, "name": vlan_name})
    return vlans


def parse_switchport(output):
    """
    Returns:
    {
      "Gi1/0/1": {
         "mode": "access" | "trunk" | None,
         "access_vlan": 10 or None,
         "native_vlan": 1 or None,
         "allowed_vlans": [10,20,30] or [],
      },
      ...
    }
    """
    result = {}
    current = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("Name:"):
            name = line.split("Name:")[1].strip()
            current = {
                "mode": None,
                "access_vlan": None,
                "native_vlan": None,
                "allowed_vlans": [],
            }
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
    """
    Parse 'show ip interface' into:
    [
      {"name": "Vlan1", "cidr": "10.1.1.10/24"},
      ...
    ]
    """
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
            # e.g. "Internet address is 10.1.1.10/24"
            parts = line.split()
            addr = parts[-1]
            # some platforms show "10.1.1.10/255.255.255.0"
            if "/" in addr and addr.split("/")[1].isdigit():
                cidr = addr
            elif "/" in addr:
                # dotted mask -> convert to prefix length
                ip, mask = addr.split("/")
                octets = [int(o) for o in mask.split(".")]
                bits = sum(bin(o).count("1") for o in octets)
                cidr = f"{ip}/{bits}"
            else:
                # fallback, shouldn't really happen
                cidr = addr + "/32"

            results.append({"name": current_int, "cidr": cidr})

    return results


# ---------- Device sync ----------

def collect_switch_data(dev):
    conn_params = {
        "device_type": dev["device_type"],
        "host": dev["host"],
        "username": dev["username"],
        "password": dev["password"],
    }
    if dev.get("secret"):
        conn_params["secret"] = dev["secret"]

    conn = ConnectHandler(**conn_params)
    vlan_output = conn.send_command("show vlan brief")
    swp_output  = conn.send_command("show interfaces switchport")
    ip_output   = conn.send_command("show ip interface")
    conn.disconnect()
    return vlan_output, swp_output, ip_output


def sync_device(dev, site):
    print(f"=== Processing {dev['name']} ({dev['host']}) ===")

    nb_device = nb.dcim.devices.get(name=dev["name"])
    if not nb_device:
        raise ValueError(f"Device {dev['name']} not found in NetBox")

    vlan_output, swp_output, ip_output = collect_switch_data(dev)

    vlans    = parse_vlans(vlan_output)
    swp_info = parse_switchport(swp_output)
    ip_info  = parse_ip_interface(ip_output)

    print(f"  Found {len(vlans)} VLANs, {len(swp_info)} switchports, {len(ip_info)} L3 interfaces")

    # VLANs
    group = get_or_create_vlan_group(site)
    vlan_map = {}
    for v in vlans:
        nb_vlan = ensure_vlan_in_netbox(v, site, group)
        vlan_map[v["id"]] = nb_vlan

    # Interfaces + switchport modes/VLANs
    for if_name, info in swp_info.items():
        nb_iface = ensure_interface_in_netbox(nb_device, if_name)

        desired_mode = None
        desired_untagged = None
        desired_tagged = []

        if info["mode"] == "access":
            desired_mode = "access"
            if info["access_vlan"] and info["access_vlan"] in vlan_map:
                desired_untagged = vlan_map[info["access_vlan"]].id

        elif info["mode"] == "trunk":
            desired_mode = "tagged"
            if info["native_vlan"] and info["native_vlan"] in vlan_map:
                desired_untagged = vlan_map[info["native_vlan"]].id
            for v in info["allowed_vlans"]:
                if v in vlan_map:
                    desired_tagged.append(vlan_map[v].id)

        changed = False

        if desired_mode and nb_iface.mode != desired_mode:
            nb_iface.mode = desired_mode
            changed = True

        if desired_untagged is not None and nb_iface.untagged_vlan != desired_untagged:
            nb_iface.untagged_vlan = desired_untagged
            changed = True

        if desired_tagged:
            current_tagged_ids = sorted([v.id for v in (nb_iface.tagged_vlans or [])])
            if sorted(desired_tagged) != current_tagged_ids:
                nb_iface.tagged_vlans = desired_tagged
                changed = True

        if changed:
            try:
                nb_iface.save()
                print(f"  [IF] Updated {if_name}: mode={desired_mode}, "
                      f"untagged={desired_untagged}, tagged={desired_tagged}")
            except RequestError as e:
                print(f"  [IF] NetBox rejected {if_name}: {e.error}")

    # IP addresses on L3 interfaces (SVIs, routed ports, loopbacks)
    for entry in ip_info:
        if_name = entry["name"]
        cidr    = entry["cidr"]

        nb_iface = ensure_l3_interface(nb_device, if_name)

        existing = nb.ipam.ip_addresses.get(address=cidr)
        if existing:
            # ensure attached to correct interface
            if (existing.assigned_object_type != "dcim.interface" or
                    existing.assigned_object_id != nb_iface.id):
                existing.assigned_object_type = "dcim.interface"
                existing.assigned_object_id   = nb_iface.id
                existing.save()
                print(f"  [IP] Re-attached {cidr} to {if_name}")
            continue

        nb_ip = nb.ipam.ip_addresses.create({
            "address": cidr,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": nb_iface.id,
        })
        print(f"  [IP] Created {cidr} on {if_name}")


def main():
    devices = load_inventory()
    site = get_site_from_netbox(NETBOX_SITE_NAME)

    print(f">>> Loaded {len(devices)} devices; site={site.name}")

    for dev in devices:
        sync_device(dev, site)

    print(">>> Done.")


if __name__ == "__main__":
    main()
