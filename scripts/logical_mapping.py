import argparse
import csv
import os
import re
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv
import pynetbox

load_dotenv()

NB_URL = os.getenv("NETBOX_URL")
NB_TOKEN = os.getenv("NETBOX_TOKEN")

# Device Type slug for "N/A Wall Jack"
WALLJACK_DEVICE_TYPE_SLUG = "wall-jack"

# Device Role slug for "Ethernet Wall Plate"
WALLJACK_ROLE_SLUG = "ethernet-wall-plate"

# Patch Panel device type/role slugs
PATCH_PANEL_DEVICE_TYPE_SLUG = "patch-panel-48-port"
PATCH_PANEL_ROLE_SLUG = "patch-panel-48-port"

DEFAULT_PANEL_NAME_TEMPLATE = "{facility_id}-{location_code}-Patch Panel {panel_letter}"
PANEL_LOCATION_ALIASES = {
    # Example: "HALL-A": "AHall",
}


# =========================
# Helpers / Types
# =========================
@dataclass
class Termination:
    term_type: str  # "dcim.interface" | "dcim.frontport" | "dcim.rearport"
    term_id: int


class NBWriter:
    """Wrapper that supports dry-run: logs actions instead of writing when dry_run=True."""

    def __init__(self, nb, dry_run: bool):
        self.nb = nb
        self.dry_run = dry_run

    def log(self, msg: str):
        print(("[DRY] " if self.dry_run else "[DO ] ") + msg)

    def create(self, endpoint, payload: dict):
        self.log(f"CREATE {endpoint._url} {payload}")
        if self.dry_run:
            return None
        return endpoint.create(payload)

    def update(self, obj, payload: dict):
        self.log(f"UPDATE {obj.url} {payload}")
        if self.dry_run:
            return None
        return obj.update(payload)


def nb_connect():
    if not NB_URL or not NB_TOKEN:
        raise RuntimeError("Missing NETBOX_URL or NETBOX_TOKEN in environment/.env")
    return pynetbox.api(NB_URL, token=NB_TOKEN)


def resolve_site_id(nb, facility_id: str) -> int:
    """
    Implement your facility-id -> site lookup rule here.
    Default assumption: Site name == facility_id (e.g., 'ABC')
    """
    site = nb.dcim.sites.get(name=facility_id)
    if site:
        return site.id

    # If you use a custom field instead, uncomment and adjust key:
    # sites = list(nb.dcim.sites.filter(cf_facility_id=facility_id))
    # if sites:
    #     return sites[0].id

    raise RuntimeError(f"Could not resolve Site for facility_id={facility_id}")


def normalize_switch_port(port_raw: str) -> str:
    p = port_raw.strip()
    if not p:
        return p
    if re.match(r"^[0-9]", p):
        return f"Gi{p}"
    return p


def validate_patch_port(patch: str) -> bool:
    # Accepts A1..A99, B1..B99, etc.
    normalized = patch.strip().upper()
    return bool(re.match(r"^[A-Z]\d{1,2}$", normalized))


def extract_panel_letter(patch_port: str) -> str:
    return patch_port[:1]


def build_patch_panel_name(facility_id: str, location_code: str, panel_letter: str, template: str) -> str:
    location_for_device = PANEL_LOCATION_ALIASES.get(location_code, location_code)
    return template.format(
        facility_id=facility_id,
        location_code=location_for_device,
        panel_letter=panel_letter,
    )


def find_switch_by_primary_ip(nb, ip: str):
    # Works because your devices have Primary IPv4 set (per your screenshot)
    candidates = [ip]
    if "/" not in ip:
        candidates.append(f"{ip}/24")

    for candidate in candidates:
        dev = nb.dcim.devices.get(primary_ip4=candidate) or nb.dcim.devices.get(primary_ip=candidate)
        if dev:
            return dev
    return None


def get_or_create_location(w: NBWriter, site_id: int, location_name: str) -> int:
    loc = w.nb.dcim.locations.get(site_id=site_id, name=location_name)
    if loc:
        return loc.id
    created = w.create(
        w.nb.dcim.locations,
        {"site": site_id, "name": location_name, "status": "active"},
    )
    return created.id if created else -1


def get_or_create_device(
    w: NBWriter,
    *,
    name: str,
    site_id: int,
    device_type_slug: str,
    role_slug: str,
    location_id: Optional[int] = None,
):
    dev = w.nb.dcim.devices.get(name=name)
    if dev:
        return dev

    dt = w.nb.dcim.device_types.get(slug=device_type_slug)
    role = w.nb.dcim.device_roles.get(slug=role_slug)
    if not dt:
        raise RuntimeError(f"Device type slug not found: {device_type_slug}")
    if not role:
        raise RuntimeError(f"Device role slug not found: {role_slug}")

    payload = {
        "name": name,
        "device_type": dt.id,
        "device_role": role.id,
        "site": site_id,
        "status": "active",
    }
    if location_id and location_id != -1:
        payload["location"] = location_id

    created = w.create(w.nb.dcim.devices, payload)
    return created if created else None


def get_or_create_interface(w: NBWriter, device_id: int, ifname: str):
    iface = w.nb.dcim.interfaces.get(device_id=device_id, name=ifname)
    if iface:
        return iface
    created = w.create(w.nb.dcim.interfaces, {"device": device_id, "name": ifname, "type": "1000base-t"})
    return created if created else None


def ensure_patch_panel_ports(w: NBWriter, patch_panel_device_id: int, port_name: str):
    """
    Ensures BOTH:
      - RearPort <port_name>
      - FrontPort <port_name> mapped to that rear port
    """
    rear = w.nb.dcim.rear_ports.get(device_id=patch_panel_device_id, name=port_name)
    if not rear:
        rear = w.create(
            w.nb.dcim.rear_ports,
            {"device": patch_panel_device_id, "name": port_name, "type": "8p8c", "positions": 1},
        )

    front = w.nb.dcim.front_ports.get(device_id=patch_panel_device_id, name=port_name)
    if not front:
        front = w.create(
            w.nb.dcim.front_ports,
            {
                "device": patch_panel_device_id,
                "name": port_name,
                "type": "8p8c",
                "rear_port": getattr(rear, "id", None),
                "rear_port_position": 1,
            },
        )
    else:
        mapped_id = (getattr(front, "rear_port", None) or {}).get("id")
        if rear and mapped_id != rear.id:
            w.update(front, {"rear_port": rear.id, "rear_port_position": 1})

    return front, rear


def ensure_walljack_ports(w: NBWriter, walljack_device_id: int, port_name: str):
    """
    Matches your wall plate model:
      - RearPort <port_name>
      - FrontPort <port_name> mapped to that rear port
    Cable lands on REAR.
    """
    rear = w.nb.dcim.rear_ports.get(device_id=walljack_device_id, name=port_name)
    if not rear:
        rear = w.create(
            w.nb.dcim.rear_ports,
            {"device": walljack_device_id, "name": port_name, "type": "8p8c", "positions": 1},
        )

    front = w.nb.dcim.front_ports.get(device_id=walljack_device_id, name=port_name)
    if not front:
        front = w.create(
            w.nb.dcim.front_ports,
            {
                "device": walljack_device_id,
                "name": port_name,
                "type": "8p8c",
                "rear_port": getattr(rear, "id", None),
                "rear_port_position": 1,
            },
        )
    else:
        mapped_id = (getattr(front, "rear_port", None) or {}).get("id")
        if rear and mapped_id != rear.id:
            w.update(front, {"rear_port": rear.id, "rear_port_position": 1})

    return front, rear


def term_interface(iface) -> Termination:
    return Termination("dcim.interface", iface.id)


def term_frontport(fp) -> Termination:
    return Termination("dcim.frontport", fp.id)


def term_rearport(rp) -> Termination:
    return Termination("dcim.rearport", rp.id)


def is_cabled(obj) -> bool:
    return bool(getattr(obj, "cable", None))


def ensure_cable(
    w: NBWriter,
    a_obj,
    a_term: Termination,
    b_obj,
    b_term: Termination,
    label: str,
    strict: bool,
):
    """
    Safe behavior:
      - If either termination already has a cable, skip (or raise if --strict).
      - Does NOT delete/replace existing cables (you can add that later if desired).
    """
    if a_obj and is_cabled(a_obj):
        msg = f"SKIP cable (A already cabled): {label}"
        if strict:
            raise RuntimeError(msg)
        w.log(msg)
        return

    if b_obj and is_cabled(b_obj):
        msg = f"SKIP cable (B already cabled): {label}"
        if strict:
            raise RuntimeError(msg)
        w.log(msg)
        return

    w.create(
        w.nb.dcim.cables,
        {
            "termination_a_type": a_term.term_type,
            "termination_a_id": a_term.term_id,
            "termination_b_type": b_term.term_type,
            "termination_b_id": b_term.term_id,
            "status": "connected",
            "label": label,
        },
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--csv",
        default=os.path.join("Database", "PortMapping.csv"),
        help="Path to CSV (ip,port,patch,room,mapping). Default: Database/PortMapping.csv",
    )
    ap.add_argument("--facility-id", required=False, help="Facility ID (e.g., ACM)")
    ap.add_argument("--patch-panel", required=False, help='Patch panel device name (fallback when mapping is absent)')
    ap.add_argument(
        "--panel-name-template",
        default=DEFAULT_PANEL_NAME_TEMPLATE,
        help="Name template: {facility_id}-{location_code}-Patch Panel {panel_letter}",
    )
    ap.add_argument("--dry-run", action="store_true", help="Print actions only; do not write to NetBox")
    ap.add_argument("--strict", action="store_true", help="Fail if a termination is already cabled")
    args = ap.parse_args()

    facility_id = args.facility_id or input("Enter facility id (e.g., ACM): ").strip()
    patch_panel_name = args.patch_panel.strip() if args.patch_panel else None

    nb = nb_connect()
    w = NBWriter(nb, dry_run=args.dry_run)
    site_id = resolve_site_id(nb, facility_id)

    with open(args.csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row["ip"].strip()
            port_raw = row["port"].strip()
            patch_port = row["patch"].strip().upper()
            room = row["room"].strip()
            mapping = (row.get("mapping") or row.get("tr") or "").strip()

            if not validate_patch_port(patch_port):
                w.log(f"SKIP: invalid patch port '{patch_port}' in row: {row}")
                continue

            panel_letter = extract_panel_letter(patch_port)
            patch_panel_device_name = None
            if mapping:
                patch_panel_device_name = build_patch_panel_name(
                    facility_id,
                    mapping,
                    panel_letter,
                    args.panel_name_template,
                )
            elif patch_panel_name:
                patch_panel_device_name = patch_panel_name
            else:
                w.log(f"SKIP: no mapping/tr and no --patch-panel for row: {row}")
                continue

            switch_port = normalize_switch_port(port_raw)

            # 1) Find switch by Primary IPv4
            switch = find_switch_by_primary_ip(nb, ip)
            if not switch:
                w.log(f"SKIP: no switch found with primary IP {ip}")
                continue

            # 2) Ensure room location
            loc_id = get_or_create_location(w, site_id, room)

            # 3) Ensure wall jack device (name must equal location name)
            walljack = get_or_create_device(
                w,
                name=room,
                site_id=site_id,
                device_type_slug=WALLJACK_DEVICE_TYPE_SLUG,
                role_slug=WALLJACK_ROLE_SLUG,
                location_id=loc_id,
            )
            walljack_id = walljack.id if walljack else None

            # 4) Ensure patch panel device exists
            patch_panel = nb.dcim.devices.get(name=patch_panel_device_name)
            if not patch_panel:
                patch_panel = get_or_create_device(
                    w,
                    name=patch_panel_device_name,
                    site_id=site_id,
                    device_type_slug=PATCH_PANEL_DEVICE_TYPE_SLUG,
                    role_slug=PATCH_PANEL_ROLE_SLUG,
                )
            patch_panel_id = patch_panel.id if patch_panel else None

            # 5) Ensure switch interface
            sw_iface = get_or_create_interface(w, switch.id, switch_port)

            # 6) Ensure ports + mappings
            pp_front = pp_rear = None
            if patch_panel_id is not None:
                pp_front, pp_rear = ensure_patch_panel_ports(w, patch_panel_id, patch_port)

            wj_front = wj_rear = None
            if walljack_id is not None:
                wj_front, wj_rear = ensure_walljack_ports(w, walljack_id, patch_port)

            # 7) Cable A: Switch IF <-> Patch Panel FRONT (your convention)
            if sw_iface and pp_front:
                ensure_cable(
                    w,
                    sw_iface,
                    term_interface(sw_iface),
                    pp_front,
                    term_frontport(pp_front),
                    label=f"{switch.name}:{switch_port} -> {patch_panel_device_name}:{patch_port} (front)",
                    strict=args.strict,
                )
            else:
                w.log(f"INFO: cannot cable A yet (missing iface or pp_front) for row: {row}")

            # 8) Cable B: Patch Panel REAR <-> Wall Jack REAR (your convention)
            if pp_rear and wj_rear:
                ensure_cable(
                    w,
                    pp_rear,
                    term_rearport(pp_rear),
                    wj_rear,
                    term_rearport(wj_rear),
                    label=f"{patch_panel_device_name}:{patch_port} (rear) -> {room}:{patch_port} (rear)",
                    strict=args.strict,
                )
            else:
                w.log(f"INFO: cannot cable B yet (missing pp_rear or wj_rear) for row: {row}")

            w.log(f"DONE: {switch.name} {switch_port} => {patch_panel_device_name} {patch_port} => {room} {patch_port}")


if __name__ == "__main__":
    main()
