import argparse
import csv
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Optional
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime

from dotenv import load_dotenv
import pynetbox
from pynetbox.core.query import RequestError

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
    "HALL-A": "AHall"
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

    def __init__(
        self,
        nb,
        dry_run: bool,
        write_workers: int,
        logger: logging.Logger,
        retry_attempts: int,
        retry_backoff: float,
    ):
        self.nb = nb
        self.dry_run = dry_run
        self.logger = logger
        self.retry_attempts = max(1, retry_attempts)
        self.retry_backoff = max(0.0, retry_backoff)
        self._dry_cache = {}
        self._dry_id = -1
        self._dry_lock = threading.Lock()
        self._write_sem = threading.Semaphore(max(1, write_workers))
        self._lock_map = {}
        self._lock_map_lock = threading.Lock()

    def lock_for(self, key):
        with self._lock_map_lock:
            lock = self._lock_map.get(key)
            if lock is None:
                lock = threading.Lock()
                self._lock_map[key] = lock
            return lock

    def log(self, msg: str):
        prefix = "[DRY] " if self.dry_run else "[DO ] "
        self.logger.debug("%s%s", prefix, msg)

    def should_retry(self, exc: RequestError) -> bool:
        status = getattr(exc, "status_code", None)
        return status in {429, 500, 502, 503, 504}

    def create(self, endpoint, payload: dict):
        endpoint_url = getattr(endpoint, "url", None) or getattr(endpoint, "_url", None) or str(endpoint)
        with self._write_sem:
            self.log(f"CREATE {endpoint_url} {payload}")
            if self.dry_run:
                with self._dry_lock:
                    key = None
                    if "device" in payload and "name" in payload:
                        key = (endpoint_url, payload.get("device"), payload.get("name"))
                    elif "site" in payload and "name" in payload:
                        key = (endpoint_url, payload.get("site"), payload.get("name"))
                    elif "name" in payload:
                        key = (endpoint_url, payload.get("name"))
                    elif "label" in payload:
                        key = (endpoint_url, payload.get("label"))

                    if key is not None and key in self._dry_cache:
                        return self._dry_cache[key]

                    stub_id = self._dry_id
                    self._dry_id -= 1
                    stub = SimpleNamespace(id=stub_id, url=f"{endpoint_url}/{stub_id}")
                    for field in ("name", "device", "site", "location", "type"):
                        if field in payload:
                            setattr(stub, field, payload.get(field))
                    if "rear_port" in payload:
                        rear_id = payload.get("rear_port")
                        setattr(stub, "rear_port", SimpleNamespace(id=rear_id) if rear_id else None)

                    if key is not None:
                        self._dry_cache[key] = stub
                    return stub
            last_exc = None
            for attempt in range(self.retry_attempts):
                try:
                    return endpoint.create(payload)
                except RequestError as exc:
                    last_exc = exc
                    if not self.should_retry(exc) or attempt == self.retry_attempts - 1:
                        raise
                    time.sleep(self.retry_backoff * (2**attempt))
            if last_exc:
                raise last_exc

    def update(self, obj, payload: dict):
        with self._write_sem:
            self.log(f"UPDATE {obj.url} {payload}")
            if self.dry_run:
                return None
            last_exc = None
            for attempt in range(self.retry_attempts):
                try:
                    return obj.update(payload)
                except RequestError as exc:
                    last_exc = exc
                    if not self.should_retry(exc) or attempt == self.retry_attempts - 1:
                        raise
                    time.sleep(self.retry_backoff * (2**attempt))
            if last_exc:
                raise last_exc


def nb_connect():
    if not NB_URL or not NB_TOKEN:
        raise RuntimeError("Missing NETBOX_URL or NETBOX_TOKEN in environment/.env")
    return pynetbox.api(NB_URL, token=NB_TOKEN)


def resolve_site_id(nb, facility_id: str) -> int:
    """
    Resolve a site by its Facility field (NetBox Site.facility).
    Falls back to site name when needed.
    """
    sites = list(nb.dcim.sites.filter(facility=facility_id))
    if len(sites) == 1:
        return sites[0].id
    if len(sites) > 1:
        names = ", ".join(s.name for s in sites)
        raise RuntimeError(f"Multiple Sites matched facility_id={facility_id}: {names}")

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


def normalize_header_key(key: str) -> str:
    k = key.strip().lower()
    k = k.lstrip("\ufeff")
    k = re.sub(r"^[^a-z0-9]+", "", k)
    return k


def slugify_location(name: str) -> str:
    slug = name.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "location"


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
    candidates = [ip]
    if "/" not in ip:
        candidates.append(f"{ip}/24")

    for candidate in candidates:
        ip_obj = nb.ipam.ip_addresses.get(address=candidate)
        if ip_obj and getattr(ip_obj, "assigned_object", None):
            assigned = ip_obj.assigned_object
            device = getattr(assigned, "device", None)
            if device:
                return device
    return None


def get_or_create_location(
    w: NBWriter, site_id: int, location_name: str, parent_id: Optional[int] = None
) -> Optional[int]:
    lock = w.lock_for(("location", site_id, location_name, parent_id))
    with lock:
        loc = w.nb.dcim.locations.get(site_id=site_id, name=location_name)
        if loc:
            if parent_id is not None:
                current_parent = getattr(loc, "parent", None)
                current_parent_id = getattr(current_parent, "id", None) if current_parent else None
                if current_parent_id != parent_id:
                    w.update(loc, {"parent": parent_id})
            return loc.id
        payload = {
            "site": site_id,
            "name": location_name,
            "slug": slugify_location(location_name),
            "status": "active",
        }
        if parent_id is not None:
            payload["parent"] = parent_id
        try:
            created = w.create(w.nb.dcim.locations, payload)
        except RequestError as exc:
            if "unique" in str(exc).lower():
                loc = w.nb.dcim.locations.get(site_id=site_id, name=location_name)
                if loc:
                    return loc.id
            raise
        return created.id if created else None


def get_or_create_device(
    w: NBWriter,
    *,
    name: str,
    site_id: int,
    device_type_slug: str,
    role_slug: str,
    location_id: Optional[int] = None,
):
    lock = w.lock_for(("device", site_id, name))
    with lock:
        dev = w.nb.dcim.devices.get(name=name, site_id=site_id) or w.nb.dcim.devices.get(name=name)
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
        "role": role.id,
        "site": site_id,
        "status": "active",
    }
    if location_id is not None:
        payload["location"] = location_id

        try:
            created = w.create(w.nb.dcim.devices, payload)
        except RequestError as exc:
            if "unique" in str(exc).lower():
                dev = w.nb.dcim.devices.get(name=name, site_id=site_id) or w.nb.dcim.devices.get(name=name)
                if dev:
                    return dev
            raise
        return created if created else None


def get_or_create_interface(w: NBWriter, device_id: int, ifname: str):
    lock = w.lock_for(("interface", device_id, ifname))
    with lock:
        if w.dry_run and device_id < 0:
            created = w.create(w.nb.dcim.interfaces, {"device": device_id, "name": ifname, "type": "1000base-t"})
            return created if created else None
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
    lock = w.lock_for(("patch_panel_ports", patch_panel_device_id, port_name))
    with lock:
        if w.dry_run and patch_panel_device_id < 0:
            rear = w.create(
                w.nb.dcim.rear_ports,
                {"device": patch_panel_device_id, "name": port_name, "type": "8p8c", "positions": 1},
            )
        else:
            rear = w.nb.dcim.rear_ports.get(device_id=patch_panel_device_id, name=port_name)
            if not rear:
                rear = w.create(
                    w.nb.dcim.rear_ports,
                    {"device": patch_panel_device_id, "name": port_name, "type": "8p8c", "positions": 1},
                )

        if rear is None or getattr(rear, "id", None) is None:
            raise RuntimeError(
                f"Failed to create/find rear port {port_name} on device_id={patch_panel_device_id}"
            )

        if w.dry_run and patch_panel_device_id < 0:
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
                mapped = getattr(front, "rear_port", None)
                mapped_id = getattr(mapped, "id", None) if mapped else None
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
    lock = w.lock_for(("walljack_ports", walljack_device_id, port_name))
    with lock:
        if w.dry_run and walljack_device_id < 0:
            rear = w.create(
                w.nb.dcim.rear_ports,
                {"device": walljack_device_id, "name": port_name, "type": "8p8c", "positions": 1},
            )
        else:
            rear = w.nb.dcim.rear_ports.get(device_id=walljack_device_id, name=port_name)
            if not rear:
                rear = w.create(
                    w.nb.dcim.rear_ports,
                    {"device": walljack_device_id, "name": port_name, "type": "8p8c", "positions": 1},
                )

        if rear is None or getattr(rear, "id", None) is None:
            raise RuntimeError(
                f"Failed to create/find rear port {port_name} on device_id={walljack_device_id}"
            )

        if w.dry_run and walljack_device_id < 0:
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
                mapped = getattr(front, "rear_port", None)
                mapped_id = getattr(mapped, "id", None) if mapped else None
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


def has_id(obj) -> bool:
    return obj is not None and getattr(obj, "id", None) is not None


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
    if not a_term.term_type or not a_term.term_id or not b_term.term_type or not b_term.term_id:
        w.log(
            f"BAD TERMINATION for '{label}': "
            f"A=({a_term.term_type},{a_term.term_id}) "
            f"B=({b_term.term_type},{b_term.term_id})"
        )
        if strict:
            raise RuntimeError("Cable terminations missing")
        return

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

    payload = {
        "termination_a_type": a_term.term_type,
        "termination_a_id": a_term.term_id,
        "termination_b_type": b_term.term_type,
        "termination_b_id": b_term.term_id,
        "status": "connected",
        "label": label,
    }
    create_cable_with_fallback(w, payload, label)


def create_cable_with_fallback(w: NBWriter, payload: dict, label: str):
    try:
        w.create(w.nb.dcim.cables, payload)
    except RequestError as exc:
        if "Must define A and B terminations" not in str(exc):
            raise
        w.log(f"RETRY cable with a_terminations/b_terminations: {label}")
        alt_payload = {
            "a_terminations": [
                {"object_type": payload["termination_a_type"], "object_id": payload["termination_a_id"]}
            ],
            "b_terminations": [
                {"object_type": payload["termination_b_type"], "object_id": payload["termination_b_id"]}
            ],
            "status": payload.get("status", "connected"),
            "label": payload.get("label"),
        }
        w.create(w.nb.dcim.cables, alt_payload)


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
    ap.add_argument("--row-workers", type=int, default=1, help="Max concurrent CSV rows to process")
    ap.add_argument("--write-workers", type=int, default=1, help="Max concurrent writes to NetBox")
    ap.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    ap.add_argument("--log-file", default="", help="Optional log file path")
    ap.add_argument("--retry-attempts", type=int, default=3, help="Retry attempts for transient NetBox errors")
    ap.add_argument("--retry-backoff", type=float, default=0.5, help="Seconds to back off between retries")
    ap.add_argument("--parent-location", default="", help="Parent location name for all room locations")
    ap.add_argument("--dry-run", action="store_true", help="Print actions only; do not write to NetBox")
    ap.add_argument("--strict", action="store_true", help="Fail if a termination is already cabled")
    args = ap.parse_args()

    facility_id = args.facility_id or input("Enter facility id (e.g., ACM): ").strip()
    patch_panel_name = args.patch_panel.strip() if args.patch_panel else None
    parent_location_name = args.parent_location or input("Enter parent location (optional): ").strip()

    logger = logging.getLogger("logical_mapping")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False
    file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    log_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_log_file = os.path.join("logs", f"logical_mapping_{log_timestamp}.log")
    log_file = args.log_file or default_log_file

    class RoomConsoleFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return bool(getattr(record, "console", False))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    console_handler.addFilter(RoomConsoleFilter())
    logger.addHandler(console_handler)

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    nb = nb_connect()
    w = NBWriter(
        nb,
        dry_run=args.dry_run,
        write_workers=args.write_workers,
        logger=logger,
        retry_attempts=args.retry_attempts,
        retry_backoff=args.retry_backoff,
    )
    site_id = resolve_site_id(nb, facility_id)
    parent_location_id = None
    if parent_location_name:
        parent_location_id = get_or_create_location(w, site_id, parent_location_name)
        if parent_location_id is None:
            raise RuntimeError(f"Failed to create/find parent location: {parent_location_name}")

    def log_room(room: str, status: str, message: str = ""):
        room_label = room or "<unknown>"
        if status == "success":
            logger.info("ROOM %s -> success", room_label, extra={"console": True})
        else:
            suffix = f": {message}" if message else ""
            logger.error("ROOM %s -> error%s", room_label, suffix, extra={"console": True})

    def process_row(row):
        try:
            row_norm = {normalize_header_key(k): v for k, v in row.items() if k}
            if all(not (v or "").strip() for v in row_norm.values()):
                return
            ip = (row_norm.get("ip") or "").strip()
            port_raw = (row_norm.get("port") or "").strip()
            patch_port = (row_norm.get("patch") or "").strip().upper()
            room = (row_norm.get("room") or "").strip()
            mapping = (row_norm.get("mapping") or row_norm.get("tr") or "").strip()
            if not ip or not port_raw or not patch_port or not room:
                log_room(room, "error", "missing required columns")
                w.log(f"SKIP: missing required columns in row: {row}")
                return

            if not validate_patch_port(patch_port):
                log_room(room, "error", f"invalid patch port '{patch_port}'")
                w.log(f"SKIP: invalid patch port '{patch_port}' in row: {row}")
                return

            panel_letter = extract_panel_letter(patch_port)
            patch_panel_device_name = None
            if mapping:
                patch_panel_device_name = build_patch_panel_name(
                    facility_id,
                    mapping,
                    panel_letter,
                    args.panel_name_template,
                )
            else:
                log_room(room, "error", "missing mapping/tr for patch panel name")
                w.log(f"SKIP: missing mapping/tr for patch panel name in row: {row}")
                return

            switch_port = normalize_switch_port(port_raw)

            # 1) Find switch by Primary IPv4
            switch = find_switch_by_primary_ip(nb, ip)
            if not switch:
                log_room(room, "error", f"no switch found with primary IP {ip}")
                w.log(f"SKIP: no switch found with primary IP {ip}")
                return

            # 2) Ensure room location
            loc_id = get_or_create_location(w, site_id, room, parent_id=parent_location_id)
            if loc_id is None:
                log_room(room, "error", "failed to create/find location")
                w.log(f"SKIP: failed to create/find location for row: {row}")
                return

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
                    location_id=parent_location_id,
                )
            patch_panel_id = patch_panel.id if patch_panel else None
            if patch_panel_id is None:
                log_room(room, "error", f"failed to create/find patch panel {patch_panel_device_name}")
                w.log(f"SKIP: failed to create/find patch panel for row: {row}")
                return

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
            if has_id(sw_iface) and has_id(pp_front):
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
                w.log(
                    f"SKIP cable A: sw_iface_id={getattr(sw_iface,'id',None)} "
                    f"pp_front_id={getattr(pp_front,'id',None)}"
                )

            # 8) Cable B: Patch Panel REAR <-> Wall Jack REAR (your convention)
            if has_id(pp_rear) and has_id(wj_rear):
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
                w.log(
                    f"SKIP cable B: pp_rear_id={getattr(pp_rear,'id',None)} "
                    f"wj_rear_id={getattr(wj_rear,'id',None)}"
                )

            log_room(room, "success")
            w.log(f"DONE: {switch.name} {switch_port} => {patch_panel_device_name} {patch_port} => {room} {patch_port}")
        except Exception as exc:
            log_room(room, "error", str(exc))
            w.log(f"ERROR: {exc} for row: {row}")

    with open(args.csv, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if args.row_workers <= 1:
        for row in rows:
            process_row(row)
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.row_workers)) as executor:
            futures = [executor.submit(process_row, row) for row in rows]
            for fut in as_completed(futures):
                exc = fut.exception()
                if exc:
                    raise exc


if __name__ == "__main__":
    main()
