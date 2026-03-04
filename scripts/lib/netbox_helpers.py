"""netbox_helpers.py — Shared NetBox write logic for netboxparse.py and dnac_netbox_sync.py.

Usage:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

    from lib.netbox_helpers import init, NetboxConfig, nb_client, build_site_map, ...

    config = NetboxConfig(netbox_url=..., netbox_token=..., dry_run=False, ...)
    init(config, logger)
"""
import re
import threading
from dataclasses import dataclass

import pynetbox
from pynetbox.core.query import RequestError


# =========================
# CONFIG / INIT
# =========================

@dataclass
class NetboxConfig:
    netbox_url: str
    netbox_token: str
    dry_run: bool = False
    inherit_site_tenant: bool = True
    inherit_site_role: bool = True
    fallback_device_type_slug: str = "unknown-catalyst-switch"
    fallback_device_role: str = "access-switch"


_cfg = None
_logger = None

_nb_local = threading.local()
_SITE_TENANT_CACHE = {}


def init(config: NetboxConfig, logger):
    """Configure the module before use. Call once from main() before spawning threads."""
    global _cfg, _logger
    _cfg = config
    _logger = logger
    _SITE_TENANT_CACHE.clear()
    # Reset any cached per-thread clients so they pick up new credentials
    if hasattr(_nb_local, "nb"):
        del _nb_local.nb


def is_dry_run() -> bool:
    return bool(_cfg and _cfg.dry_run)


# =========================
# NB CLIENT
# =========================

def nb_client():
    if not hasattr(_nb_local, "nb"):
        _nb_local.nb = pynetbox.api(_cfg.netbox_url, token=_cfg.netbox_token)
    return _nb_local.nb


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
    """Infer a NetBox ROLE from a device type/model string."""
    if not device_type_name:
        return None
    lowered = device_type_name.lower()
    if any(x in lowered for x in ("catalyst", "switch", "9200", "9300", "9500", "35xx", "3560", "3750", "3850")):
        return "switch"
    return None


def is_vlan1_interface(if_name: str) -> bool:
    if not if_name:
        return False
    return re.match(r"^vlan\s*1$", if_name.strip(), re.IGNORECASE) is not None


def dns_label(name: str) -> str:
    return (name or "").split(".")[0]


# =========================
# TENANT / ROLE HELPERS
# =========================

def get_site_tenant_id(site):
    if not site:
        return None

    cached = _SITE_TENANT_CACHE.get(site.id)
    if cached is not None:
        return cached

    tenant_id = None
    tenant = getattr(site, "tenant", None)
    if tenant and getattr(tenant, "id", None):
        tenant_id = tenant.id
    else:
        tenant_id = getattr(site, "tenant_id", None)

    if tenant_id is None:
        try:
            refreshed = nb_client().dcim.sites.get(site.id)
            refreshed_tenant = getattr(refreshed, "tenant", None)
            if refreshed_tenant and getattr(refreshed_tenant, "id", None):
                tenant_id = refreshed_tenant.id
            else:
                tenant_id = getattr(refreshed, "tenant_id", None)
        except Exception:
            pass

    _SITE_TENANT_CACHE[site.id] = tenant_id
    return tenant_id


def get_obj_tenant_id(obj):
    tenant = getattr(obj, "tenant", None)
    if tenant and getattr(tenant, "id", None):
        return tenant.id
    return getattr(obj, "tenant_id", None)


def set_obj_tenant(obj, tenant_id, context):
    try:
        obj.tenant = tenant_id
    except AttributeError:
        _logger.info("  [TENANT SKIP] %s has no tenant field", context)
        return False
    return True


def resolve_site_role(site):
    if not site:
        return None
    return getattr(site, "site_role", None) or getattr(site, "role", None)


def resolve_role_mappings(site_role):
    if not site_role:
        return None, None, None

    role_slug = getattr(site_role, "slug", None)
    role_name = getattr(site_role, "name", None)

    device_role = None
    vlan_role = None
    ip_role = None

    if role_slug:
        device_role = nb_client().dcim.device_roles.get(slug=role_slug)
        vlan_role = nb_client().ipam.vlan_roles.get(slug=role_slug)
        ip_role = nb_client().ipam.roles.get(slug=role_slug)
    if role_name:
        device_role = device_role or nb_client().dcim.device_roles.get(name=role_name)
        vlan_role = vlan_role or nb_client().ipam.vlan_roles.get(name=role_name)
        ip_role = ip_role or nb_client().ipam.roles.get(name=role_name)

    return device_role, vlan_role, ip_role


# =========================
# SITE MAP
# =========================

def build_site_map():
    """Build a mapping of Facility Code -> Site object using NetBox site.facility field."""
    site_map = {}
    for site in nb_client().dcim.sites.all():
        facility = getattr(site, "facility", None)
        if facility and isinstance(facility, str):
            code = facility.strip().upper()
            if code:
                site_map[code] = site
    return site_map


def extract_facility_id_from_hostname(hostname: str, site_map: dict):
    """Extract facility code from hostname by matching tokens against known facility codes."""
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
# VLAN UTILS
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


# =========================
# NETBOX DEVICE HELPERS
# =========================

def resolve_device_type(nb_type_name: str):
    """Resolve a NetBox DeviceType; falls back to fallback_device_type_slug."""
    device_type = None
    if nb_type_name:
        _dt_by_slug  = nb_client().dcim.device_types.get(slug=nb_type_name)
        _dt_by_model = next(iter(nb_client().dcim.device_types.filter(model=nb_type_name)), None)
        _dt_by_name  = next(iter(nb_client().dcim.device_types.filter(name=nb_type_name)), None)
        device_type = _dt_by_slug or _dt_by_model or _dt_by_name
        if device_type:
            return device_type

        query = nb_type_name.strip()
        candidates = nb_client().dcim.device_types.filter(q=query)
        q_lower = query.lower()
        for c in candidates:
            for field in (c.model, c.name, c.slug):
                if field and field.strip().lower() == q_lower:
                    return c

    return next(iter(nb_client().dcim.device_types.filter(slug=_cfg.fallback_device_type_slug)), None)


def resolve_device_role(role_name: str):
    role = None
    if role_name:
        role = (
            nb_client().dcim.device_roles.get(slug=role_name)
            or next(iter(nb_client().dcim.device_roles.filter(name=role_name)), None)
        )
        if role:
            return role

    return (
        nb_client().dcim.device_roles.get(slug=_cfg.fallback_device_role)
        or next(iter(nb_client().dcim.device_roles.filter(name=_cfg.fallback_device_role)), None)
    )


def ensure_device_in_netbox(
    dev, site, tenant_id=None, site_device_role=None,
    *, serial=None, software_version=None, dnac_device_id=None, stack_serials=None
):
    """
    Create or update a device in NetBox.

    Optional keyword args (all default to None so existing callers that don't pass them
    continue to work without modification):
      serial           — single-value serial for NetBox's serial field
      software_version — synced to sw_version custom field
      dnac_device_id   — synced to dnac_device_id custom field
      stack_serials    — comma-separated stack serials, synced to stack_serials custom field

    Serial update behavior: if an existing device already has a different serial, a warning
    is logged (possible hardware replacement) and the serial is overwritten unless DRY_RUN.
    """
    if site:
        results = list(nb_client().dcim.devices.filter(name=dev["name"], site_id=site.id))
    else:
        results = list(nb_client().dcim.devices.filter(name=dev["name"]))
    nb_device = results[0] if results else None

    # Secondary lookup: strip domain suffix and try case-insensitive match.
    # Handles FQDN-vs-short-name mismatches (e.g. DNAC "ACM-AHALL.risd.net" vs NetBox "ACM-AHall").
    if not nb_device and "." in dev["name"]:
        short_name = dev["name"].split(".")[0]
        if site:
            results = list(nb_client().dcim.devices.filter(name__ie=short_name, site_id=site.id))
        else:
            results = list(nb_client().dcim.devices.filter(name__ie=short_name))
        if results:
            nb_device = results[0]
            _logger.info(
                "  [DEVICE] Matched %r to existing device %r via short hostname",
                dev["name"], nb_device.name,
            )

    if nb_device:
        # Update site if needed
        desired_site_id = site.id if site else None
        current_site_id = nb_device.site.id if nb_device.site else None
        if desired_site_id != current_site_id:
            if _cfg.dry_run:
                _logger.info("  [DRY RUN] Would update site for %s to %s", dev["name"], site.name if site else "None")
            else:
                nb_device.site = desired_site_id
                nb_device.save()
                _logger.info("  [DEVICE] Updated site for %s to %s", dev["name"], site.name if site else "None")

        if tenant_id is not None:
            current_tenant_id = get_obj_tenant_id(nb_device)
            if current_tenant_id != tenant_id:
                if _cfg.dry_run:
                    _logger.info("  [DRY RUN] Would update tenant for %s", dev["name"])
                else:
                    if set_obj_tenant(nb_device, tenant_id, f"device {dev['name']}"):
                        nb_device.save()
                        _logger.info("  [DEVICE] Updated tenant for %s", dev["name"])

        if site_device_role:
            current_role_id = nb_device.device_role.id if nb_device.device_role else None
            if current_role_id != site_device_role.id:
                if _cfg.dry_run:
                    _logger.info("  [DRY RUN] Would update role for %s to %s", dev["name"], site_device_role.name)
                else:
                    nb_device.device_role = site_device_role.id
                    nb_device.role = site_device_role.id
                    nb_device.save()
                    _logger.info("  [DEVICE] Updated role for %s to %s", dev["name"], site_device_role.name)

        # Serial update — warn on change (possible hardware replacement), then overwrite
        if serial is not None:
            current_serial = getattr(nb_device, "serial", None) or ""
            if current_serial and current_serial != serial:
                _logger.warning(
                    "  [SERIAL CHANGE] %s: existing serial %r differs from new %r — possible hardware replacement",
                    dev["name"], current_serial, serial,
                )
            if current_serial != serial:
                if _cfg.dry_run:
                    _logger.info("  [DRY RUN] Would update serial for %s to %s", dev["name"], serial)
                else:
                    nb_device.serial = serial
                    nb_device.save()
                    _logger.info("  [DEVICE] Updated serial for %s to %s", dev["name"], serial)

        _sync_device_custom_fields(nb_device, dev["name"], software_version, dnac_device_id, stack_serials)
        return nb_device

    # --- Create new device ---
    nb_type_name = dev.get("netbox_device_type") or dev.get("nb_device_type")
    nb_role_name = (
        dev.get("netbox_device_role")
        or dev.get("nb_device_role")
        or dev.get("device_role")
        or _cfg.fallback_device_role
    )

    device_type = resolve_device_type(nb_type_name)
    # If platformId resolved to the fallback type, try the DNAC human-readable type string as a
    # second attempt (e.g. "Cisco Catalyst 9200L 48-port PoE+ Switch" often matches better than
    # a raw platformId like "C9200L-48P-4G").
    if device_type and _cfg.fallback_device_type_slug and device_type.slug == _cfg.fallback_device_type_slug:
        dnac_type_hint = dev.get("_dnac_type") or ""
        if dnac_type_hint:
            better = resolve_device_type(dnac_type_hint)
            if better and better.slug != _cfg.fallback_device_type_slug:
                _logger.info(
                    "  [DEVICE TYPE] %s: platformId %r → fallback; using DNAC type %r → %s",
                    dev["name"], nb_type_name, dnac_type_hint, better.model,
                )
                device_type = better
    if not device_type:
        raise ValueError(
            f"DeviceType resolution failed for {dev['name']}. "
            f"CSV type={nb_type_name!r}, fallback slug={_cfg.fallback_device_type_slug!r} not found in NetBox."
        )

    device_role = resolve_device_role(nb_role_name)
    if not device_role:
        raise ValueError(
            f"DeviceRole resolution failed for {dev['name']}. "
            f"CSV role={nb_role_name!r}, fallback role={_cfg.fallback_device_role!r} not found in NetBox."
        )

    if site_device_role:
        device_role = site_device_role

    if nb_type_name and device_type.slug == _cfg.fallback_device_type_slug:
        _logger.info("  [DEVICE TYPE FALLBACK] %s: '%s' -> '%s'", dev["name"], nb_type_name, device_type.model)

    if not site:
        raise ValueError(
            f"Site mapping failed for {dev['name']} (hostname did not contain a known Facility code)."
        )

    payload = {
        "name": dev["name"],
        "device_type": device_type.id,
        "site": site.id,
        "device_role": device_role.id,
        "role": device_role.id,
    }
    if tenant_id is not None:
        payload["tenant"] = tenant_id
    if serial:
        payload["serial"] = serial

    if _cfg.dry_run:
        _logger.info(
            "  [DRY RUN] Would create device %s (type=%s, role=%s, site=%s, serial=%s)",
            dev["name"], device_type.model, device_role.name, site.name, serial or "",
        )
        return None

    created = nb_client().dcim.devices.create(payload)
    _logger.info(
        "  [NEW DEVICE] Created %s (type=%s, role=%s, site=%s)",
        dev["name"], device_type.model, device_role.name, site.name,
    )
    if created:
        _sync_device_custom_fields(created, dev["name"], software_version, dnac_device_id, stack_serials)
    return created


def _sync_device_custom_fields(nb_device, device_name, software_version, dnac_device_id, stack_serials):
    custom_updates = {}
    if software_version is not None:
        custom_updates["sw_version"] = software_version
    if dnac_device_id is not None:
        custom_updates["dnac_device_id"] = dnac_device_id
    if stack_serials is not None:
        custom_updates["stack_serials"] = stack_serials

    if not custom_updates:
        return

    if _cfg.dry_run:
        _logger.info(
            "  [DRY RUN] Would update custom fields for %s: %s",
            device_name, list(custom_updates.keys()),
        )
        return

    for k, v in custom_updates.items():
        try:
            nb_device.custom_fields[k] = v
            nb_device.save()
        except Exception as e:
            _logger.warning("  [CUSTOM FIELD] Skipping field '%s' for %s: %s", k, device_name, e)
            # Roll back the dirty field so it doesn't bleed into later saves
            try:
                nb_device.custom_fields.pop(k, None)
            except Exception:
                pass


# =========================
# VLAN HELPERS
# =========================

def get_or_create_vlan_group(site, group_name):
    group = (
        nb_client().ipam.vlan_groups.get(name=group_name, scope_type="dcim.site", scope_id=site.id)
        if site else None
    )

    if not group:
        if _cfg.dry_run:
            _logger.info(
                "  [DRY RUN] Would create VLAN group '%s' for site=%s",
                group_name, site.name if site else "None",
            )
            return None
        payload = {"name": group_name, "slug": group_name.lower().replace(" ", "-")}
        if site:
            payload["scope_type"] = "dcim.site"
            payload["scope_id"] = site.id
        group = nb_client().ipam.vlan_groups.create(payload)

    return group


def ensure_vlan_in_netbox(vlan, group, tenant_id=None, vlan_role_id=None):
    if not group:
        return None

    existing = nb_client().ipam.vlans.get(vid=vlan["id"], group_id=group.id)
    if existing:
        changed = False
        if existing.name != vlan["name"]:
            existing.name = vlan["name"]
            changed = True
        if tenant_id is not None:
            current_tenant_id = get_obj_tenant_id(existing)
            if current_tenant_id != tenant_id:
                if set_obj_tenant(existing, tenant_id, f"vlan {vlan['id']}"):
                    changed = True
        if vlan_role_id is not None:
            current_role_id = existing.role.id if existing.role else None
            if current_role_id != vlan_role_id:
                existing.role = vlan_role_id
                changed = True
        if changed:
            if _cfg.dry_run:
                _logger.info("  [DRY RUN] Would update VLAN %s", vlan["id"])
            else:
                existing.save()
        return existing

    if _cfg.dry_run:
        _logger.info(
            "  [DRY RUN] Would create VLAN %s (%s) in group %s",
            vlan["id"], vlan["name"], group.name,
        )
        return None

    payload = {"vid": vlan["id"], "name": vlan["name"], "group": group.id}
    if tenant_id is not None:
        payload["tenant"] = tenant_id
    if vlan_role_id is not None:
        payload["role"] = vlan_role_id
    return nb_client().ipam.vlans.create(payload)


# =========================
# INTERFACE HELPERS
# =========================

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


def ensure_interface(nb_device, if_name, tenant_id=None, iface_cache=None):
    if not nb_device:
        return None
    if iface_cache is not None:
        nb_iface = iface_cache.get(if_name)
    else:
        nb_iface = nb_client().dcim.interfaces.get(device_id=nb_device.id, name=if_name)
    if nb_iface:
        if tenant_id is not None:
            current_tenant_id = get_obj_tenant_id(nb_iface)
            if current_tenant_id != tenant_id:
                if _cfg.dry_run:
                    _logger.info("  [DRY RUN] Would update tenant for interface %s", if_name)
                else:
                    if set_obj_tenant(nb_iface, tenant_id, f"interface {if_name}"):
                        nb_iface.save()
                        _logger.info("  [IF] Updated tenant for %s", if_name)
        return nb_iface

    iface_type = detect_interface_type(if_name)
    if _cfg.dry_run:
        _logger.info("  [DRY RUN] Would create interface %s type=%s", if_name, iface_type)
        return None

    payload = {"device": nb_device.id, "name": if_name, "type": iface_type}
    if tenant_id is not None:
        payload["tenant"] = tenant_id
    try:
        return nb_client().dcim.interfaces.create(payload)
    except RequestError as e:
        if "tenant" in str(getattr(e, "error", e)).lower() and "tenant" in payload:
            payload.pop("tenant", None)
            return nb_client().dcim.interfaces.create(payload)
        raise
