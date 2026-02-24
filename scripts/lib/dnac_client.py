"""dnac_client.py — Cisco DNA Center / Catalyst Center REST API client.

Thread-safe: a single DNACClient instance can be shared across DISCOVERY_WORKERS
threads. Token refresh is protected by a threading.Lock.
"""
import time
import threading

import requests
from dataclasses import dataclass


@dataclass
class DNACConfig:
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    page_size: int = 500
    timeout: int = 30
    max_retries: int = 3


class DNACClient:
    # Proactively refresh when less than 5 minutes remain on the token.
    # DNAC tokens expire in 1 hour; with 400 devices and multiple API calls each,
    # a full run can easily exceed that window.
    TOKEN_REFRESH_THRESHOLD_SECS = 300

    def __init__(self, config: DNACConfig):
        self._cfg = config
        self._token = None
        self._token_expiry = 0.0  # monotonic timestamp
        self._lock = threading.Lock()

        self._session = requests.Session()
        self._session.verify = config.verify_ssl
        if not config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _authenticate(self):
        """Obtain a new token. Caller must hold self._lock."""
        url = f"{self._cfg.base_url}/dna/system/api/v1/auth/token"
        resp = self._session.post(
            url,
            auth=(self._cfg.username, self._cfg.password),
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        self._token = resp.json()["Token"]
        # DNAC tokens expire in exactly 1 hour; set expiry to 55 min from now
        self._token_expiry = time.monotonic() + 3300

    def _ensure_token(self):
        """Refresh the token if it is missing or within the refresh threshold."""
        with self._lock:
            remaining = self._token_expiry - time.monotonic()
            if self._token is None or remaining < self.TOKEN_REFRESH_THRESHOLD_SECS:
                self._authenticate()

    # ------------------------------------------------------------------
    # Core request
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict = None) -> dict:
        """Authenticated GET with retry on 429 (rate limit) and reactive refresh on 401."""
        self._ensure_token()
        url = f"{self._cfg.base_url}{path}"

        for attempt in range(self._cfg.max_retries + 1):
            headers = {"X-Auth-Token": self._token, "Content-Type": "application/json"}
            resp = self._session.get(url, headers=headers, params=params, timeout=self._cfg.timeout)

            if resp.status_code == 401:
                # Token expired mid-run; force refresh and retry once
                with self._lock:
                    self._authenticate()
                headers["X-Auth-Token"] = self._token
                resp = self._session.get(url, headers=headers, params=params, timeout=self._cfg.timeout)
                resp.raise_for_status()
                return resp.json()

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                time.sleep(retry_after)
                self._ensure_token()
                continue

            resp.raise_for_status()
            return resp.json()

        raise RuntimeError(f"DNAC GET {path} failed after {self._cfg.max_retries} retries (429 rate limit)")

    # ------------------------------------------------------------------
    # Device endpoints
    # ------------------------------------------------------------------

    def get_all_devices(self) -> list:
        """Paginate through /network-device and return all device records."""
        devices = []
        offset = 1  # DNAC uses 1-based offsets

        while True:
            params = {"offset": offset, "limit": self._cfg.page_size}
            data = self._get("/dna/intent/api/v1/network-device", params=params)
            page = data.get("response", [])
            if not page:
                break
            devices.extend(page)
            if len(page) < self._cfg.page_size:
                break
            offset += len(page)

        return devices

    def get_device_interfaces(self, device_id: str) -> list:
        """Return all interfaces for a device. Returns [] on any error."""
        try:
            data = self._get(f"/dna/intent/api/v1/interface/network-device/{device_id}")
            return data.get("response", [])
        except Exception:
            return []

    def get_device_vlans(self, device_id: str) -> list:
        """Return VLANs for a device. Returns [] on 400 (non-switch) or any error."""
        try:
            data = self._get(f"/dna/intent/api/v1/network-device/{device_id}/vlan")
            return data.get("response", [])
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 400:
                return []
            raise
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------

    def get_physical_topology(self) -> dict:
        """Return the physical topology response dict (contains 'nodes' and 'links')."""
        data = self._get("/dna/intent/api/v1/topology/physical-topology")
        return data.get("response", {})
