#!/usr/bin/env python3
import os
import time
import json
import ssl
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3


from prometheus_client import CollectorRegistry, Gauge, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST
from wsgiref.simple_server import make_server

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CONFIG_PATH = os.environ.get("IDRAC_CONFIG", "/etc/prometheus/idrac.yml")
DEFAULT_TIMEOUT = int(os.environ.get("IDRAC_TIMEOUT", "15"))
LISTEN_ADDR = os.environ.get("IDRAC_LISTEN", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("IDRAC_PORT", "9348"))

# Session token cache: target -> (token, session_location, expires_epoch)
_SESSION_CACHE: Dict[str, Tuple[str, str, float]] = {}
# iDRAC sessions often default to 30 min; keep shorter to be safe
SESSION_TTL_SECONDS = int(os.environ.get("IDRAC_SESSION_TTL", "1200"))

def _requests_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "DELETE"],
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    return s


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return cfg


def _get_host_creds(cfg: Dict[str, Any], target: str) -> Tuple[str, str]:
    hosts = cfg.get("hosts", {}) or {}
    default = hosts.get("default", {}) or {}
    specific = hosts.get(str(target), {}) or {}

    user = specific.get("username") or default.get("username")
    pw = specific.get("password") or default.get("password")
    if not user or not pw:
        raise ValueError(f"Missing credentials for target={target} (no default or host entry)")
    return str(user), str(pw)


def _base_url(target: str) -> str:
    # iDRAC Redfish usually on https://<ip>
    return f"https://{target}"


def _now() -> float:
    return time.time()


class RedfishClient:
    def __init__(self, target: str, username: str, password: str, timeout: int = DEFAULT_TIMEOUT):
        self.target = target
        self.username = username
        self.password = password
        self.timeout = timeout
        self.base = _base_url(target)
        self.http = _requests_session()

    def _headers(self) -> Dict[str, str]:
        token_tuple = _SESSION_CACHE.get(self.target)
        if token_tuple:
            token, _loc, exp = token_tuple
            if _now() < exp:
                return {"X-Auth-Token": token}
        return {}

    def _create_session(self) -> None:
        # If valid cached token exists, keep it
        token_tuple = _SESSION_CACHE.get(self.target)
        if token_tuple and _now() < token_tuple[2]:
            return

        url = f"{self.base}/redfish/v1/SessionService/Sessions"
        payload = {"UserName": self.username, "Password": self.password}

        resp = self.http.post(
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=self.timeout,
            verify=False,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"CreateSession failed: {resp.status_code} {resp.text[:200]}")

        token = resp.headers.get("X-Auth-Token")
        loc = resp.headers.get("Location", "")
        if not token:
            raise RuntimeError("CreateSession succeeded but no X-Auth-Token returned")

        _SESSION_CACHE[self.target] = (token, loc, _now() + SESSION_TTL_SECONDS)

    def _delete_session(self) -> None:
        token_tuple = _SESSION_CACHE.get(self.target)
        if not token_tuple:
            return
        token, loc, _exp = token_tuple
        if not loc:
            return
        url = f"{self.base}{loc}"
        try:
            self.http.delete(url, headers={"X-Auth-Token": token}, timeout=self.timeout, verify=False)
        finally:
            _SESSION_CACHE.pop(self.target, None)

    def get(self, path: str) -> Dict[str, Any]:
        # path can be full @odata.id or absolute https URL
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        elif path.startswith("/"):
            url = f"{self.base}{path}"
        else:
            url = f"{self.base}/{path}"

        # Always prefer session auth; fallback to basic if needed
        try:
            self._create_session()
            resp = self.http.get(url, headers=self._headers(), timeout=self.timeout, verify=False)
            if resp.status_code == 401:
                # try basic auth once
                resp = self.http.get(url, auth=(self.username, self.password), timeout=self.timeout, verify=False)
        except Exception:
            # last resort basic auth
            resp = self.http.get(url, auth=(self.username, self.password), timeout=self.timeout, verify=False)

        if resp.status_code >= 400:
            raise RuntimeError(f"GET {url} failed: {resp.status_code}")

        return resp.json()

    def pick_first_member(self, collection_path: str) -> str:
        col = self.get(collection_path)
        members = col.get("Members") or []
        if not members:
            raise RuntimeError(f"No Members in {collection_path}")
        mid = members[0].get("@odata.id")
        if not mid:
            raise RuntimeError(f"Member missing @odata.id in {collection_path}")
        return mid


def _health_to_status(health_obj: Any) -> str:
    # Redfish typically: {"Health":"OK","HealthRollup":"OK","State":"Enabled"}
    if isinstance(health_obj, dict):
        h = health_obj.get("Health") or health_obj.get("HealthRollup") or health_obj.get("State")
        return str(h) if h is not None else "N/A"
    if isinstance(health_obj, str):
        return health_obj
    return "N/A"


def _truthy_state(v: Any) -> int:
    if v is True:
        return 1
    if v is False or v is None:
        return 0
    s = str(v).strip().lower()
    return 1 if s in ("on", "true", "enabled", "up") else 0


def _safe_label(v: Any) -> str:
    if v is None:
        return "N/A"
    s = str(v)
    return s[:200]


def collect_all_metrics(target: str, cfg: Dict[str, Any], registry: CollectorRegistry) -> None:
    username, password = _get_host_creds(cfg, target)
    timeout = int(cfg.get("timeout", DEFAULT_TIMEOUT))
    rf = RedfishClient(target=target, username=username, password=password, timeout=timeout)

    # --- Common metrics (up) ---
    up = Gauge("idrac_redfish_up", "Redfish scrape success (1=up, 0=down)", ["target"], registry=registry)
    scrape_seconds = Gauge("idrac_redfish_scrape_seconds", "Scrape duration seconds", ["target"], registry=registry)

    start = _now()
    try:
        root = rf.get("/redfish/v1")
        up.labels(target=target).set(1)
    except Exception:
        up.labels(target=target).set(0)
        scrape_seconds.labels(target=target).set(_now() - start)
        raise
    finally:
        scrape_seconds.labels(target=target).set(_now() - start)

    # Resolve System + Chassis + Manager (best-effort)
    sys_id = None
    chassis_id = None

    try:
        sys_id = rf.pick_first_member("/redfish/v1/Systems")
    except Exception:
        pass

    try:
        chassis_id = rf.pick_first_member("/redfish/v1/Chassis")
    except Exception:
        pass

    # --- System: machine info / bios / health / power / indicator LED ---
    g_system_health = Gauge("idrac_system_health", "System health state", ["status"], registry=registry)
    g_bios = Gauge("idrac_system_bios_info", "BIOS version info", ["version"], registry=registry)
    g_machine = Gauge(
        "idrac_system_machine_info",
        "System machine info (labels only)",
        ["manufacturer", "model", "serial", "sku"],
        registry=registry,
    )
    g_mem_size = Gauge("idrac_system_memory_size_bytes", "System memory size in bytes", registry=registry)
    g_cpu_count = Gauge("idrac_system_cpu_count", "CPU count", registry=registry)
    g_indicator = Gauge("idrac_system_indicator_led_on", "Indicator LED state (label state)", ["state"], registry=registry)
    g_power_on = Gauge("idrac_system_power_on", "System power on (1=on, 0=off)", registry=registry)

    if sys_id:
        sys_obj = rf.get(sys_id)

        status = _health_to_status((sys_obj.get("Status") or {}))
        g_system_health.labels(status=_safe_label(status)).set(1)

        bios = sys_obj.get("BiosVersion") or sys_obj.get("BIOSVersion")
        if bios:
            g_bios.labels(version=_safe_label(bios)).set(1)

        manufacturer = sys_obj.get("Manufacturer")
        model = sys_obj.get("Model")
        serial = sys_obj.get("SerialNumber")
        sku = sys_obj.get("SKU") or sys_obj.get("PartNumber") or "N/A"
        g_machine.labels(
            manufacturer=_safe_label(manufacturer),
            model=_safe_label(model),
            serial=_safe_label(serial),
            sku=_safe_label(sku),
        ).set(1)

        # TotalMemoryMiB 
        mem_mib = sys_obj.get("MemorySummary", {}).get("TotalSystemMemoryGiB")
        if mem_mib is not None:
            # GiB
            try:
                g_mem_size.set(float(mem_mib) * 1024 * 1024 * 1024)
            except Exception:
                pass
        else:
            total_mib = sys_obj.get("TotalSystemMemoryMiB")
            if total_mib is not None:
                try:
                    g_mem_size.set(float(total_mib) * 1024 * 1024)
                except Exception:
                    pass

        cpu_cnt = sys_obj.get("ProcessorSummary", {}).get("Count")
        if cpu_cnt is None:
            cpu_cnt = sys_obj.get("ProcessorSummary", {}).get("LogicalProcessorCount")
        if cpu_cnt is not None:
            try:
                g_cpu_count.set(float(cpu_cnt))
            except Exception:
                pass

        # Power state is often "On"/"Off"
        pstate = sys_obj.get("PowerState")
        g_power_on.set(1 if str(pstate).lower() == "on" else 0)

        # Indicator LED: "Lit", "Blinking", "Off"
        led = sys_obj.get("IndicatorLED") or "N/A"
        # prefer a stable label and use value for on/off
        g_indicator.labels(state=_safe_label(led)).set(1 if str(led).lower() not in ("off", "unknown", "n/a") else 0)

    # --- Sensors: thermal + fans ---
    g_temp = Gauge("idrac_sensors_temperature", "Temperature sensors (C)", ["name"], registry=registry)
    g_fan = Gauge("idrac_sensors_fan_speed", "Fan sensors (RPM)", ["name"], registry=registry)

    if chassis_id:
        # Thermal
        try:
            thermal = rf.get(f"{chassis_id}/Thermal")
            temps = thermal.get("Temperatures") or []
            for t in temps:
                name = t.get("Name") or t.get("SensorNumber") or "Temp"
                val = t.get("ReadingCelsius")
                if val is None:
                    continue
                g_temp.labels(name=_safe_label(name)).set(float(val))

            fans = thermal.get("Fans") or []
            for f in fans:
                name = f.get("Name") or f.get("FanName") or f.get("MemberId") or "Fan"
                rpm = f.get("Reading") or f.get("ReadingRPM") or f.get("ReadingRpm")
                if rpm is None:
                    continue
                g_fan.labels(name=_safe_label(name)).set(float(rpm))
        except Exception:
            pass

    # --- Power: PSU + power control ---
    g_psu_out = Gauge("idrac_power_supply_output_watts", "PSU output watts", ["id"], registry=registry)
    g_psu_in = Gauge("idrac_power_supply_input_watts", "PSU input watts", ["id"], registry=registry)
    g_psu_vin = Gauge("idrac_power_supply_input_voltage", "PSU input voltage", ["id"], registry=registry)

    g_pwr_avg = Gauge("idrac_power_control_avg_consumed_watts", "Power avg consumed watts", ["name"], registry=registry)
    g_pwr_cap = Gauge("idrac_power_control_capacity_watts", "Power capacity watts", ["id"], registry=registry)

    if chassis_id:
        try:
            power = rf.get(f"{chassis_id}/Power")
            # PowerSupplies array
            psus = power.get("PowerSupplies") or []
            for psu in psus:
                pid = psu.get("MemberId") or psu.get("Name") or psu.get("SerialNumber") or "0"
                outw = psu.get("PowerOutputWatts")
                inw = psu.get("PowerInputWatts")
                vin = psu.get("LineInputVoltage")
                if outw is not None:
                    g_psu_out.labels(id=_safe_label(pid)).set(float(outw))
                if inw is not None:
                    g_psu_in.labels(id=_safe_label(pid)).set(float(inw))
                if vin is not None:
                    g_psu_vin.labels(id=_safe_label(pid)).set(float(vin))

            # PowerControl array (often includes total avg/capacity)
            pctrl = power.get("PowerControl") or []
            for pc in pctrl:
                name = pc.get("Name") or pc.get("MemberId") or "0"
                avg = pc.get("PowerConsumedWatts")
                cap = pc.get("PowerCapacityWatts")
                if avg is not None:
                    g_pwr_avg.labels(name=_safe_label(name)).set(float(avg))
                if cap is not None:
                    # dashboard asks id="0" in one panel; keep MemberId as id if present
                    pc_id = pc.get("MemberId") or "0"
                    g_pwr_cap.labels(id=_safe_label(pc_id)).set(float(cap))
        except Exception:
            pass

    # --- Storage: drives ---
    g_drive_info = Gauge(
        "idrac_storage_drive_info",
        "Drive info (labels only)",
        ["id", "slot", "manufacturer", "mediatype", "model", "protocol", "serial", "status"],
        registry=registry,
    )
    g_drive_health = Gauge("idrac_storage_drive_health", "Drive health (label status)", ["id", "status"], registry=registry)
    g_drive_cap = Gauge("idrac_storage_drive_capacity_bytes", "Drive capacity bytes", ["id"], registry=registry)

    if sys_id:
        try:
            storage_col = rf.get(f"{sys_id}/Storage")
            controllers = storage_col.get("Members") or []
            for ctrl in controllers:
                ctrl_id = ctrl.get("@odata.id")
                if not ctrl_id:
                    continue
                ctrl_obj = rf.get(ctrl_id)
                drives = ctrl_obj.get("Drives") or []
                for d in drives:
                    did = d.get("@odata.id")
                    if not did:
                        continue
                    dobj = rf.get(did)
                    drive_id = dobj.get("Id") or dobj.get("SerialNumber") or did.split("/")[-1]

                    slot = dobj.get("PhysicalLocation", {}).get("PartLocation", {}).get("ServiceLabel") \
                        or dobj.get("LocationIndicatorActive") \
                        or dobj.get("Name") \
                        or "N/A"

                    manufacturer = dobj.get("Manufacturer")
                    mediatype = dobj.get("MediaType")
                    model = dobj.get("Model")
                    protocol = dobj.get("Protocol")
                    serial = dobj.get("SerialNumber")

                    status = _health_to_status(dobj.get("Status") or {})
                    g_drive_info.labels(
                        id=_safe_label(drive_id),
                        slot=_safe_label(slot),
                        manufacturer=_safe_label(manufacturer),
                        mediatype=_safe_label(mediatype),
                        model=_safe_label(model),
                        protocol=_safe_label(protocol),
                        serial=_safe_label(serial),
                        status=_safe_label(status),
                    ).set(1)

                    g_drive_health.labels(id=_safe_label(drive_id), status=_safe_label(status)).set(1)

                    cap = dobj.get("CapacityBytes")
                    if cap is not None:
                        g_drive_cap.labels(id=_safe_label(drive_id)).set(float(cap))
        except Exception:
            pass

    # --- Memory modules ---
    g_mem_info = Gauge(
        "idrac_memory_module_info",
        "Memory module info (labels only)",
        ["id", "name", "manufacturer", "serial", "type", "rank", "ecc", "status"],
        registry=registry,
    )
    g_mem_health = Gauge("idrac_memory_module_health", "Memory module health", ["id", "status"], registry=registry)
    g_mem_cap = Gauge("idrac_memory_module_capacity_bytes", "Memory module capacity bytes", ["id"], registry=registry)
    g_mem_speed = Gauge("idrac_memory_module_speed_mhz", "Memory module speed MHz", ["id"], registry=registry)

    if sys_id:
        try:
            mem_col = rf.get(f"{sys_id}/Memory")
            members = mem_col.get("Members") or []
            for m in members:
                mid = m.get("@odata.id")
                if not mid:
                    continue
                mobj = rf.get(mid)
                mem_id = mobj.get("Id") or mid.split("/")[-1]
                name = mobj.get("Name") or mem_id
                manufacturer = mobj.get("Manufacturer")
                serial = mobj.get("SerialNumber")
                mtype = mobj.get("MemoryDeviceType") or mobj.get("BaseModuleType") or "N/A"
                rank = mobj.get("RankCount") or "N/A"
                ecc = mobj.get("ErrorCorrection") or "N/A"
                status = _health_to_status(mobj.get("Status") or {})

                g_mem_info.labels(
                    id=_safe_label(mem_id),
                    name=_safe_label(name),
                    manufacturer=_safe_label(manufacturer),
                    serial=_safe_label(serial),
                    type=_safe_label(mtype),
                    rank=_safe_label(rank),
                    ecc=_safe_label(ecc),
                    status=_safe_label(status),
                ).set(1)

                g_mem_health.labels(id=_safe_label(mem_id), status=_safe_label(status)).set(1)

                cap = mobj.get("CapacityMiB")
                if cap is not None:
                    g_mem_cap.labels(id=_safe_label(mem_id)).set(float(cap) * 1024 * 1024)

                spd = mobj.get("OperatingSpeedMhz") or mobj.get("OperatingSpeedMHz")
                if spd is not None:
                    g_mem_speed.labels(id=_safe_label(mem_id)).set(float(spd))
        except Exception:
            pass

    # --- Network: adapter + ports ---
    g_net_port_health = Gauge("idrac_network_port_health", "Network port health", ["id", "status"], registry=registry)
    g_net_link = Gauge("idrac_network_port_link_up", "Network port link up (1=up)", ["id", "name"], registry=registry)
    g_net_speed = Gauge("idrac_network_port_current_speed_mbps", "Network port speed Mbps", ["id", "name"], registry=registry)
    g_net_adapter_health = Gauge("idrac_network_adapter_health", "Network adapter health", ["id", "status"], registry=registry)

    if sys_id:
        try:
            nics = rf.get(f"{sys_id}/NetworkInterfaces")
            members = nics.get("Members") or []
            for nic in members:
                nic_id = nic.get("@odata.id")
                if not nic_id:
                    continue
                nic_obj = rf.get(nic_id)
                nic_name = nic_obj.get("Name") or nic_obj.get("Id") or nic_id.split("/")[-1]
                nic_status = _health_to_status(nic_obj.get("Status") or {})
                g_net_adapter_health.labels(id=_safe_label(nic_name), status=_safe_label(nic_status)).set(1)

                # Ports can be under NetworkPorts or Ports depending on implementation
                ports_ref = nic_obj.get("NetworkPorts") or nic_obj.get("Ports")
                if isinstance(ports_ref, dict) and ports_ref.get("@odata.id"):
                    ports_col = rf.get(ports_ref["@odata.id"])
                    ports = ports_col.get("Members") or []
                    for p in ports:
                        pid_ref = p.get("@odata.id")
                        if not pid_ref:
                            continue
                        pobj = rf.get(pid_ref)
                        pid = pobj.get("Id") or pobj.get("Name") or pid_ref.split("/")[-1]
                        pname = pobj.get("Name") or pid

                        pstatus = _health_to_status(pobj.get("Status") or {})
                        g_net_port_health.labels(id=_safe_label(pid), status=_safe_label(pstatus)).set(1)

                        link = pobj.get("LinkStatus") or pobj.get("LinkState") or pobj.get("LinkUp")
                        # Normalize to 1/0
                        link_up = 1 if str(link).lower() in ("up", "true", "1", "linkup") else 0
                        g_net_link.labels(id=_safe_label(pid), name=_safe_label(pname)).set(link_up)

                        speed = pobj.get("CurrentLinkSpeedMbps") or pobj.get("CurrentSpeedMbps")
                        if speed is not None:
                            g_net_speed.labels(id=_safe_label(pid), name=_safe_label(pname)).set(float(speed))
        except Exception:
            pass

    # --- Event log (SEL): dashboard expects timestamp as sample value ---
    g_sel = Gauge(
        "idrac_events_log_entry",
        "SEL/event log entry timestamp (seconds since epoch); labels carry message/severity/id",
        ["id", "severity", "message"],
        registry=registry,
    )

    # Try Managers -> LogServices first
    try:
        mgr = rf.pick_first_member("/redfish/v1/Managers")
        mgr_obj = rf.get(mgr)
        logsvc = mgr_obj.get("LogServices")
        if isinstance(logsvc, dict) and logsvc.get("@odata.id"):
            logsvc_col = rf.get(logsvc["@odata.id"])
            services = logsvc_col.get("Members") or []
            # pick a likely SEL / SystemEventLog
            sel_svc = None
            for s in services:
                sid = s.get("@odata.id")
                if not sid:
                    continue
                sobj = rf.get(sid)
                name = (sobj.get("Name") or "").lower()
                if "sel" in name or "system" in name or "event" in name:
                    sel_svc = sobj
                    break
            if sel_svc is None and services:
                sel_svc = rf.get(services[0]["@odata.id"])

            if sel_svc and isinstance(sel_svc, dict):
                entries_ref = sel_svc.get("Entries")
                if isinstance(entries_ref, dict) and entries_ref.get("@odata.id"):
                    entries = rf.get(entries_ref["@odata.id"])
                    members = entries.get("Members") or []
                    # cap to prevent label explosion
                    members = members[:50]
                    for e in members:
                        eid_ref = e.get("@odata.id")
                        if not eid_ref:
                            continue
                        eobj = rf.get(eid_ref)
                        eid = str(eobj.get("Id") or eobj.get("EntryCode") or eid_ref.split("/")[-1])
                        sev = str(eobj.get("Severity") or "N/A")
                        msg = str(eobj.get("Message") or eobj.get("MessageId") or "N/A")

                        # Created timestamp to epoch seconds
                        created = eobj.get("Created") or eobj.get("CreatedTime") or eobj.get("EventTimestamp")
                        ts = None
                        if created:
                            # Parse Redfish ISO8601-ish; fallback to now if parsing fails
                            # Examples: 2026-01-14T08:38:49-06:00
                            try:
                                # Minimal parser: strip timezone, parse as struct_time in local-ish, then treat as epoch.
                                # For dashboard range comparisons, relative order matters more than perfect TZ handling.
                                m = re.match(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})", str(created))
                                if m:
                                    dt = f"{m.group(1)} {m.group(2)}"
                                    ts = time.mktime(time.strptime(dt, "%Y-%m-%d %H:%M:%S"))
                            except Exception:
                                ts = None
                        if ts is None:
                            ts = _now()

                        g_sel.labels(id=_safe_label(eid), severity=_safe_label(sev), message=_safe_label(msg)).set(float(ts))
    except Exception:
        pass


def _http_response(start_response, status: str, headers: List[Tuple[str, str]], body: bytes):
    start_response(status, headers)
    return [body]


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    if path == "/health":
        return _http_response(
            start_response,
            "200 OK",
            [("Content-Type", "text/plain; charset=utf-8")],
            b"ok\n",
        )

    if path != "/metrics":
        return _http_response(
            start_response,
            "404 Not Found",
            [("Content-Type", "text/plain; charset=utf-8")],
            b"not found\n",
        )

    # Parse query string for target=
    qs = environ.get("QUERY_STRING", "")
    params = {}
    for part in qs.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params.setdefault(k, []).append(v)
        else:
            params.setdefault(part, []).append("")

    target_vals = params.get("target", [])
    if not target_vals:
        return _http_response(
            start_response,
            "400 Bad Request",
            [("Content-Type", "text/plain; charset=utf-8")],
            b"missing required query param: target\n",
        )

    target = target_vals[0]

    # Build per-request registry (multi-target exporter pattern)
    registry = CollectorRegistry()
    try:
        cfg = _load_config()
        collect_all_metrics(target=target, cfg=cfg, registry=registry)
        output = generate_latest(registry)
        return _http_response(
            start_response,
            "200 OK",
            [("Content-Type", CONTENT_TYPE_LATEST)],
            output,
        )
    except Exception as e:
        # Exporter should still return 200 with some metrics OR return 500. Here: 500 with explanation.
        msg = f"scrape failed for target={target}: {e}\n".encode("utf-8")
        return _http_response(
            start_response,
            "500 Internal Server Error",
            [("Content-Type", "text/plain; charset=utf-8")],
            msg,
        )

from urllib.parse import parse_qs
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST

async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    path = scope.get("path", "/")
    query_string = (scope.get("query_string") or b"").decode("utf-8", errors="ignore")
    qs = parse_qs(query_string)

    if path == "/health":
        body = b"ok\n"
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": body})
        return

    if path != "/metrics":
        body = b"not found\n"
        await send({
            "type": "http.response.start",
            "status": 404,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": body})
        return

    targets = qs.get("target", [])
    if not targets:
        body = b"missing required query param: target\n"
        await send({
            "type": "http.response.start",
            "status": 400,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": body})
        return

    target = targets[0]

    registry = CollectorRegistry()
    try:
        cfg = _load_config()
        collect_all_metrics(target=target, cfg=cfg, registry=registry)
        output = generate_latest(registry)

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", CONTENT_TYPE_LATEST.encode("utf-8"))],
        })
        await send({"type": "http.response.body", "body": output})
    except Exception as e:
        msg = f"scrape failed for target={target}: {e}\n".encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 500,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": msg})
