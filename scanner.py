"""
DEVICE SCANNER v3.0
====================
Detection methods:
  1. pywifi        — WiFi SSIDs (hotspots + routers)
  2. Windows BT    — Bluetooth classic + BLE (paired/discoverable)
  3. bleak         — BLE passive scan (non-discoverable phones, earbuds, watches)
  4. scapy ARP     — All devices on your same local network
  5. ESP32 serial  — WiFi probe requests + BLE from ESP32 sensor

Install requirements:
  pip install pywifi bleak scapy pyserial comtypes

Run in two terminals:
  Terminal 1:  python scanner.py
  Terminal 2:  python -m http.server 8000
  Browser:     http://localhost:8000/dashboard.html

ESP32 setup:
  - Flash esp32_sensor.ino via Arduino IDE
  - Connect ESP32 via USB, find its COM port in Device Manager
  - Set ESP32_PORT below (e.g. "COM3")
"""

import asyncio
import json
import subprocess
import threading
import time
from datetime import datetime

# ── Optional imports — scanner keeps running even if not installed ──────
try:
    import pywifi
    PYWIFI_OK = True
except ImportError:
    PYWIFI_OK = False
    print("[WARN] pywifi not installed — WiFi SSID scan disabled")

try:
    from bleak import BleakScanner
    BLEAK_OK = True
except ImportError:
    BLEAK_OK = False
    print("[WARN] bleak not installed  — BLE passive scan disabled")
    print("       Run:  pip install bleak")

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[WARN] scapy not installed  — ARP network scan disabled")
    print("       Run:  pip install scapy")

try:
    import serial
    import serial.tools.list_ports
    SERIAL_OK = True
except ImportError:
    SERIAL_OK = False
    print("[WARN] pyserial not installed — ESP32 scan disabled")
    print("       Run:  pip install pyserial")

# ── ESP32 CONFIG ────────────────────────────────────────────────────────
# Set this to your ESP32's COM port. Leave as None to auto-detect.
# Find it in Windows Device Manager → Ports (COM & LPT)
ESP32_PORT = None   # e.g. "COM3"  ← change this if auto-detect fails
ESP32_BAUD = 115200

# ── ARP CONFIG ──────────────────────────────────────────────────────────
# Your local network range. Change the first 3 numbers to match your
# router's IP (e.g. if router is 192.168.0.1 → use "192.168.0.0/24")
ARP_NETWORK = "10.5.79.0/24"


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def estimate_distance(rssi, tx_power=-59, n=2.7):
    if rssi == 0:
        return -1
    return round(10 ** ((tx_power - rssi) / (10 * n)), 1)

def signal_quality(rssi):
    if rssi >= -50: return "Excellent"
    elif rssi >= -60: return "Good"
    elif rssi >= -70: return "Fair"
    elif rssi >= -80: return "Weak"
    else: return "Very Weak"


# ═══════════════════════════════════════════════════════════════════════
# CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════

HOTSPOT_BRAND_KEYWORDS = [
    "iphone", "samsung", "oppo", "vivo", "realme", "redmi", "xiaomi",
    "oneplus", "poco", "motorola", "nokia", "huawei", "honor", "pixel",
    "infinix", "tecno", "lava", "micromax", "iqoo", "nothing", "moto",
    "android", "phone", "hotspot", "mobile data",
]
HOTSPOT_SUFFIXES = ["_4g", "-4g", " 4g", "_5g", "-5g", " 5g", "_4g+", "-4g+"]

ROUTER_BRAND_KEYWORDS = [
    "router", "dlink", "tplink", "tp-link", "d-link", "netgear",
    "linksys", "asus", "ubiquiti", "unifi", "mikrotik", "cisco",
    "jiofiber", "jio_fiber", "hathway", "airfiber", "broadband",
    "fiber", "fibre", "ftth", "gateway", "modem", "tsbb", "c2j",
    "access_point", "_ext", "_mesh",
]
ROUTER_ISP_PREFIXES = [
    "airtel_", "jio_", "bsnl_", "hathway_", "act_", "excitel_",
    "you_", "tikona_", "spectranet_",
]

def identify_wifi_type(name):
    if not name or name == "Hidden Network":
        return "other"
    n = name.lower().strip()
    if any(k in n for k in HOTSPOT_BRAND_KEYWORDS):
        return "mobile"
    if any(n.endswith(s) for s in HOTSPOT_SUFFIXES):
        return "mobile"
    if any(k in n for k in ROUTER_BRAND_KEYWORDS):
        return "router"
    if any(n.startswith(p) for p in ROUTER_ISP_PREFIXES):
        return "router"
    words = n.replace("_", " ").replace("-", " ").split()
    has_digits = any(c.isdigit() for c in n)
    if len(words) <= 3 and not has_digits and len(n) <= 22:
        return "mobile"
    return "other"

def identify_bt_type(name):
    n = name.lower()
    if any(k in n for k in [
        "iphone", "samsung", "oppo", "vivo", "realme", "redmi", "xiaomi",
        "oneplus", "poco", "motorola", "pixel", "android", "phone",
        "infinix", "tecno", "nothing", "moto", "iqoo",
    ]):
        return "mobile"
    if any(k in n for k in [
        "macbook", "laptop", "dell", "lenovo", "thinkpad",
        "surface", "acer", "ideapad", "vivobook", "zenbook",
    ]):
        return "laptop"
    if any(k in n for k in [
        "airpods", "buds", "headphone", "earphone", "speaker",
        "jbl", "sony", "boat", "earbuds", "wf-", "wh-", "headset",
        "bose", "portronics", "soundcore", "boult", "mivi",
        "avrcp", "a2dp", "oblivion", "audio",
    ]):
        return "audio"
    if any(k in n for k in [
        "watch", "band", "amazfit", "fireboltt", "fastrack", "noise",
        "titan", "gear",
    ]):
        return "wearable"
    if any(k in n for k in [
        "keyboard", "mouse", "controller", "joystick", "gamepad",
    ]):
        return "peripheral"
    if any(k in n for k in [
        "phonebook access", "personal area network", "generic access",
        "device information service", "hands-free", "serial port",
        "pbap", "hts001", "pan service", "hid service",
    ]):
        return "bt_service"
    return "unknown"


# ═══════════════════════════════════════════════════════════════════════
# SCANNER 1 — pywifi (WiFi SSIDs: hotspots + routers)
# ═══════════════════════════════════════════════════════════════════════

def scan_wifi():
    """
    Scans for WiFi SSIDs being broadcast nearby.
    FIX: Creates fresh PyWiFi() every scan — reusing the same object causes
    Windows to invalidate the WlanApi handle after ~20 cycles ("Open handle
    failed"). Also silences pywifi's noisy logger and retries once on fail.
    """
    if not PYWIFI_OK:
        return []
    import logging
    logging.getLogger("pywifi").setLevel(logging.CRITICAL)

    def _do_scan():
        w = pywifi.PyWiFi()          # fresh object every call
        iface = w.interfaces()[0]
        iface.scan()
        time.sleep(3)
        return iface.scan_results()

    results = []
    try:
        results = _do_scan()
    except Exception:
        try:
            time.sleep(1)
            results = _do_scan()   # retry once
        except Exception as e:
            print(f"  [WiFi Error] {e}")
            return []

    seen = {}
    for r in results:
        if r.bssid not in seen or r.signal > seen[r.bssid].signal:
            seen[r.bssid] = r

    devices = []
    for d in seen.values():
        freq_mhz = d.freq / 1000
        freq_ghz = round(freq_mhz / 1000, 2)
        band     = "5 GHz" if freq_mhz > 4000 else "2.4 GHz"
        name     = d.ssid.strip() if d.ssid and d.ssid.strip() else "Hidden Network"
        devices.append({
            "name":           name,
            "mac":            d.bssid,
            "rssi":           d.signal,
            "distance":       estimate_distance(d.signal),
            "signal_quality": signal_quality(d.signal),
            "freq":           freq_ghz,
            "band":           band,
            "source":         "wifi",
            "type":           identify_wifi_type(name),
        })
    return devices


# ═══════════════════════════════════════════════════════════════════════
# SCANNER 2 — Windows Bluetooth API (classic BT + BLE, paired/discoverable)
# ═══════════════════════════════════════════════════════════════════════

def scan_bluetooth_windows():
    """
    Uses Windows Runtime API via PowerShell.
    Finds Bluetooth Classic and BLE devices Windows has discovered.

    FIX: Windows registers every BT device AND its service profiles separately.
    e.g. "Boult Audio" appears as:
      - "Boult Audio Airbass"
      - "Boult Audio Airbass Avrcp Transport"
      - "Boult Audio Airbass Avrcp Transport"  (another entry)
    We strip all known service suffixes BEFORE storing, then deduplicate
    by the cleaned base name so only ONE entry per real device remains.

    FIX: WinBT returns Windows cached devices (seen days ago, now offline).
    These get a short TTL unless BLE also confirms them this cycle.
    """
    # All known Windows BT service suffixes to strip
    SERVICE_SUFFIXES = [
        " avrcp transport", " avrcp", " a2dp sink", " a2dp source", " a2dp",
        " hid service", " handsfree", " hands-free", " hands free",
        " phonebook access pse service", " phonebook access pse",
        " phonebook access", " pbap",
        " object push service", " object push",
        " headset audio gateway service", " headset audio gateway",
        " serial port service", " serial port",
        " personal area network service", " personal area network",
        " generic attribute profile", " generic access profile",
        " device information service", " device information",
        " rfcomm protocol tdi", " rfcomm",
        " pan service", " hts001",
        " service",
    ]
    # Entries whose FULL name matches these → skip entirely
    SKIP_ENTIRELY = [
        "bluetooth device", "generic attribute", "rfcomm",
        "phonebook access", "object push", "headset audio gateway",
        "personal area network", "device information", "serial port",
        "hands-free", "bluetooth peripheral", "a2dp sink", "a2dp source",
    ]

    def clean_name(raw):
        n = raw.strip()
        nl = n.lower()
        for sfx in SERVICE_SUFFIXES:
            if nl.endswith(sfx):
                n  = n[:len(n)-len(sfx)].strip()
                nl = n.lower()
        return n

    def should_skip(name):
        nl = name.lower()
        return any(s in nl for s in SKIP_ENTIRELY)

    devices = []
    ps = """
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$null = [Windows.Devices.Bluetooth.BluetoothAdapter,Windows.Devices.Bluetooth,ContentType=WindowsRuntime]
$null = [Windows.Devices.Enumeration.DeviceInformation,Windows.Devices.Enumeration,ContentType=WindowsRuntime]
$m = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1
function Await($t,$r){ $task=$m.MakeGenericMethod($r); $n=$task.Invoke($null,@($t)); $n.Wait(-1)|Out-Null; $n.Result }
$bt  = Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync(
    [Windows.Devices.Enumeration.DeviceClass]::BluetoothClassicDevice
)) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Enumeration.DeviceInformation]])
$ble = Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync(
    [Windows.Devices.Enumeration.DeviceClass]::BluetoothLowEnergy
)) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Enumeration.DeviceInformation]])
(@($bt)+@($ble)) | ForEach-Object { if($_.Name){ Write-Output $_.Name } }
"""
    try:
        r = subprocess.run(["powershell", "-Command", ps],
                           capture_output=True, text=True, timeout=20)
        for line in r.stdout.strip().splitlines():
            raw = line.strip()
            if not raw or len(raw) <= 1:
                continue
            name = clean_name(raw)
            if not name or should_skip(name):
                continue
            dtype = identify_bt_type(name)
            if dtype == "bt_service":
                continue
            devices.append({
                "name":           name,
                "mac":            "BT",
                "rssi":           -65,
                "distance":       estimate_distance(-65),
                "signal_quality": "Good",
                "freq":           2.4,
                "band":           "Bluetooth",
                "source":         "bluetooth",
                "type":           dtype,
                "method":         "win_bt",
            })
    except Exception as e:
        print(f"  [WinBT Error] {e}")

    # Fallback via PnP
    if not devices:
        try:
            r = subprocess.run(
                ["powershell",
                 "Get-PnpDevice -Class Bluetooth | Select-Object Status,FriendlyName | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=10)
            raw = r.stdout.strip()
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                skip_hw = ["adapter","enumerator","radio","filter",
                           "bluetooth le","microsoft","intel","qualcomm","realtek"]
                for d in data:
                    raw_name = (d.get("FriendlyName") or "").strip()
                    if not raw_name or any(w in raw_name.lower() for w in skip_hw):
                        continue
                    name = clean_name(raw_name)
                    if not name or should_skip(name):
                        continue
                    dtype = identify_bt_type(name)
                    if dtype == "bt_service":
                        continue
                    rssi = -60 if d.get("Status") == "OK" else -85
                    devices.append({
                        "name":           name,
                        "mac":            "BT",
                        "rssi":           rssi,
                        "distance":       estimate_distance(rssi),
                        "signal_quality": signal_quality(rssi),
                        "freq":           2.4,
                        "band":           "Bluetooth",
                        "source":         "bluetooth",
                        "type":           dtype,
                        "method":         "win_pnp",
                    })
        except Exception as e:
            print(f"  [WinBT Fallback Error] {e}")

    # Deduplicate by cleaned name — keeps highest RSSI per device
    seen = {}
    for d in devices:
        key = d["name"].lower()
        if key not in seen or d["rssi"] > seen[key]["rssi"]:
            seen[key] = d
    return list(seen.values())


# ═══════════════════════════════════════════════════════════════════════
# SCANNER 3 — bleak BLE passive scan (non-discoverable devices)
# ═══════════════════════════════════════════════════════════════════════

async def _bleak_scan_async(duration=8.0):
    """
    Passive BLE advertisement scan. Duration=8s gives more time to catch
    phones that advertise at slow intervals (100ms-500ms for background BLE).
    """
    seen = {}

    def callback(device, adv_data):
        mac  = device.address
        rssi = adv_data.rssi if adv_data.rssi is not None else -100
        if mac not in seen or rssi > (seen[mac][1].rssi or -100):
            seen[mac] = (device, adv_data)

    try:
        async with BleakScanner(detection_callback=callback):
            await asyncio.sleep(duration)
    except Exception as e:
        raise RuntimeError(str(e))

    devices = []
    for mac, (d, adv) in seen.items():
        rssi  = adv.rssi if adv.rssi is not None else -80
        name  = (d.name or adv.local_name or "").strip()

        if not name:
            # Unnamed but within ~6m → almost certainly a phone (privacy mode)
            # Your phone at -52 dBm right next to you WILL pass this check
            if rssi >= -80:
                name  = f"Unknown BLE [{mac[-5:]}]"
                dtype = "mobile"
            else:
                continue   # unnamed + far away = background noise
        else:
            dtype = identify_bt_type(name)
            if dtype == "bt_service":
                continue

        devices.append({
            "name":           name,
            "mac":            mac,
            "rssi":           rssi,
            "distance":       estimate_distance(rssi),
            "signal_quality": signal_quality(rssi),
            "freq":           2.4,
            "band":           "Bluetooth",
            "source":         "bluetooth",
            "type":           dtype,
            "method":         "ble_passive",
        })
    return devices


def scan_ble():
    """
    Synchronous BLE wrapper.
    FIX: CoInitialize() sets COM to MTA in the worker thread — required for
    WinRT Bluetooth callbacks to fire. Without this bleak silently fails
    on Windows STA threads.
    """
    if not BLEAK_OK:
        return []

    result_holder = []
    error_holder  = []

    def _thread():
        com_ok = False
        try:
            import pythoncom
            pythoncom.CoInitialize()
            com_ok = True
        except ImportError:
            pass
        try:
            result_holder.extend(asyncio.run(_bleak_scan_async()))
        except Exception as e:
            error_holder.append(str(e))
        finally:
            if com_ok:
                try:
                    import pythoncom
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    t.join(timeout=25)   # 8s scan + COM + margin

    if t.is_alive():
        print("  [BLE Warning] Scan timed out")
        return []
    if error_holder:
        print(f"  [BLE Error] {error_holder[0]}")
        return []
    return result_holder


# ═══════════════════════════════════════════════════════════════════════
# SCANNER 4 — scapy ARP scan (all devices on your local network)
# ═══════════════════════════════════════════════════════════════════════

def scan_arp():
    """
    Sends ARP broadcast packets to every IP in your local subnet.
    Any device that responds is on your network — reveals its IP + MAC.
    Detects: phones, laptops, smart TVs, IoT devices — anything connected
    to the same router as you, even if WiFi-only (not hotspot).

    Requires: pip install scapy
    Also needs Npcap installed: https://npcap.com/#download
    """
    if not SCAPY_OK:
        return []
    devices = []
    try:
        # Suppress scapy output
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ARP_NETWORK)
        result = srp(pkt, timeout=3, verbose=0)[0]

        for sent, received in result:
            ip  = received.psrc
            mac = received.hwsrc

            # Try to guess device type from MAC OUI (first 3 bytes)
            # This is a rough heuristic — MAC vendors are publicly registered
            mac_prefix = mac.upper().replace(":", "")[:6]
            dtype = guess_type_from_mac(mac_prefix)

            devices.append({
                "name":           ip,          # IP address as display name
                "mac":            mac,
                "rssi":           -60,          # ARP gives no RSSI — use placeholder
                "distance":       -1,           # unknown
                "signal_quality": "N/A",
                "freq":           0,
                "band":           "LAN",
                "source":         "arp",
                "type":           dtype,
                "method":         "arp",
                "ip":             ip,
            })
    except Exception as e:
        print(f"  [ARP Error] {e}")
        if "Npcap" in str(e) or "winpcap" in str(e).lower():
            print("  → Install Npcap from https://npcap.com/#download")
    return devices

# Rough MAC OUI → device type mapping
# OUI = first 6 hex digits of MAC, identifies the manufacturer
APPLE_OUIS    = {"A45E60","A8BB50","DC2B2A","F0D1A9","3C2EFF","706F81",
                 "B8FF61","ACE4B5","A82066","D4619D","3C15C2","A4B197"}
SAMSUNG_OUIS  = {"8CC84B","CCF9E8","549B12","A82066","FC5B39","8C71F8"}
GOOGLE_OUIS   = {"F488E2","3C5AB4","000000"}  # Pixel / Chromecast
AMAZON_OUIS   = {"40B4CD","0CB3EB","FC65DE"}
INTEL_OUIS    = {"8086F2","7085C2","A4C494"}  # common in laptops

def guess_type_from_mac(oui6):
    """Guess device type from MAC OUI prefix (first 6 hex chars, no colons)."""
    if oui6 in APPLE_OUIS:
        return "mobile"      # could be iPhone, iPad, Mac — call it mobile
    if oui6 in SAMSUNG_OUIS:
        return "mobile"
    if oui6 in GOOGLE_OUIS:
        return "mobile"
    if oui6 in AMAZON_OUIS:
        return "other"       # Echo, Fire TV, etc.
    if oui6 in INTEL_OUIS:
        return "laptop"
    return "other"


# ═══════════════════════════════════════════════════════════════════════
# SCANNER 5 — ESP32 serial reader
# ═══════════════════════════════════════════════════════════════════════

# Shared buffer — ESP32 reader thread writes here, main loop reads it
_esp32_buffer = []
_esp32_lock   = threading.Lock()
_esp32_thread = None

def _find_esp32_port():
    """Auto-detect ESP32 COM port by looking for Silicon Labs or CP210x USB-Serial."""
    if not SERIAL_OK:
        return None
    for port in serial.tools.list_ports.comports():
        desc = (port.description or "").lower()
        if any(k in desc for k in ["cp210", "ch340", "silicon labs", "esp32", "uart"]):
            return port.device
    return None

def _esp32_reader_thread(port, baud):
    """
    Background thread that continuously reads JSON lines from ESP32.
    ESP32 sends one JSON object per line, e.g.:
      {"type":"wifi_probe","mac":"AA:BB:CC:DD:EE:FF","rssi":-55,"ssid":"MyPhone"}
      {"type":"ble","mac":"11:22:33:44:55:66","rssi":-60,"name":"","adv_type":0}
    """
    import serial as ser_mod
    global _esp32_buffer
    print(f"  [ESP32] Connecting on {port} @ {baud} baud...")
    try:
        with ser_mod.Serial(port, baud, timeout=2) as s:
            print(f"  [ESP32] Connected ✓")
            while True:
                try:
                    line = s.readline().decode("utf-8", errors="ignore").strip()
                    if not line or not line.startswith("{"):
                        continue
                    obj = json.loads(line)
                    with _esp32_lock:
                        _esp32_buffer.append(obj)
                        # Keep buffer from growing unbounded
                        if len(_esp32_buffer) > 500:
                            _esp32_buffer = _esp32_buffer[-500:]
                except json.JSONDecodeError:
                    pass
                except Exception:
                    time.sleep(0.1)
    except Exception as e:
        print(f"  [ESP32] Connection failed: {e}")
        print(f"  [ESP32] Check COM port. Set ESP32_PORT manually in scanner.py")

def start_esp32_reader():
    """Start the ESP32 background reader thread."""
    global _esp32_thread
    if not SERIAL_OK:
        return
    port = ESP32_PORT or _find_esp32_port()
    if not port:
        print("  [ESP32] Not found — skipping. Plug in ESP32 and set ESP32_PORT if needed.")
        return
    _esp32_thread = threading.Thread(
        target=_esp32_reader_thread,
        args=(port, ESP32_BAUD),
        daemon=True
    )
    _esp32_thread.start()

def drain_esp32_buffer():
    """
    Read everything currently in the ESP32 buffer and convert to device records.
    Called once per scan cycle.
    """
    if not SERIAL_OK:
        return []

    with _esp32_lock:
        raw = list(_esp32_buffer)
        _esp32_buffer.clear()

    # Aggregate by MAC — keep strongest RSSI seen in this batch
    seen = {}
    for obj in raw:
        mac  = obj.get("mac", "")
        rssi = obj.get("rssi", -80)
        if not mac:
            continue
        if mac not in seen or rssi > seen[mac]["rssi"]:
            seen[mac] = obj

    devices = []
    for mac, obj in seen.items():
        pkt_type = obj.get("type", "")
        rssi     = obj.get("rssi", -80)
        name     = obj.get("name", "") or obj.get("ssid", "") or f"ESP-{mac[-5:].replace(':','')}"

        if pkt_type == "wifi_probe":
            # Phone actively looking for known WiFi networks → WiFi is ON
            ssid  = obj.get("ssid", "")
            label = f"WiFi probe" + (f": {ssid}" if ssid else "")
            devices.append({
                "name":           name if name != label else f"Phone [{mac[-8:]}]",
                "mac":            mac,
                "rssi":           rssi,
                "distance":       estimate_distance(rssi),
                "signal_quality": signal_quality(rssi),
                "freq":           2.4,
                "band":           "2.4 GHz",
                "source":         "esp32_wifi",
                "type":           "mobile",
                "method":         "esp32_probe",
            })

        elif pkt_type == "ble":
            # BLE advertisement from a nearby device
            dtype = identify_bt_type(name) if name else "mobile"
            if dtype == "bt_service":
                continue
            devices.append({
                "name":           name or f"BLE [{mac[-8:]}]",
                "mac":            mac,
                "rssi":           rssi,
                "distance":       estimate_distance(rssi),
                "signal_quality": signal_quality(rssi),
                "freq":           2.4,
                "band":           "Bluetooth",
                "source":         "esp32_ble",
                "type":           dtype,
                "method":         "esp32_ble",
            })

    return devices


# ═══════════════════════════════════════════════════════════════════════
# MERGE — combine all sources, deduplicate
# ═══════════════════════════════════════════════════════════════════════

def merge_devices(*device_lists):
    """
    Merge devices from multiple scanners.
    Deduplication priority:
      - Same MAC → keep the one with the strongest RSSI
      - Same name (no MAC) → keep the one with the strongest RSSI
    """
    by_mac  = {}   # mac → device
    by_name = {}   # name.lower() → device  (for BT devices with no real MAC)

    for devices in device_lists:
        for d in devices:
            mac  = d.get("mac", "")
            name = d.get("name", "").lower()
            rssi = d.get("rssi", -100)

            # Deduplicate by MAC if it's a real MAC (not "BT" placeholder)
            if mac and mac not in ("BT",):
                existing = by_mac.get(mac)
                if not existing or rssi > existing.get("rssi", -100):
                    by_mac[mac] = d
            else:
                # No real MAC — deduplicate by name
                existing = by_name.get(name)
                if not existing or rssi > existing.get("rssi", -100):
                    by_name[name] = d

    # Merge both dicts, preferring MAC-keyed entries when name collides
    result = list(by_mac.values())
    mac_names = {d["name"].lower() for d in result}
    for d in by_name.values():
        if d["name"].lower() not in mac_names:
            result.append(d)

    return result


# ═══════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("   DEVICE SCANNER v3.0")
    print("   WiFi · BLE · ARP · ESP32")
    print("=" * 60)
    print()
    print("  Active scanners:")
    print(f"    pywifi     {'✓' if PYWIFI_OK else '✗ (pip install pywifi)'}")
    print(f"    bleak BLE  {'✓' if BLEAK_OK  else '✗ (pip install bleak)'}")
    print(f"    scapy ARP  {'✓' if SCAPY_OK  else '✗ (pip install scapy + Npcap)'}")
    print(f"    pyserial   {'✓' if SERIAL_OK else '✗ (pip install pyserial)'}")
    print()
    print("  Terminal 2: python -m http.server 8000")
    print("  Browser:    http://localhost:8000/dashboard.html")
    print()

    # ── Wipe stale data from previous session on startup ──────────────
    # scan_data.json from a previous run would show old devices immediately.
    # We write a fresh empty payload with a new session_id so the dashboard
    # knows to clear its own client-side cache when the scanner restarts.
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open("scan_data.json", "w") as f:
        json.dump({
            "session_id":   session_id,
            "timestamp":    "--:--:--",
            "scan_number":  0,
            "total":        0,
            "wifi_count":   0,
            "bt_count":     0,
            "arp_count":    0,
            "mobile_count": 0,
            "router_count": 0,
            "nearby_count": 0,
            "devices":      [],
        }, f)
    print(f"  scan_data.json cleared (new session: {session_id})")
    print()

    # Start ESP32 background reader thread
    start_esp32_reader()

    scan_count = 0

    # Persistence cache — keeps devices visible for CACHE_TTL seconds
    # after last seen. Prevents blinking between cycles.
    # 30s = device must be absent for 3+ full scan cycles to disappear.
    CACHE_TTL = 30   # seconds
    cache = {}       # key: unique_id → {"device": {...}, "last_seen": float}

    while True:
        scan_count += 1
        ts  = datetime.now().strftime("%H:%M:%S")
        now = time.time()

        print(f"[{ts}] Scan #{scan_count}")

        # ── Run all scanners ────────────────────────────────────────────
        print(f"  WiFi (pywifi)...", end="", flush=True)
        wifi_devs   = scan_wifi()
        print(f" {len(wifi_devs)}", end="  ")

        print(f"WinBT...", end="", flush=True)
        winbt_devs  = scan_bluetooth_windows()
        print(f" {len(winbt_devs)}", end="  ")

        print(f"BLE...", end="", flush=True)
        ble_devs    = scan_ble()
        print(f" {len(ble_devs)}", end="  ")

        print(f"ARP...", end="", flush=True)
        arp_devs    = scan_arp()
        print(f" {len(arp_devs)}", end="  ")

        esp_devs    = drain_esp32_buffer()
        print(f"ESP32: {len(esp_devs)}")

        # ── BLE confirmed names/MACs (truly live this cycle) ───────────
        ble_names = {d["name"].lower() for d in ble_devs}
        ble_macs  = {d["mac"] for d in ble_devs if d["mac"] != "BT"}

        # Tag each device with its TTL before merging
        # WiFi + BLE + ARP = live signal  → full CACHE_TTL
        # WinBT confirmed by BLE          → full CACHE_TTL
        # WinBT NOT confirmed by BLE      → short TTL (1 cycle only)
        #   because WinBT returns Windows' registry — devices seen days ago
        #   that may no longer be nearby
        for d in winbt_devs:
            if d["name"].lower() in ble_names or d.get("mac","") in ble_macs:
                d["_ttl"] = CACHE_TTL
            else:
                d["_ttl"] = CACHE_TTL * 0.4   # ~12s — expires after 1 missed cycle
        for d in wifi_devs + ble_devs + arp_devs + esp_devs:
            d["_ttl"] = CACHE_TTL

        # ── Merge fresh results ─────────────────────────────────────────
        fresh = merge_devices(wifi_devs, winbt_devs, ble_devs, arp_devs, esp_devs)

        # ── Update persistence cache ────────────────────────────────────
        for d in fresh:
            mac  = d.get("mac", "")
            name = d.get("name", "").lower()
            key  = mac if mac and mac != "BT" else f"name:{name}"
            ttl  = d.pop("_ttl", CACHE_TTL)
            cache[key] = {"device": d, "last_seen": now, "ttl": ttl}

        # Evict stale — each device uses its own TTL
        cache = {k: v for k, v in cache.items()
                 if now - v["last_seen"] <= v.get("ttl", CACHE_TTL)}

        all_devices = [v["device"] for v in cache.values()]
        all_devices.sort(key=lambda x: x["distance"] if x["distance"] > 0 else 9999)

        # ── Stats ───────────────────────────────────────────────────────
        def count(fn): return sum(1 for d in all_devices if fn(d))

        mobile_count = count(lambda d: d["type"] == "mobile")
        router_count = count(lambda d: d["type"] == "router")
        bt_count     = count(lambda d: d["source"] in ("bluetooth","esp32_ble"))
        wifi_count   = count(lambda d: d["source"] in ("wifi","esp32_wifi"))
        arp_count    = count(lambda d: d["source"] == "arp")
        nearby_count = count(lambda d: 0 < d["distance"] <= 5)

        print(f"  Total={len(all_devices)}  wifi={wifi_count}  bt={bt_count}  "
              f"arp={arp_count}  mobile={mobile_count}  "
              f"router={router_count}  nearby={nearby_count}")

        data = {
            "session_id":   session_id,
            "timestamp":    ts,
            "scan_number":  scan_count,
            "total":        len(all_devices),
            "wifi_count":   wifi_count,
            "bt_count":     bt_count,
            "arp_count":    arp_count,
            "mobile_count": mobile_count,
            "router_count": router_count,
            "nearby_count": nearby_count,
            "devices":      all_devices,
        }

        with open("scan_data.json", "w") as f:
            json.dump(data, f, indent=2)
        print(f"  scan_data.json updated.\n")

        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScanner stopped.")