import pywifi
import time
import json
import subprocess
import re
import platform
from datetime import datetime

# ─── Distance Estimation ───────────────────────────────────────────────
def estimate_distance(rssi, tx_power=-59, n=2.7):
    if rssi == 0:
        return -1
    dist = 10 ** ((tx_power - rssi) / (10 * n))
    return round(dist, 1)

def signal_quality(rssi):
    if rssi >= -50: return "Excellent"
    elif rssi >= -60: return "Good"
    elif rssi >= -70: return "Fair"
    elif rssi >= -80: return "Weak"
    else: return "Very Weak"

# ─── Device Type Identification ────────────────────────────────────────
MOBILE_KEYWORDS = [
    "iphone", "samsung", "oppo", "vivo", "realme", "redmi", "xiaomi",
    "oneplus", "poco", "motorola", "nokia", "huawei", "honor", "pixel",
    "android", "mobile", "phone", "hotspot", "4g", "5g", "jio", "airtel",
    "bsnl", "idea", "vi ", "data", "moto", "asus", "infinix", "tecno"
]
ROUTER_KEYWORDS = [
    "router", "wifi", "wi-fi", "home", "office", "dlink", "tplink",
    "netgear", "linksys", "asus", "bsnl", "airtel", "jiofiber", "act",
    "hathway", "nbn", "broadband", "fiber", "fibre", "gateway",
    "modem", "lan", "net", "connect", "tp-link", "d-link"
]

def identify_device_type(name, source="wifi"):
    if source == "bluetooth":
        name_lower = name.lower()
        if any(k in name_lower for k in ["iphone", "samsung", "oppo", "vivo",
            "realme", "redmi", "xiaomi", "oneplus", "poco", "motorola",
            "pixel", "android", "phone"]):
            return "mobile"
        elif any(k in name_lower for k in ["macbook", "laptop", "dell", "hp",
            "lenovo", "thinkpad", "surface", "asus", "acer"]):
            return "laptop"
        elif any(k in name_lower for k in ["airpods", "buds", "headphone",
            "earphone", "speaker", "jbl", "sony", "boat", "earbuds", "wf-",
            "wh-", "headset"]):
            return "audio"
        elif any(k in name_lower for k in ["watch", "band", "fit", "gear",
            "galaxy watch", "mi band"]):
            return "wearable"
        elif any(k in name_lower for k in ["keyboard", "mouse", "controller",
            "joystick", "gamepad"]):
            return "peripheral"
        else:
            return "unknown"
    else:
        name_lower = name.lower()
        if any(k in name_lower for k in MOBILE_KEYWORDS):
            return "mobile"
        elif any(k in name_lower for k in ROUTER_KEYWORDS):
            return "router"
        else:
            return "other"

# ─── WiFi Scanner ──────────────────────────────────────────────────────
def scan_wifi():
    devices = []
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(3)
        results = iface.scan_results()

        seen = {}
        for r in results:
            seen[r.bssid] = r

        for d in seen.values():
            dist = estimate_distance(d.signal)
            freq_ghz = round(d.freq / 1000000, 1)
            band = "5 GHz" if d.freq > 4000000000 else "2.4 GHz"
            dtype = identify_device_type(d.ssid if d.ssid else "", "wifi")
            devices.append({
                "name": d.ssid if d.ssid else "Hidden Network",
                "mac": d.bssid,
                "rssi": d.signal,
                "distance": dist,
                "signal_quality": signal_quality(d.signal),
                "freq": freq_ghz,
                "band": band,
                "source": "wifi",
                "type": dtype
            })
    except Exception as e:
        print(f"[WiFi Error] {e}")
    return devices

# ─── Bluetooth Scanner (Windows) ───────────────────────────────────────
def scan_bluetooth_windows():
    devices = []
    try:
        # Use PowerShell to scan Bluetooth devices
        ps_script = """
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $null = [Windows.Devices.Bluetooth.BluetoothAdapter,Windows.Devices.Bluetooth,ContentType=WindowsRuntime]
        $null = [Windows.Devices.Enumeration.DeviceInformation,Windows.Devices.Enumeration,ContentType=WindowsRuntime]

        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]

        Function Await($WinRtTask, $ResultType) {
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
        }

        $devices = Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync([Windows.Devices.Enumeration.DeviceClass]::BluetoothClassicDevice)) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Enumeration.DeviceInformation]])
        $bleDevices = Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync([Windows.Devices.Enumeration.DeviceClass]::BluetoothLowEnergy)) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Enumeration.DeviceInformation]])

        $all = @($devices) + @($bleDevices)
        foreach ($d in $all) {
            $id = $d.Id -replace '.*BluetoothLE?#BluetoothLE?', '' -replace '-.*', '' -replace '\\\\', ''
            Write-Output "$($d.Name)|$($d.Id)|BT"
        }
        """
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().split('\n')
        for line in lines:
            line = line.strip()
            if '|' in line and line:
                parts = line.split('|')
                if len(parts) >= 2:
                    name = parts[0].strip()
                    if name and name != "":
                        dtype = identify_device_type(name, "bluetooth")
                        devices.append({
                            "name": name,
                            "mac": "BT Device",
                            "rssi": -65,
                            "distance": estimate_distance(-65),
                            "signal_quality": "Good",
                            "freq": 2.4,
                            "band": "Bluetooth",
                            "source": "bluetooth",
                            "type": dtype
                        })
    except Exception as e:
        print(f"[BT Error] {e}")

    # Fallback: use netsh to find paired/visible BT devices
    if not devices:
        try:
            result = subprocess.run(
                ["powershell", "Get-PnpDevice -Class Bluetooth | Select-Object Status,FriendlyName | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                name = d.get("FriendlyName", "").strip()
                status = d.get("Status", "")
                if name and "adapter" not in name.lower() and "enumerator" not in name.lower():
                    dtype = identify_device_type(name, "bluetooth")
                    devices.append({
                        "name": name,
                        "mac": "BT Device",
                        "rssi": -65 if status == "OK" else -85,
                        "distance": estimate_distance(-65 if status == "OK" else -85),
                        "signal_quality": "Good" if status == "OK" else "Weak",
                        "freq": 2.4,
                        "band": "Bluetooth",
                        "source": "bluetooth",
                        "type": dtype
                    })
        except Exception as e:
            print(f"[BT Fallback Error] {e}")

    return devices

# ─── Main Scanner Loop ─────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("   DEVICE SCANNER — WiFi + Bluetooth")
    print("=" * 55)
    print("Open dashboard.html in browser after starting server")
    print("Run: python -m http.server 8000")
    print("Then: http://localhost:8000/dashboard.html")
    print("Press Ctrl+C to stop.\n")

    scan_count = 0
    while True:
        scan_count += 1
        print(f"[Scan #{scan_count}] {datetime.now().strftime('%H:%M:%S')} — Scanning WiFi...", end="", flush=True)
        wifi_devices = scan_wifi()
        print(f" {len(wifi_devices)} found | Scanning Bluetooth...", end="", flush=True)
        bt_devices = scan_bluetooth_windows()
        print(f" {len(bt_devices)} found")

        all_devices = wifi_devices + bt_devices
        all_devices.sort(key=lambda x: x["distance"] if x["distance"] > 0 else 999)

        # Stats
        mobile_count = sum(1 for d in all_devices if d["type"] == "mobile")
        router_count = sum(1 for d in all_devices if d["type"] == "router")
        bt_count = sum(1 for d in all_devices if d["source"] == "bluetooth")
        wifi_count = sum(1 for d in all_devices if d["source"] == "wifi")
        nearby_count = sum(1 for d in all_devices if 0 < d["distance"] <= 5)

        data = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "scan_number": scan_count,
            "total": len(all_devices),
            "wifi_count": wifi_count,
            "bt_count": bt_count,
            "mobile_count": mobile_count,
            "router_count": router_count,
            "nearby_count": nearby_count,
            "devices": all_devices
        }

        with open("scan_data.json", "w") as f:
            json.dump(data, f, indent=2)

        time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScanner stopped.")