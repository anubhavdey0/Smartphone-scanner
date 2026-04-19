import pywifi
import time
import math
import os
import json
from datetime import datetime

def estimate_distance(rssi, tx_power=-59, n=2.7):
    if rssi == 0:
        return -1
    return round(10 ** ((tx_power - rssi) / (10 * n)), 1)

def get_signal_bars(rssi):
    if rssi >= -50:
        return "Excellent"
    elif rssi >= -60:
        return "Good"
    elif rssi >= -70:
        return "Fair"
    elif rssi >= -80:
        return "Weak"
    else:
        return "Very Weak"

def scan_devices():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    print("Scanner running... Open dashboard.html in your browser!")
    print("Press Ctrl+C to stop.\n")

    while True:
        iface.scan()
        time.sleep(3)
        results = iface.scan_results()

        seen = {}
        for r in results:
            seen[r.bssid] = r

        devices = []
        for d in seen.values():
            dist = estimate_distance(d.signal)
            devices.append({
                "name": d.ssid if d.ssid else "Hidden Device",
                "mac": d.bssid,
                "rssi": d.signal,
                "distance": dist,
                "signal_quality": get_signal_bars(d.signal),
                "freq": d.freq
            })

        # Sort by distance
        devices.sort(key=lambda x: x["distance"])

        data = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "count": len(devices),
            "devices": devices
        }

        with open("scan_data.json", "w") as f:
            json.dump(data, f)

        print(f"[{data['timestamp']}] Devices found: {len(devices)}")
        time.sleep(5)

if __name__ == "__main__":
    try:
        scan_devices()
    except KeyboardInterrupt:
        print("\nScanner stopped.")
    except Exception as e:
        print(f"Error: {e}")
        
#python scanner.py
#python -m http.server 8000
#http://localhost:8000/dashboard.html
