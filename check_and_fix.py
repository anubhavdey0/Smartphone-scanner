"""
check_and_fix.py
================
Run this ONCE before starting scanner.py.
It does 3 things:
  1. Finds your actual local network and patches ARP_NETWORK in scanner.py
  2. Tests that bleak is working (BLE scan)
  3. Tests that scapy is working (ARP send)

Run it like this (as Administrator for scapy to work):
  Right-click Command Prompt → Run as administrator
  python check_and_fix.py
"""

import subprocess
import socket
import sys
import os
import re

SCANNER_FILE = "scanner.py"   # must be in the same folder

# ══════════════════════════════════════════════════════════════
# STEP 1 — Find your local network automatically
# ══════════════════════════════════════════════════════════════
print("=" * 55)
print("  STEP 1 — Finding your local network")
print("=" * 55)

def get_local_ip():
    """Get the machine's own local IP by opening a dummy UDP socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # doesn't actually send anything
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

local_ip = get_local_ip()

if not local_ip:
    print("  [ERROR] Could not detect local IP.")
    print("  Open CMD and run:  ipconfig")
    print("  Find your WiFi IPv4 address, e.g. 192.168.1.105")
    print("  Then edit scanner.py line 74:")
    print('    ARP_NETWORK = "192.168.X.0/24"')
    print("  (replace X with the third number of your IP)")
else:
    # e.g. 192.168.1.105 → 192.168.1.0/24
    parts   = local_ip.split(".")
    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    print(f"  Your IP      : {local_ip}")
    print(f"  Your network : {network}")

    # ── Patch scanner.py ──────────────────────────────────────
    if not os.path.exists(SCANNER_FILE):
        print(f"\n  [ERROR] {SCANNER_FILE} not found in this folder.")
        print(f"  Make sure check_and_fix.py is in the same folder as scanner.py")
    else:
        with open(SCANNER_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        # Replace the ARP_NETWORK line (matches any existing value)
        old_pattern = r'ARP_NETWORK\s*=\s*"[\d./]+"'
        new_line     = f'ARP_NETWORK = "{network}"'
        new_content  = re.sub(old_pattern, new_line, content)

        if new_content == content:
            # Check if pattern exists — if yes, value was already correct
            if re.search(old_pattern, content):
                print(f"\n  ✓ scanner.py already correct — no change needed.")
                print(f'    ARP_NETWORK = "{network}"')
            else:
                print(f"\n  [WARN] Could not find ARP_NETWORK in {SCANNER_FILE}.")
                print(f"  Manually set it to:")
                print(f'    ARP_NETWORK = "{network}"')
        else:
            with open(SCANNER_FILE, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"\n  ✓ scanner.py patched: ARP_NETWORK = \"{network}\"")

print()

# ══════════════════════════════════════════════════════════════
# STEP 2 — Test bleak (BLE scan)
# ══════════════════════════════════════════════════════════════
print("=" * 55)
print("  STEP 2 — Testing bleak (BLE passive scan)")
print("=" * 55)
print("  Scanning for 5 seconds... (make sure BT is ON in Windows)")
print()

try:
    import asyncio
    from bleak import BleakScanner

    # bleak 3.x removed d.rssi — use detection_callback to get RSSI
    seen = {}
    def _cb(device, adv_data):
        mac = device.address
        if mac not in seen or (adv_data.rssi or -100) > (seen[mac][1].rssi or -100):
            seen[mac] = (device, adv_data)

    async def test_ble():
        async with BleakScanner(detection_callback=_cb):
            await asyncio.sleep(5.0)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_ble())
    loop.close()

    if seen:
        print(f"  ✓ bleak is working! Found {len(seen)} BLE device(s):")
        # Sort by RSSI — strongest (closest) first
        sorted_devs = sorted(seen.items(), key=lambda x: (x[1][1].rssi or -100), reverse=True)
        for i, (mac, (d, adv)) in enumerate(sorted_devs[:12]):
            name = d.name or adv.local_name or ""
            rssi = adv.rssi if adv.rssi is not None else -100
            # Hint if unnamed but strong — likely your phone
            if not name and rssi >= -70:
                label = f"(no name) ← LIKELY YOUR PHONE (strong signal)"
            elif not name:
                label = "(no name)"
            else:
                label = name
            print(f"    {i+1}. {label:45s}  MAC: {mac}  RSSI: {rssi} dBm")
        if len(seen) > 12:
            print(f"    ... and {len(seen) - 12} more")
        print()
        print("  NOTE: Phones often advertise BLE without a name (privacy).")
        print("  The strongest unnamed device is very likely your phone.")
    else:
        print("  ✓ bleak is installed and working.")
        print("  No BLE devices found right now — that's OK.")
        print("  Make sure nearby phones have Bluetooth ON.")

except ImportError:
    print("  ✗ bleak is NOT installed.")
    print("  Run:  pip install bleak")
except Exception as e:
    print(f"  ✗ bleak error: {e}")
    print()
    if "Bluetooth" in str(e) or "adapter" in str(e).lower():
        print("  → Make sure Bluetooth is turned ON in Windows Settings.")
        print("    Settings → Bluetooth & devices → Bluetooth → On")
    else:
        print("  → Try:  pip install --upgrade bleak")

print()

# ══════════════════════════════════════════════════════════════
# STEP 3 — Test scapy (ARP scan)
# ══════════════════════════════════════════════════════════════
print("=" * 55)
print("  STEP 3 — Testing scapy (ARP network scan)")
print("=" * 55)

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import ARP, Ether, srp, conf

    if local_ip:
        target = f"{local_ip}/28"   # scan a small /28 slice for quick test
        print(f"  Sending ARP to {target} (quick test, 3 sec)...")
        print()

        pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        result = srp(pkt, timeout=3, verbose=0)[0]

        if result:
            print(f"  ✓ scapy is working! Found {len(result)} device(s) on network:")
            for sent, received in result:
                print(f"    IP: {received.psrc:18s}  MAC: {received.hwsrc}")
        else:
            print("  ✓ scapy sent ARP packets successfully (no replies in /28 slice).")
            print("  Full /24 scan in scanner.py will cover the whole network.")
    else:
        # No IP — just check import works
        print("  scapy imported successfully ✓")
        print("  (Skipping ARP test — no local IP detected)")

except ImportError:
    print("  ✗ scapy is NOT installed.")
    print("  Run:  pip install scapy")
    print()
    print("  Also install Npcap from:  https://npcap.com/#download")
    print("  During install, CHECK: 'WinPcap API-compatible mode'")

except PermissionError:
    print("  ✗ scapy needs Administrator privileges on Windows.")
    print()
    print("  → Close this window.")
    print("  → Right-click Command Prompt → 'Run as administrator'")
    print("  → Run:  python check_and_fix.py   again")

except Exception as e:
    err = str(e)
    print(f"  ✗ scapy error: {err}")
    print()
    if "npcap" in err.lower() or "winpcap" in err.lower() or "socket" in err.lower():
        print("  → Install Npcap from:  https://npcap.com/#download")
        print("    During install, CHECK: 'WinPcap API-compatible mode'")
        print("    Then RESTART your computer.")
    elif "permission" in err.lower() or "access" in err.lower():
        print("  → Run as Administrator (right-click Command Prompt)")
    else:
        print("  → Try:  pip install --upgrade scapy")

print()
print("=" * 55)
print("  All checks done.")
print("  If all steps show ✓ — run scanner.py as Administrator.")
print("  Right-click CMD → Run as administrator → python scanner.py")
print("=" * 55)