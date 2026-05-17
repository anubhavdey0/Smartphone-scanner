# 📡 Smartphone & Device Scanner

A real-time WiFi, Bluetooth, and ARP network scanner with a live web dashboard.

## Features
- Scans nearby WiFi hotspots and routers
- Detects Bluetooth & BLE devices (phones, earbuds, watches)
- ARP network scan for devices on your local network
- Live dashboard in the browser

## Requirements
- Windows 10/11
- Python 3.x
- Npcap (https://npcap.com)

## Installation
```bash
pip install pywifi bleak scapy pyserial comtypes
```

## Usage
Right-click `START_SCANNER.bat` → Run as administrator

## Dashboard
Open `http://localhost:8000/dashboard.html` in your browser