import threading
import time
import socket
import requests
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from plyer import notification
from scapy.all import ARP, Ether, srp
import nmap

#Change "SUBNET" to your own subnet mask
#by running "ipconfig" or "ifconfig" in the terminal/CMD
SUBNET = "192.168.0.1/24"
SCAN_INTERVAL = 10
HIGH_RISK_PORTS = [21, 23, 3389, 139, 445, 1433, 3306, 5900, 5432, 137, 138]

devices = {}
nm = nmap.PortScanner()

def get_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return "Unknown"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def analyze_host(ip):
    try:
        nm.scan(ip, arguments="-O --top-ports 10")

        os_guess = "Unknown"
        ports = []

        if ip in nm.all_hosts():

            if "osmatch" in nm[ip] and nm[ip]["osmatch"]:
                os_guess = nm[ip]["osmatch"][0]["name"]

            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    if nm[ip][proto][port]["state"] == "open":
                        ports.append(port)

        return os_guess, ports

    except:
        return "Unknown", []

def risk_score(vendor, ports):
    if vendor == "Unknown":
        return "Suspicious"

    for p in ports:
        if p in HIGH_RISK_PORTS:
            return "High Risk"

    return "Normal"

def log_event(ip, event, risk):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def scan_network():
    arp = ARP(pdst=SUBNET)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    active_ips = set()

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc

        active_ips.add(ip)

        hostname = get_hostname(ip)
        vendor = get_vendor(mac)
        os_type, ports = analyze_host(ip)

        risk = risk_score(vendor, ports)

        now = datetime.now().strftime("%H:%M:%S")

        if ip not in devices:
            devices[ip] = {
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "os": os_type,
                "ports": ports,
                "risk": risk,
                "status": "Online"
            }

            notification.notify(
                title="Network Monitoring Alert",
                message=f"New Device IP: {ip}\nRisk Level: {risk}",
                timeout=5
            )

            log_event(ip, "New Device Detected", risk)

        else:
            devices[ip]["status"] = "Online"

    for ip in list(devices.keys()):
        if ip not in active_ips:
            devices[ip]["status"] = "Offline"
            log_event(ip, "Device Offline", "Normal")

def monitor_loop():
    while True:
        scan_network()
        time.sleep(SCAN_INTERVAL)

def update_gui():
    for row in tree.get_children():
        tree.delete(row)

    counts = {"Online":0,"Offline":0}

    for ip, d in devices.items():

        counts[d["status"]] += 1

        tree.insert("", "end",
        values=(
            ip,
            d["hostname"],
            d["vendor"],
            d["os"],
            d["risk"],
            d["status"]
        ))

    total_label.config(text=f"Total Devices: {len(devices)}")
    online_label.config(text=f"Online: {counts['Online']}")
    offline_label.config(text=f"Offline: {counts['Offline']}")

    root.after(5000, update_gui)

root = tk.Tk()
root.title("Network Monitoring Dashboard")
root.geometry("1200x600")
root.iconbitmap("favicon_netmon.ico")
root.configure(bg="#0f0f0f")

top = tk.Frame(root, bg="#0f0f0f")
top.pack(pady=10)

total_label = tk.Label(top,text="Total Devices: 0",fg="white",bg="#0f0f0f")
total_label.pack(side="left",padx=15)

online_label = tk.Label(top,text="Online: 0",fg="lime",bg="#0f0f0f")
online_label.pack(side="left",padx=15)

offline_label = tk.Label(top,text="Offline: 0",fg="red",bg="#0f0f0f")
offline_label.pack(side="left",padx=15)

columns = ("IP","Hostname","Vendor","OS","Risk","Status")
tree = ttk.Treeview(root, columns=columns, show="headings")

for c in columns:
    tree.heading(c,text=c)
    tree.column(c,width=180)

tree.pack(fill="both",expand=True)

threading.Thread(target=monitor_loop,daemon=True).start()
root.after(5000, update_gui)

print("Running Network Monitoring Dashboard... (This may take awhile)")
root.mainloop()